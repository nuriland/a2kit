//go:build windows

package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/0xrawsec/golang-etw/etw"

	"github.com/nuriland/a2kit/wire"
)

// PktMon is the ETW provider of the packet monitor. It logs each packet as event 160, in a payload that PacketType says how to read.
const (
	pktmonProvider    = "{4D4F80D9-C8BD-4D73-BB5B-19C90402C5AC}"
	pktmonPacketEvent = 160
	pktmonEthernet    = 1    // PacketType: an Ethernet frame
	pktmonIP          = 3    // raw IP; 2 is an 802.11 frame, which is not parsed
	pktmonQueue       = 8192 // packets the callback may have queued ahead of ReadSegment
)

// flushEvery is how often the ETW session is told to hand over what its buffers hold
const flushEvery = 100 * time.Millisecond

var (
	propComponent = utf16Ptr("ComponentId")
	propType      = utf16Ptr("PacketType")
	propSize      = utf16Ptr("LoggedPayloadSize")
	propPayload   = utf16Ptr("Payload")
)

// pktmonPacket is a TCP packet as pktmon logged it.
type pktmonPacket struct {
	ip  []byte       // what a recording keeps
	seg wire.Segment // its TCP, aliasing ip
}

// Live captures TCP with pktmon, the packet monitor that ships with Windows. It needs nothing
// installed, and it sees a VPN's tunnel adapter. It needs Administrator.
//
// pktmon.exe starts the capture, and a real-time ETW session reads the packets it logs.
type Live struct {
	packets chan pktmonPacket // filled by the ETW callback, which must never wait on it
	done    chan struct{}     // closed when the capture ends, and err says why
	err     error
	ended   sync.Once

	comp    int // the pktmon component, or 0 for all of them
	session *etw.RealTimeSession
	trace   *etw.Consumer
	rec     *recorder // nil unless recording
	dropped uint64    // packets the queue had no room for, counted by the callback

	flushErr chan error // why flushing stopped, if it failed

	closers  []closer // what OpenLive began; Close undoes it last first
	closed   sync.Once
	closeErr error
}

type closer struct {
	what string
	f    func() error
}

// OpenLive with no name captures every adapter, which is where a VPN's tunnel shows up and the
// game's TCP with it. The decoder's lock picks the game out. A name is one of Devices: "nics" for
// all adapters, a component ID, or an adapter's name.
func OpenLive(name string) (*Live, error) {
	comp, err := pktmonComponent(name)
	if err != nil {
		return nil, err
	}
	l := &Live{
		packets:  make(chan pktmonPacket, pktmonQueue),
		done:     make(chan struct{}),
		flushErr: make(chan error, 1),
		comp:     comp,
	}
	if err := l.start(); err != nil {
		return nil, errors.Join(err, l.Close())
	}
	return l, nil
}

// start begins the capture, and registers how to undo each step as it succeeds.
func (l *Live) start() error {
	l.session = etw.NewRealTimeSession(fmt.Sprintf("a2kit-pktmon-%d-%d", os.Getpid(), time.Now().UnixNano()))
	l.onClose("stopping ETW", l.stopETW)
	err := l.session.EnableProvider(etw.Provider{GUID: pktmonProvider, EnableLevel: 0xff, MatchAnyKeyword: ^uint64(0)})
	if err != nil {
		return fmt.Errorf("capture: pktmon: enabling the provider (Administrator may be required): %w", err)
	}

	l.trace = etw.NewRealTimeConsumer(context.Background()).FromSessions(l.session)
	l.trace.EventRecordCallback = l.event
	if err := l.trace.Start(); err != nil {
		return fmt.Errorf("capture: pktmon: opening the event consumer: %w", err)
	}
	go l.watch()
	go l.flush()

	// pktmon logs to a file too, which nothing here reads. Give it a small one in a directory of
	// its own, not PktMon.etl in the working directory.
	dir, err := os.MkdirTemp("", "a2kit-pktmon-")
	if err != nil {
		return fmt.Errorf("capture: pktmon: %w", err)
	}
	l.onClose("removing pktmon's log", func() error { return os.RemoveAll(dir) })

	comps := "nics"
	if l.comp != 0 {
		comps = strconv.Itoa(l.comp)
	}
	_, err = pktmon("start", "--capture", "--comp", comps, "--pkt-size", "0",
		"--file-name", filepath.Join(dir, "capture.etl"), "--file-size", "32")
	if err != nil {
		return fmt.Errorf("capture: pktmon: starting capture of %s: %w", comps, err)
	}
	l.onClose("stopping pktmon", func() error {
		_, err := pktmon("stop")
		return err
	})
	return nil
}

func (l *Live) onClose(what string, f func() error) {
	l.closers = append(l.closers, closer{what, f})
}

// ReadSegment waits for a segment, and returns io.EOF once closed.
func (l *Live) ReadSegment() (wire.Segment, error) {
	select {
	case p := <-l.packets:
		if l.rec != nil {
			if err := l.rec.write(p.seg.Time, p.ip, len(p.ip)); err != nil {
				return wire.Segment{}, fmt.Errorf("capture: recording: %w", err)
			}
		}
		return p.seg, nil
	case <-l.done:
		return wire.Segment{}, l.err
	}
}

// Record also writes every TCP packet read from now on to w, as a pcap file of raw IP. pktmon logs
// a packet at each component it crosses, so with more than one the file may hold copies of it,
// which the decoder takes for retransmits.
func (l *Live) Record(w io.Writer) error {
	rec, err := newRecorder(w, linkRaw)
	if err != nil {
		return fmt.Errorf("capture: recording: %w", err)
	}
	l.rec = rec
	return nil
}

// Close ends the capture, and may be called from any goroutine. It reports what it could not undo,
// and what went wrong on the way.
func (l *Live) Close() error {
	l.closed.Do(func() {
		l.end(io.EOF)
		var errs []error
		for _, c := range slices.Backward(l.closers) {
			if err := c.f(); err != nil {
				errs = append(errs, fmt.Errorf("capture: pktmon: %s: %w", c.what, err))
			}
		}
		l.closeErr = errors.Join(errors.Join(errs...), l.degraded())
	})
	return l.closeErr
}

// end ends the capture with err, which ReadSegment then returns. Only the first call counts.
func (l *Live) end(err error) {
	l.ended.Do(func() {
		l.err = err
		close(l.done)
	})
}

// watch ends the capture if the trace does, which it does on its own only when something outside
// stops the ETW session.
func (l *Live) watch() {
	l.trace.Wait()
	err := l.trace.Err()
	if err == nil {
		err = errors.New("stopped")
	}
	l.end(fmt.Errorf("capture: pktmon: event consumer: %w", err))
}

// flush tells the session to hand over its buffers every flushEvery, until the capture ends.
func (l *Live) flush() {
	name := l.session.TraceName()
	name16 := utf16Ptr(name)
	l.every(flushEvery, func() error {
		// The call fills in its properties, so each gets new ones.
		return etw.ControlTrace(0, name16, etw.NewRealTimeEventTraceSessionProperties(name), etw.EVENT_TRACE_CONTROL_FLUSH)
	})
}

// every calls f at each interval until the capture ends. It stops at the first error, which Close reports
func (l *Live) every(interval time.Duration, f func() error) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-tick.C:
		}
		if err := f(); err != nil {
			l.flushErr <- err
			return
		}
	}
}

// stopETW stops the session, and then the consumer. The session's end is what lets the trace end,
// so the consumer, which waits for that, goes second.
func (l *Live) stopETW() error {
	var err error
	if l.session.IsStarted() { // EnableProvider starts it, and may fail after
		err = l.session.Stop()
	}
	if l.trace == nil {
		return err
	}
	err = errors.Join(err, l.trace.Stop())
	// Being cancelled is how the consumer ends when it is stopped while a buffer is still coming.
	if traceErr := l.trace.Err(); !errors.Is(traceErr, etw.ERROR_CANCELLED) {
		err = errors.Join(err, traceErr)
	}
	return err
}

// degraded reports what went wrong without ending the capture: packets lost, because ETW lost
// events before the callback saw them or the queue had no room, and a flush that failed. The decoder
// gives up the gaps. It reads what the callback counted, so it is for after the trace has stopped.
func (l *Live) degraded() error {
	var errs []error
	if l.trace != nil && l.trace.LostEvents > 0 {
		errs = append(errs, fmt.Errorf("capture: pktmon: ETW reported lost events %d times", l.trace.LostEvents))
	}
	if l.dropped > 0 {
		errs = append(errs, fmt.Errorf("capture: pktmon: %d packets dropped, the queue was full", l.dropped))
	}
	select {
	case err := <-l.flushErr:
		errs = append(errs, fmt.Errorf("capture: pktmon: flushing the ETW session failed, so frames may have run seconds late: %w", err))
	default:
	}
	return errors.Join(errs...)
}

// event is called for every event of the session, on the thread that processes the trace. It
// queues the TCP packets, and returns false so that the library parses nothing itself.
func (l *Live) event(e *etw.EventRecord) bool {
	select {
	case <-l.done:
		return false
	default:
	}
	switch p, ok, err := readEvent(e, l.comp); {
	case err != nil:
		l.end(err)
	case ok:
		l.queue(p)
	}
	return false
}

// queue hands p to ReadSegment, and drops it if ReadSegment is too far behind. The callback must
// not wait: ETW would lose the events instead.
func (l *Live) queue(p pktmonPacket) {
	select {
	case l.packets <- p:
	default:
		l.dropped++
	}
}

// readEvent reads a packet event, and reports false for any other event, or one of a component
// other than comp when that is not 0, or a packet that is not TCP.
func readEvent(e *etw.EventRecord, comp int) (pktmonPacket, bool, error) {
	if e.EventHeader.EventDescriptor.Id != pktmonPacketEvent {
		return pktmonPacket{}, false, nil
	}
	var component, kind, size uint32
	err := errors.Join(
		u32(e, propComponent, &component),
		u32(e, propType, &kind),
		u32(e, propSize, &size),
	)
	if err != nil {
		return pktmonPacket{}, false, fmt.Errorf("capture: pktmon: reading packet properties: %w", err)
	}
	if comp != 0 && int(component) != comp {
		return pktmonPacket{}, false, nil
	}
	if size == 0 || size > snapLen {
		return pktmonPacket{}, false, fmt.Errorf("capture: pktmon: invalid payload size %d", size)
	}
	data := make([]byte, size)
	if err := property(e, propPayload, data); err != nil {
		return pktmonPacket{}, false, fmt.Errorf("capture: pktmon: reading the payload: %w", err)
	}
	p, ok := tcpPacket(e.EventHeader.UTCTimeStamp(), int(component), kind, data)
	return p, ok, nil
}

// tcpPacket strips a payload that pktmon logged as packetType down to TCP.
func tcpPacket(t time.Time, component int, packetType uint32, data []byte) (pktmonPacket, bool) {
	var link int
	switch packetType {
	case pktmonEthernet:
		link = linkEthernet
	case pktmonIP:
		link = linkRaw
	default:
		return pktmonPacket{}, false
	}
	ip, version := network(link, data)
	if version == 0 {
		return pktmonPacket{}, false
	}
	seg, ok := peel(linkRaw, ip)
	if !ok {
		return pktmonPacket{}, false
	}
	seg.Time, seg.IfIndex = t, component
	return pktmonPacket{ip, seg}, true
}

// u32 reads a uint32 property of e.
func u32(e *etw.EventRecord, name *uint16, v *uint32) error {
	return property(e, name, unsafe.Slice((*byte)(unsafe.Pointer(v)), 4))
}

// property reads the property called name into buf, which must be as big as the property.
func property(e *etw.EventRecord, name *uint16, buf []byte) error {
	d := etw.PropertyDataDescriptor{PropertyName: uint64(uintptr(unsafe.Pointer(name))), ArrayIndex: ^uint32(0)}
	return etw.TdhGetProperty(e, 0, nil, 1, &d, uint32(len(buf)), &buf[0])
}

func utf16Ptr(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		panic(err) // s has a NUL
	}
	return p
}

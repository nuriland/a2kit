//go:build cgo && !windows

package capture

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/gopacket/gopacket/pcap"

	"github.com/nuriland/a2kit/wire"
)

// Flags libpcap sets on a device.
const (
	ifLoopback     = 0x1
	ifUp           = 0x2
	ifStatus       = 0x30 // the connection: unknown, connected, disconnected, or not applicable
	ifDisconnected = 0x20
)

// bufferSize is the kernel buffer of a live capture.
const bufferSize = 16 << 20

// Live captures a device's TCP through libpcap.
type Live struct {
	h    *pcap.Handle
	rec  *recorder // nil unless recording
	link int
}

// OpenLive with no name takes the first device that is up, has an address, is
// not a loopback, and is not known to be disconnected. It needs root or the access_bpf group on macOS.
func OpenLive(name string) (*Live, error) {
	if name == "" {
		var err error
		if name, err = defaultDevice(); err != nil {
			return nil, err
		}
	}

	in, err := pcap.NewInactiveHandle(name)
	if err != nil {
		return nil, fmt.Errorf("capture: %s: %w", name, err)
	}
	defer in.CleanUp()

	// Immediate mode hands each packet over as it arrives, rather than when a buffer fills or the
	// timeout expires. Not on Linux, where libpcap then gives every packet a slot as big as the
	// largest the device can deliver, 64 KiB with offloads on, and the buffer holds 256 packets.
	// A read still wakes every 10ms, so that Close never waits longer.
	err = errors.Join(
		in.SetSnapLen(snapLen),
		in.SetPromisc(false),
		in.SetImmediateMode(runtime.GOOS != "linux"),
		in.SetTimeout(10*time.Millisecond),
		in.SetBufferSize(bufferSize),
	)
	if err != nil {
		return nil, fmt.Errorf("capture: %s: %w", name, err)
	}

	h, err := in.Activate()
	if err != nil {
		return nil, fmt.Errorf("capture: %s: %w", name, err)
	}
	if err := h.SetBPFFilter("tcp"); err != nil {
		h.Close()
		return nil, fmt.Errorf("capture: %s: %w", name, err)
	}
	return &Live{h: h, link: int(h.LinkType())}, nil
}

// ReadSegment waits for a segment, and returns io.EOF once closed.
func (l *Live) ReadSegment() (wire.Segment, error) {
	for {
		data, ci, err := l.h.ZeroCopyReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err == io.EOF {
			return wire.Segment{}, io.EOF
		}
		if err != nil {
			return wire.Segment{}, fmt.Errorf("capture: %w", err)
		}
		if l.rec != nil {
			if err := l.rec.write(ci.Timestamp, data, ci.Length); err != nil {
				return wire.Segment{}, fmt.Errorf("capture: recording: %w", err)
			}
		}
		if s, ok := peel(l.link, data); ok {
			s.Time, s.IfIndex = ci.Timestamp, ci.InterfaceIndex
			return s, nil
		}
	}
}

// Record also writes every packet read from now on to w, as a pcap file. That is all the TCP the
// device sees, not only the game's.
func (l *Live) Record(w io.Writer) error {
	rec, err := newRecorder(w, fileLinkType(l.link))
	if err != nil {
		return fmt.Errorf("capture: recording: %w", err)
	}
	l.rec = rec
	return nil
}

// fileLinkType returns the link type a file uses for dlt. A live handle numbers raw IP as its OS
// does, 12 or 14, where a file uses 101.
func fileLinkType(dlt int) int {
	if dlt == 12 || dlt == 14 {
		return linkRaw
	}
	return dlt
}

// Close ends the capture, and may be called from any goroutine.
func (l *Live) Close() error {
	l.h.Close()
	return nil
}

// defaultDevice is the device OpenLive opens when none is named.
func defaultDevice() (string, error) {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("capture: %w", err)
	}
	for _, in := range ifs {
		if in.Flags&ifUp != 0 && in.Flags&ifLoopback == 0 && in.Flags&ifStatus != ifDisconnected && len(in.Addresses) > 0 {
			return in.Name, nil
		}
	}
	return "", errors.New("capture: no device is up")
}

// Devices lists the devices that can be captured.
func Devices() ([]Device, error) {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("capture: %w", err)
	}
	devs := make([]Device, len(ifs))
	for i, in := range ifs {
		devs[i] = Device{Name: in.Name, Description: in.Description}
	}
	return devs, nil
}

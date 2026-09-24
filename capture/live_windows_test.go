//go:build windows

package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
)

// tcpv4 is an IPv4 packet with a TCP segment of payload, 10.0.0.2:13328 to 10.0.0.1:10000.
func tcpv4(seq uint32, payload string) []byte {
	p := make([]byte, 40+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8], p[9] = 64, protoTCP
	copy(p[12:], []byte{10, 0, 0, 2})
	copy(p[16:], []byte{10, 0, 0, 1})
	binary.BigEndian.PutUint16(p[20:], 13328)
	binary.BigEndian.PutUint16(p[22:], 10000)
	binary.BigEndian.PutUint32(p[24:], seq)
	p[32] = 5 << 4
	p[33] = 0x18 // PSH, ACK
	copy(p[40:], payload)
	return p
}

// frame is ip in an Ethernet frame. Each of types but the last is a VLAN tag's, and the last is the EtherType of ip.
func frame(ip []byte, types ...uint16) []byte {
	f := make([]byte, 12) // the addresses
	for i, t := range types {
		f = binary.BigEndian.AppendUint16(f, t)
		if i < len(types)-1 {
			f = binary.BigEndian.AppendUint16(f, 7) // the tag's VLAN
		}
	}
	return append(f, ip...)
}

func TestTCPPacket(t *testing.T) {
	tcp := tcpv4(1000, "hello")
	udp := tcpv4(0, "")
	udp[9] = 17
	tests := []struct {
		name       string
		packetType uint32
		data       []byte
		ok         bool
	}{
		{name: "raw", packetType: pktmonIP, data: tcp, ok: true},
		{name: "ethernet", packetType: pktmonEthernet, data: frame(tcp, 0x0800), ok: true},
		{name: "vlan", packetType: pktmonEthernet, data: frame(tcp, 0x8100, 0x0800), ok: true},
		{name: "udp", packetType: pktmonIP, data: udp},
		{name: "arp", packetType: pktmonEthernet, data: frame(tcp, 0x0806)},
		{name: "wifi", packetType: 2, data: frame(tcp, 0x0800)},
		{name: "unknown type", packetType: 9, data: tcp},
		{name: "empty", packetType: pktmonIP},
	}
	when := time.Unix(123, 456)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, ok := tcpPacket(when, 143, test.packetType, test.data)
			if ok != test.ok {
				t.Fatalf("tcpPacket(%d, %x) = %t, want %t", test.packetType, test.data, ok, test.ok)
			}
			if !ok {
				return
			}
			s := p.seg
			if !bytes.Equal(p.ip, tcp) || string(s.Payload) != "hello" || s.Seq != 1000 ||
				s.Src.String() != "10.0.0.2:13328" || s.Dst.String() != "10.0.0.1:10000" ||
				s.IfIndex != 143 || !s.Time.Equal(when) {
				t.Errorf("packet = %x, %+v", p.ip, s)
			}
		})
	}
}

// pktmonList is what pktmon list printed on a Windows 11 machine, with CRLF line ends.
const pktmonList = "\r\nNetwork Adapters:\r\n" +
	"   Id MAC Address       Name\r\n" +
	"   -- -----------       ----\r\n" +
	"    7 0A-00-27-00-00-06 VirtualBox Host-Only Ethernet Adapter\r\n" +
	"    6 B4-B5-B6-93-CA-DD RZ608 Wi-Fi 6E 80MHz\r\n" +
	"    4 B4-B5-B6-93-CA-DE Bluetooth Device (Personal Area Network)\r\n" +
	"  125 04-42-1A-97-50-23 Intel(R) Ethernet Controller (3) I225-V\r\n"

func TestParseAdapters(t *testing.T) {
	as, err := parseAdapters([]byte(pktmonList))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range as {
		got = append(got, fmt.Sprintf("%d %s %s", a.id, a.mac, a.name))
	}
	// The Wi-Fi adapter is left out, and the rest come by ID.
	want := "4 b4:b5:b6:93:ca:de Bluetooth Device (Personal Area Network)\n" +
		"7 0a:00:27:00:00:06 VirtualBox Host-Only Ethernet Adapter\n" +
		"125 04:42:1a:97:50:23 Intel(R) Ethernet Controller (3) I225-V"
	if strings.Join(got, "\n") != want {
		t.Errorf("adapters:\n%s\nwant:\n%s", strings.Join(got, "\n"), want)
	}
	if _, err := parseAdapters([]byte("\r\nNetwork Adapters:\r\n")); err == nil {
		t.Error("parsed adapters from a listing with none")
	}

	id, err := adapterNamed(as, "Intel(R) Ethernet Controller (3) I225-V")
	if err != nil || id != 125 {
		t.Errorf("adapterNamed = %d, %v, want 125", id, err)
	}
	if _, err := adapterNamed(as, "RZ608 Wi-Fi 6E 80MHz"); err == nil {
		t.Error("named an adapter that is left out")
	}
}

func TestPktmonComponent(t *testing.T) {
	for name, want := range map[string]int{"": 0, "nics": 0, "NICS": 0, "143": 143} {
		if got, err := pktmonComponent(name); err != nil || got != want {
			t.Errorf("pktmonComponent(%q) = %d, %v, want %d", name, got, err, want)
		}
	}
}

// newLive is a Live with nothing started, for what the ETW callback would have queued.
func newLive(comp int) *Live {
	return &Live{packets: make(chan pktmonPacket, 4), done: make(chan struct{}), comp: comp}
}

func TestReadSegment(t *testing.T) {
	l := newLive(143)
	for i, s := range []string{"a", "b"} {
		p, ok := tcpPacket(time.Unix(int64(i), 0), 143, pktmonIP, tcpv4(uint32(i), s))
		if !ok {
			t.Fatal("not TCP")
		}
		l.packets <- p
	}
	for _, want := range []string{"a", "b"} {
		s, err := l.ReadSegment()
		if err != nil || string(s.Payload) != want {
			t.Errorf("ReadSegment = %q, %v, want %q", s.Payload, err, want)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.ReadSegment(); err != io.EOF {
		t.Errorf("ReadSegment after Close = %v, want EOF", err)
	}
}

func TestReadSegmentFailure(t *testing.T) {
	l := newLive(143)
	p, _ := tcpPacket(time.Unix(0, 0), 143, pktmonIP, tcpv4(0, "a"))
	l.packets <- p
	l.end(errors.New("capture failed"))
	l.end(errors.New("a second failure")) // the first one counts

	// A queued packet may come first, but the failure comes within a read more than there are.
	var err error
	for range 2 {
		if _, err = l.ReadSegment(); err != nil {
			break
		}
	}
	if err == nil || err.Error() != "capture failed" {
		t.Errorf("ReadSegment = %v, want the first failure", err)
	}
}

func TestQueueDropsWhenFull(t *testing.T) {
	l := newLive(0) // room for 4
	p, _ := tcpPacket(time.Unix(0, 0), 143, pktmonIP, tcpv4(0, "a"))
	for range 6 {
		l.queue(p)
	}
	if len(l.packets) != 4 || l.dropped != 2 {
		t.Errorf("queued %d and dropped %d, want 4 and 2", len(l.packets), l.dropped)
	}
	select {
	case <-l.done:
		t.Error("a full queue ended the capture")
	default:
	}
}

func TestCloseReportsWhatWentWrong(t *testing.T) {
	l := newLive(0)
	if err := l.Close(); err != nil {
		t.Fatalf("Close of a capture that missed nothing = %v", err)
	}

	l = newLive(0)
	l.trace = etw.NewRealTimeConsumer(context.Background())
	l.trace.LostEvents = 3
	l.dropped = 2
	err := l.Close()
	if err == nil || !strings.Contains(err.Error(), "lost events 3 times") || !strings.Contains(err.Error(), "2 packets dropped") {
		t.Errorf("Close = %v, want the lost events and the dropped packets", err)
	}
}

func TestEveryCallsUntilTheCaptureEnds(t *testing.T) {
	l := newLive(0)
	calls := make(chan struct{}, 100)
	stopped := make(chan struct{})
	go func() {
		l.every(time.Millisecond, func() error { calls <- struct{}{}; return nil })
		close(stopped)
	}()
	for range 3 {
		select {
		case <-calls:
		case <-time.After(5 * time.Second):
			t.Fatal("not called again")
		}
	}
	l.Close()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("still calling after Close")
	}
}

func TestFailedFlushDoesNotEndTheCapture(t *testing.T) {
	l := newLive(0)
	l.flushErr = make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		l.every(time.Millisecond, func() error { return errors.New("access denied") })
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("kept calling after an error")
	}
	select {
	case <-l.done:
		t.Error("a failed flush ended the capture")
	default:
	}
	err := l.Close()
	if err == nil || !strings.Contains(err.Error(), "flushing the ETW session failed") || !strings.Contains(err.Error(), "access denied") {
		t.Errorf("Close = %v, want the failed flush", err)
	}
}

func TestRecord(t *testing.T) {
	var buf bytes.Buffer
	l := newLive(0) // all components, which a VPN's tunnel needs
	if err := l.Record(&buf); err != nil {
		t.Fatal(err)
	}
	p, _ := tcpPacket(time.Unix(123, 456), 143, pktmonEthernet, frame(tcpv4(1000, "hello"), 0x0800))
	l.packets <- p
	if _, err := l.ReadSegment(); err != nil {
		t.Fatal(err)
	}

	r, err := NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	s, err := r.ReadSegment()
	if err != nil {
		t.Fatal(err)
	}
	if string(s.Payload) != "hello" || s.Seq != 1000 || !s.Time.Equal(time.Unix(123, 456)) {
		t.Errorf("replayed %+v", s)
	}
	if _, err := r.ReadSegment(); err != io.EOF {
		t.Errorf("second replayed segment: %v, want EOF", err)
	}
}

func TestCloseUndoesLastFirst(t *testing.T) {
	var order []int
	l := newLive(0)
	for i := range 3 {
		l.onClose(fmt.Sprint("step ", i), func() error {
			order = append(order, i)
			if i == 1 {
				return nil
			}
			return errors.New("failed")
		})
	}
	err := l.Close()
	if fmt.Sprint(order) != "[2 1 0]" {
		t.Errorf("undone in order %v, want [2 1 0]", order)
	}
	if err == nil || !strings.Contains(err.Error(), "step 2") || !strings.Contains(err.Error(), "step 0") || strings.Contains(err.Error(), "step 1") {
		t.Errorf("Close = %v, want the failures of steps 2 and 0", err)
	}
	if again := l.Close(); again != err || len(order) != 3 {
		t.Errorf("a second Close ran the steps again, or returned %v", again)
	}
}

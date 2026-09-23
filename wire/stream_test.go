package wire

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nuriland/a2kit/internal/wiretest"
)

func segment(seq uint32, flags TCPFlags, p []byte, at time.Duration) Segment {
	return Segment{Time: epoch.Add(at), Src: srv, Dst: cli, Seq: seq, Flags: flags, Payload: p}
}

func TestSplit(t *testing.T) {
	f := wiretest.AppendFrame(nil, 0x04, 0x38, 41)
	d := NewDecoder(Config{})
	feed(d, f[:10])
	expect(t, d, "")
	feed(d, f[10:])
	expect(t, d, "04 38 len=41 -\n")
}

func TestOrder(t *testing.T) {
	var p []byte
	var want strings.Builder
	for i := range 6 {
		p = wiretest.AppendFrame(p, 0x04, 0x38, 30+i)
		fmt.Fprintf(&want, "04 38 len=%d -\n", 30+i)
	}
	for _, isn := range []uint32{1000, 0xFFFFFFF0} {
		t.Run(fmt.Sprint(isn), func(t *testing.T) {
			d := NewDecoder(Config{})
			d.FeedSegment(segment(isn-1, SYN, nil, 1))
			d.FeedSegment(segment(isn+120, ACK, p[120:], 2)) // the tail first
			d.FeedSegment(segment(isn, ACK, p[:50], 3))
			d.FeedSegment(segment(isn, ACK, p[:50], 4))       // a retransmit
			d.FeedSegment(segment(isn+30, ACK, p[30:120], 5)) // overlaps both
			expect(t, d, want.String())
		})
	}
}

func TestGap(t *testing.T) {
	var (
		d = NewDecoder(Config{})
		f = wiretest.AppendFrame(nil, 0x05, 0x38, 4)
	)
	d.FeedSegment(segment(1, ACK, wiretest.AppendFrame(nil, 0x04, 0x38, 100)[:10], 1)) // and never the rest
	for i := range maxHeld + 1 {
		d.FeedSegment(segment(100000+uint32(i)*1000, ACK, f, time.Duration(2+i)))
	}
	expect(t, d, "05 38 len=4 resynced\n")
}

func TestGapKeeps(t *testing.T) {
	var (
		d = NewDecoder(Config{})
		f = wiretest.AppendFrame(nil, 0x05, 0x38, 4)
	)
	d.FeedSegment(segment(1, ACK, wiretest.AppendFrame(nil, 0x04, 0x38, 100)[:10], 1))
	seq := uint32(1000)
	for i := range maxHeld + 1 {
		d.FeedSegment(segment(seq, ACK, f, time.Duration(2+i)))
		seq += uint32(len(f))
	}
	want := "05 38 len=4 resynced\n" + strings.Repeat("05 38 len=4 -\n", maxHeld)
	expect(t, d, want)
}

func TestTLSSegment(t *testing.T) {
	var (
		d   = NewDecoder(Config{})
		tls = []byte{0x17, 0x03, 0x03, 0x00, 0x02, 0xAB, 0xCD}
	)
	d.FeedSegment(segment(1, ACK, tls, 1))
	d.FeedSegment(segment(1+uint32(len(tls)), ACK, wiretest.AppendFrame(nil, 0x04, 0x38, 3), 2))
	expect(t, d, "04 38 len=3 resynced\n") // the TLS bytes count as skipped
}

func TestGapWait(t *testing.T) {
	var (
		d = NewDecoder(Config{})
		f = wiretest.AppendFrame(nil, 0x05, 0x38, 4)
	)
	d.FeedSegment(segment(0, SYN, nil, 0))
	d.FeedSegment(segment(1000, ACK, f, time.Millisecond)) // past a gap that never fills
	expect(t, d, "")
	d.FeedSegment(segment(1000+uint32(len(f)), ACK, f, time.Millisecond+maxGapWait))
	expect(t, d, "05 38 len=4 resynced\n05 38 len=4 -\n")
}

// ack is a bare ACK from the client, acknowledging the server's bytes before seq.
func ack(seq uint32, at time.Duration) Segment {
	return Segment{Time: epoch.Add(at), Src: cli, Dst: srv, Flags: ACK, Ack: seq}
}

func TestGapAcked(t *testing.T) {
	var (
		a = wiretest.AppendFrame(nil, 0x04, 0x38, 10)
		b = wiretest.AppendFrame(nil, 0x05, 0x38, 10) // the capture misses it
		c = wiretest.AppendFrame(nil, 0x06, 0x38, 10)
	)
	for _, isn := range []uint32{1000, 0xFFFFFFF0} {
		t.Run(fmt.Sprint(isn), func(t *testing.T) {
			var (
				d   = NewDecoder(Config{})
				bAt = isn + uint32(len(a))
				cAt = bAt + uint32(len(b))
				end = cAt + uint32(len(c))
			)
			d.FeedSegment(segment(isn-1, SYN, nil, 0))
			d.FeedSegment(segment(isn, ACK, a, 1))
			d.FeedSegment(segment(cAt, ACK, c, 2))
			d.FeedSegment(ack(bAt+5, 3)) // into the gap: the rest of it may still come
			d.FeedSegment(Segment{Time: epoch.Add(4), Src: cli, Dst: srv, Ack: end})
			expect(t, d, "04 38 len=10 -\n") // no ACK flag, so no ACK

			d.FeedSegment(ack(end, 5))
			expect(t, d, "06 38 len=10 resynced\n")
		})
	}
}

// An ACK past bytes the capture has not seen moves nothing, so bytes that follow in order are
// still parsed.
func TestAckAhead(t *testing.T) {
	var (
		d = NewDecoder(Config{})
		a = wiretest.AppendFrame(nil, 0x04, 0x38, 10)
		b = wiretest.AppendFrame(nil, 0x05, 0x38, 10)
	)
	d.FeedSegment(segment(0, SYN, nil, 0))
	d.FeedSegment(segment(1, ACK, a, 1))
	d.FeedSegment(ack(100000, 2))
	d.FeedSegment(segment(1+uint32(len(a)), ACK, b, 3))
	expect(t, d, "04 38 len=10 -\n05 38 len=10 -\n")
}

func TestFlush(t *testing.T) {
	var (
		d = NewDecoder(Config{})
		f = wiretest.AppendFrame(nil, 0x05, 0x38, 4)
	)
	d.FeedSegment(segment(0, SYN, nil, 0))
	d.FeedSegment(segment(1000, ACK, f, 1))
	d.Flush()
	expect(t, d, "05 38 len=4 resynced\n")
}

func TestHeldTime(t *testing.T) {
	var (
		d = NewDecoder(Config{})
		a = wiretest.AppendFrame(nil, 0x04, 0x38, 10)
		b = wiretest.AppendFrame(nil, 0x05, 0x38, 10)
	)
	d.FeedSegment(segment(0, SYN, nil, 0))
	d.FeedSegment(segment(1+uint32(len(a)), ACK, b, 1*time.Millisecond)) // early
	d.FeedSegment(segment(1, ACK, a, 5*time.Millisecond))                // and the gap before it
	var got []time.Duration
	for f := range d.Frames() {
		got = append(got, f.Time.Sub(epoch))
	}
	if want := []time.Duration{5 * time.Millisecond, 1 * time.Millisecond}; !slices.Equal(got, want) {
		t.Errorf("stamped %v, want %v", got, want)
	}
}

func TestReconnect(t *testing.T) {
	var (
		d = NewDecoder(Config{})
		f = wiretest.AppendFrame(nil, 0x04, 0x38, 20)
	)
	d.FeedSegment(segment(1_000_000, SYN|ACK, nil, 1))
	d.FeedSegment(segment(1_000_001, ACK, f, 2))
	d.FeedSegment(segment(1_000_000, SYN|ACK, nil, 3)) // the same SYN, sent again
	d.FeedSegment(segment(1_000_001+uint32(len(f)), ACK, f, 4))
	expect(t, d, "04 38 len=20 -\n04 38 len=20 -\n")

	d.FeedSegment(segment(5, SYN|ACK, nil, 5)) // a new connection, its sequence behind the old one's
	d.FeedSegment(segment(6, ACK, f, 6))
	expect(t, d, "04 38 len=20 -\n")
}

func TestFin(t *testing.T) {
	var (
		d  = NewDecoder(Config{})
		f  = wiretest.AppendFrame(nil, 0x33, 0x36, 4)
		up = Segment{Src: cli, Dst: srv, Seq: 1, Flags: ACK, Payload: f}
	)
	d.FeedSegment(segment(1, FIN|ACK, f, 1))

	up.Time = epoch.Add(closeGrace)
	d.FeedSegment(up)
	if _, ok := d.streams[key{src: srv, dst: cli}]; !ok {
		t.Fatal("dropped before its grace")
	}
	up.Time = epoch.Add(closeGrace + 1)
	up.Seq += uint32(len(f))
	d.FeedSegment(up)
	if _, ok := d.streams[key{src: srv, dst: cli}]; ok {
		t.Fatal("kept after its grace")
	}
}

func TestStalest(t *testing.T) {
	d := NewDecoder(Config{})
	port := func(i int) netip.AddrPort {
		return netip.AddrPortFrom(netip.MustParseAddr("10.0.1.1"), uint16(1000+i))
	}
	for i := range maxStreams + 1 {
		d.Feed(epoch.Add(time.Duration(i)), port(i), cli, []byte{0xAA})
	}
	if len(d.streams) != maxStreams {
		t.Fatalf("%d streams", len(d.streams))
	}
	if _, ok := d.streams[key{src: port(0), dst: cli}]; ok {
		t.Error("the stalest stream stayed")
	}
	if _, ok := d.streams[key{src: port(maxStreams), dst: cli}]; !ok {
		t.Error("the newest stream is missing")
	}
}

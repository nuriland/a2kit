package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nuriland/a2kit/internal/wiretest"
)

var (
	srv   = netip.MustParseAddrPort("10.0.0.2:13328")
	cli   = netip.MustParseAddrPort("10.0.0.1:10000")
	epoch = time.Unix(0, 0)
)

func feed(d *Decoder, p []byte) {
	d.Feed(epoch, srv, cli, p)
}

// frames prints the frames found so far, a line each, without their direction. framesDir
// includes it.
func frames(d *Decoder) string { return printed(d, FromServer|FromClient) }

func framesDir(d *Decoder) string { return printed(d, 0) }

func printed(d *Decoder, hide Flags) string {
	var b strings.Builder
	for f := range d.Frames() {
		fmt.Fprintf(&b, "%v len=%d %v\n", f.Opcode, len(f.Payload), f.Flags&^hide)
	}
	return b.String()
}

func expect(t *testing.T, d *Decoder, want string) {
	t.Helper()
	if got := frames(d); got != want {
		t.Errorf("frames:\n%swant:\n%s", got, want)
	}
}

func expectDir(t *testing.T, d *Decoder, want string) {
	t.Helper()
	if got := framesDir(d); got != want {
		t.Errorf("frames:\n%swant:\n%s", got, want)
	}
}

func TestOpcode(t *testing.T) {
	b := wiretest.AppendFrame(nil, 0x04, 0x38, 41)
	if len(b) != 44 || b[0] != 47 {
		t.Fatalf("a 41-byte payload: varint %d, %d bytes; want 47, 44", b[0], len(b))
	}
	d := NewDecoder(Config{})
	feed(d, b)

	fs := slices.Collect(d.Frames())
	if len(fs) != 1 {
		t.Fatalf("%d frames, want 1", len(fs))
	}
	f := fs[0]
	if f.Opcode != 0x3804 || f.Opcode.Bytes() != [2]byte{0x04, 0x38} {
		t.Errorf("opcode %#x", uint16(f.Opcode))
	}
	if !bytes.Equal(f.Payload, b[3:]) {
		t.Errorf("payload % x", f.Payload)
	}
	if f.Flags != 0 || f.Src != srv || f.Dst != cli {
		t.Errorf("flags %v, %v -> %v; want no direction, before the lock", f.Flags, f.Src, f.Dst)
	}
}

func TestFrameString(t *testing.T) {
	f := Frame{
		Time:    time.Unix(1700000000, 6000000),
		Src:     srv,
		Dst:     cli,
		Opcode:  0x3804,
		Payload: make([]byte, 41),
		Flags:   FromServer | WasLZ4 | WasBundled,
	}
	want := "ts=1700000000006000000 opcode=04 38 len=41 flags=server,lz4,bundled src=10.0.0.2:13328 dst=10.0.0.1:10000"
	if got := f.String(); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if got := Flags(0).String(); got != "-" {
		t.Errorf("no flags: %q", got)
	}
}

func TestShapes(t *testing.T) {
	d := NewDecoder(Config{})
	feed(d, slices.Concat(
		wiretest.AppendFrame(nil, 0x00, 0x36, 8), // a frame behind it, so a stream takes it at the start
		wiretest.AppendFrame(nil, 0x05, 0x38, 300),
		[]byte{0, 0},
		wiretest.AppendFrame(nil, 0x12, 0x34, 3),
	))
	expect(t, d, "00 36 len=8 -\n05 38 len=300 -\n12 34 len=3 -\n")
}

func TestKnownOnly(t *testing.T) {
	d := NewDecoder(Config{KnownOnly: true})
	feed(d, slices.Concat(
		wiretest.AppendFrame(nil, 0x00, 0x36, 8), // a known frame behind it, so the start is taken
		wiretest.AppendFrame(nil, 0x04, 0x38, 5),
		wiretest.AppendFrame(nil, 0x12, 0x34, 3),
		wiretest.AppendFrame(nil, 0x33, 0x36, 7),
	))
	expect(t, d, "00 36 len=8 -\n04 38 len=5 -\n33 36 len=7 -\n")
}

func TestResync(t *testing.T) {
	d := NewDecoder(Config{})
	feed(d, slices.Concat([]byte{0xAA, 0xAA}, wiretest.AppendFrame(nil, 0x04, 0x38, 41), wiretest.AppendFrame(nil, 0x05, 0x38, 9)))
	expect(t, d, "04 38 len=41 resynced\n05 38 len=9 -\n")

	feed(d, slices.Concat([]byte{0x01}, wiretest.AppendFrame(nil, 0x04, 0x38, 2)))
	expect(t, d, "04 38 len=2 resynced\n")
}

func TestProbation(t *testing.T) {
	d := NewDecoder(Config{})
	feed(d, slices.Concat(
		[]byte{0x01}, // too short to be a frame, so the next one is found at once
		wiretest.AppendFrame(nil, 0x04, 0x38, 5),
		[]byte{0x80, 0x80, 0x05, 0x22, 0x38}, // varint 81920, and a plausible opcode
		wiretest.AppendFrame(nil, 0x05, 0x38, 9),
		wiretest.AppendFrame(nil, 0x33, 0x36, 4),
	))
	expect(t, d, "04 38 len=5 resynced\n05 38 len=9 resynced\n33 36 len=4 -\n")
}

// At the start, envelopes take three headers in a row to believe; after a frame, one.
func TestEnvelopes(t *testing.T) {
	d := NewDecoder(Config{})
	f := wiretest.AppendFrame(nil, 0x04, 0x38, 20)
	feed(d, slices.Concat(enveloped(f, len(f)), enveloped(f, len(f)), enveloped(f, len(f))))
	st := d.streams[key{src: srv, dst: cli}]
	if !st.fr.env.on {
		t.Fatal("envelopes not found at the start")
	}
	expect(t, d, strings.Repeat("04 38 len=20 -\n", 3))

	after := NewDecoder(Config{})
	feed(after, slices.Concat(wiretest.AppendFrame(nil, 0x00, 0x36, 8), enveloped(f, len(f))))
	if !after.streams[key{src: srv, dst: cli}].fr.env.on {
		t.Fatal("envelopes not found after a frame")
	}
	expect(t, after, "00 36 len=8 -\n04 38 len=20 -\n")

	feed(d, []byte{0xFF, 0xFF}) // half the next header
	feed(d, slices.Concat(
		[]byte{0xFF, 0xFF}, // and the rest: FF FF FF FF is no length
		wiretest.AppendFrame(nil, 0x05, 0x38, 9),
		wiretest.AppendFrame(nil, 0x33, 0x36, 4), // unaligned again, 05 38 is trusted for the frame behind it
	))
	expect(t, d, "05 38 len=9 resynced\n33 36 len=4 -\n")
	if st.fr.env.on {
		t.Error("envelopes still on")
	}
}

func TestTLS(t *testing.T) {
	d := NewDecoder(Config{})
	feed(d, []byte{0x16, 0x03, 0x01, 0x00, 0x20, 0x06, 0x00, 0x36, 0x06, 0x00, 0x36})
	expect(t, d, "")
}

func TestGarbage(t *testing.T) {
	d := NewDecoder(Config{})
	x := uint32(12345)
	junk := make([]byte, 4096)
	for range 3000 {
		for i := range junk {
			x = x*1103515245 + 12345
			junk[i] = byte(x >> 16)
		}
		feed(d, junk)
		frames(d)
	}
	st := d.streams[key{src: srv, dst: cli}]
	if len(st.fr.buf) > maxBuf+3 {
		t.Fatalf("stream holds %d bytes", len(st.fr.buf))
	}

	var p []byte
	for range 150 {
		p = wiretest.AppendFrame(p, 0x04, 0x38, 20)
	}
	var got string
	for range 300 {
		feed(d, p)
		got = frames(d)
	}
	if want := strings.Repeat("04 38 len=20 -\n", 150); got != want {
		t.Errorf("after garbage:\n%s", got)
	}
}

func TestFramesBreak(t *testing.T) {
	d := NewDecoder(Config{})
	feed(d, slices.Concat(wiretest.AppendFrame(nil, 0x04, 0x38, 1), wiretest.AppendFrame(nil, 0x05, 0x38, 2), wiretest.AppendFrame(nil, 0x33, 0x36, 3)))
	for range d.Frames() {
		break
	}
	expect(t, d, "05 38 len=2 -\n33 36 len=3 -\n")
	expect(t, d, "")
}

type segments struct {
	s   []Segment
	err error
}

func (r *segments) ReadSegment() (Segment, error) {
	if len(r.s) == 0 {
		if r.err != nil {
			return Segment{}, r.err
		}
		return Segment{}, io.EOF
	}
	s := r.s[0]
	r.s = r.s[1:]
	return s, nil
}

// The segments past a gap are given up when the reader ends, before its error.
func TestDecode(t *testing.T) {
	f := wiretest.AppendFrame(nil, 0x04, 0x38, 41)
	g := wiretest.AppendFrame(nil, 0x05, 0x38, 2)
	broken := errors.New("broken")
	r := &segments{
		s: []Segment{
			segment(1, ACK, f[:10], 1),
			segment(11, ACK, f[10:], 2),
			segment(1+uint32(len(f)), ACK, g, 3),
			segment(1000, ACK, g, 4), // past a gap that never fills
		},
		err: broken,
	}
	var got []string
	var err error
	for f, e := range NewDecoder(Config{}).Decode(r) {
		if e != nil {
			err = e
			break
		}
		got = append(got, f.Opcode.String())
	}
	if !slices.Equal(got, []string{"04 38", "05 38", "05 38"}) || err != broken {
		t.Errorf("got %q, %v", got, err)
	}
}

func TestLock(t *testing.T) {
	web := netip.MustParseAddrPort("10.0.0.9:7777")
	d := NewDecoder(Config{})
	d.Feed(epoch, web, cli, []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	feed(d, wiretest.AppendFrame(nil, 0x04, 0x38, 10))                // combat, but nothing known before it
	feed(d, wiretest.AppendFrame(nil, 0x05, 0x38, 10))                // and now there is: it locks
	d.Feed(epoch, web, cli, wiretest.AppendFrame(nil, 0x33, 0x36, 4)) // plausible, but not the lock's
	d.Feed(epoch, cli, srv, wiretest.AppendFrame(nil, 0x44, 0x36, 4)) // the client side
	feed(d, wiretest.AppendFrame(nil, 0x05, 0x38, 6))
	expectDir(t, d, "04 38 len=10 -\n05 38 len=10 server\n05 38 len=6 server\n")
}

// Known frames and combat from the client side do not turn the lock around.
func TestLockHolds(t *testing.T) {
	tick := slices.Repeat(wiretest.AppendFrame(nil, 0x00, 0x36, 2), 3)
	d := NewDecoder(Config{})
	feed(d, tick)
	d.Feed(epoch, cli, srv, slices.Concat(tick, wiretest.AppendFrame(nil, 0x04, 0x38, 10)))
	feed(d, wiretest.AppendFrame(nil, 0x33, 0x36, 4))
	expectDir(t, d, "00 36 len=2 -\n00 36 len=2 -\n00 36 len=2 server\n33 36 len=4 server\n")
}

// Random bytes, and TLS records split across segments, do not lock; the game's stream does.
func TestLockNoise(t *testing.T) {
	var (
		d     = NewDecoder(Config{})
		r     = rand.New(rand.NewPCG(1, 2))
		https = netip.MustParseAddrPort("10.0.0.9:443")
		seg   = make([]byte, 1400)
	)
	for i := range 1500 {
		for j := range seg {
			seg[j] = byte(r.Uint32())
		}
		if i%12 == 0 {
			copy(seg, []byte{0x17, 0x03, 0x03, 0x40, 0x00}) // a record starts, and runs on for 11 segments
		}
		d.Feed(epoch, https, cli, seg)
		frames(d)
	}
	if d.srv != nil {
		t.Fatalf("locked on noise from %v", d.srv.key.src)
	}
	feed(d, slices.Concat(
		wiretest.AppendFrame(nil, 0x00, 0x36, 2),
		wiretest.AppendFrame(nil, 0x04, 0x38, 10),
		wiretest.AppendFrame(nil, 0x05, 0x38, 10),
	))
	expectDir(t, d, "00 36 len=2 -\n04 38 len=10 server\n05 38 len=10 server\n")
}

// The lock ends when its server's stream closes, and the next server locks.
func TestLockHandover(t *testing.T) {
	var (
		d    = NewDecoder(Config{})
		next = netip.MustParseAddrPort("10.0.0.7:13328")
		f    = slices.Concat(wiretest.AppendFrame(nil, 0x04, 0x38, 10), wiretest.AppendFrame(nil, 0x05, 0x38, 10))
	)
	d.FeedSegment(segment(1, ACK, f, 0))
	d.FeedSegment(segment(1+uint32(len(f)), FIN|ACK, nil, time.Second))
	expectDir(t, d, "04 38 len=10 -\n05 38 len=10 server\n")

	d.FeedSegment(Segment{Time: epoch.Add(time.Second + closeGrace), Src: next, Dst: cli, Seq: 1, Flags: ACK, Payload: f})
	expectDir(t, d, "04 38 len=10 -\n05 38 len=10 server\n")
	if d.srv == nil || d.srv.key.src != next {
		t.Error("not locked on the new server")
	}
}

func TestEmitClient(t *testing.T) {
	d := NewDecoder(Config{EmitClient: true})
	feed(d, slices.Concat(wiretest.AppendFrame(nil, 0x04, 0x38, 10), wiretest.AppendFrame(nil, 0x05, 0x38, 10)))
	d.Feed(epoch, cli, srv, wiretest.AppendFrame(nil, 0x44, 0x36, 4))
	expectDir(t, d, "04 38 len=10 -\n05 38 len=10 server\n44 36 len=4 client\n")
}

func TestLockIdle(t *testing.T) {
	web := netip.MustParseAddrPort("10.0.0.9:7777")
	d := NewDecoder(Config{})
	var p []byte
	for range 3 {
		p = wiretest.AppendFrame(p, 0x33, 0x36, 4)
	}
	d.Feed(epoch.Add(1000), web, cli, p)
	d.Feed(epoch.Add(2000), srv, cli, wiretest.AppendFrame(nil, 0x04, 0x38, 10)) // locked on web, so ignored
	expectDir(t, d, "33 36 len=4 -\n33 36 len=4 -\n33 36 len=4 server\n")

	// web quiet for 61 s
	d.Feed(epoch.Add(2000+61*time.Second), srv, cli, slices.Concat(wiretest.AppendFrame(nil, 0x04, 0x38, 10), wiretest.AppendFrame(nil, 0x05, 0x38, 10)))
	expectDir(t, d, "04 38 len=10 -\n05 38 len=10 server\n")
}

// A game segment that starts like a TLS record is skipped while hunting, and the partial frame
// before it is dropped. On the locked pair it is parsed.
func TestTLSLookalike(t *testing.T) {
	a := wiretest.AppendFrame(nil, 0x04, 0x38, 41)
	copy(a[20:], []byte{0x16, 0x03, 0x01, 0x00, 0x05})
	b := wiretest.AppendFrame(nil, 0x05, 0x38, 9)
	for _, tt := range []struct {
		name   string
		before []byte
		want   string
	}{
		{"hunting", wiretest.AppendFrame(nil, 0x00, 0x36, 2), "05 38 len=9 resynced\n"},
		{"locked", slices.Concat(wiretest.AppendFrame(nil, 0x00, 0x36, 2), wiretest.AppendFrame(nil, 0x05, 0x38, 2)), "04 38 len=41 -\n05 38 len=9 -\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDecoder(Config{})
			feed(d, tt.before)
			frames(d)
			feed(d, a[:20])
			feed(d, a[20:])
			feed(d, b)
			expect(t, d, tt.want)
		})
	}
}

// Every known opcode is in a family, which plausible relies on.
func TestKnownInFamilies(t *testing.T) {
	for _, op := range known {
		if !inFamily(byte(op >> 8)) {
			t.Errorf("%v is known, and in no family", op)
		}
	}
}

func BenchmarkFeed(b *testing.B) {
	var plain, p []byte
	for range 20 {
		plain = wiretest.AppendFrame(plain, 0x04, 0x38, 60)
	}
	for range 200 {
		p = wiretest.AppendFrame(p, 0x33, 0x36, 120)
		p = wiretest.AppendBundle(p, plain)
	}
	d := NewDecoder(Config{})
	b.SetBytes(int64(len(p)))
	for b.Loop() {
		for rest := p; len(rest) > 0; {
			n := min(len(rest), 1460) // a segment's worth
			feed(d, rest[:n])
			rest = rest[n:]
			for range d.Frames() {
			}
		}
	}
}

// bodies returns n frames of opcode op 38, and each one's body, the opcode and payload.
func bodies(n int, op byte) (stream []byte, want []string) {
	for i := range n {
		size := 10 + i%200
		f := wiretest.AppendFrame(nil, op, 0x38, size)
		stream = append(stream, f...)
		want = append(want, string(f[len(f)-2-size:]))
	}
	return stream, want
}

// recovered counts the frames found that were sent, and those that were not.
func recovered(d *Decoder, want []string) (found, bogus int) {
	return count(slices.Collect(d.Frames()), want)
}

func count(fs []Frame, want []string) (found, bogus int) {
	left := map[string]int{}
	for _, w := range want {
		left[w]++
	}
	for _, f := range fs {
		op := f.Opcode.Bytes()
		if k := string(op[:]) + string(f.Payload); left[k] > 0 {
			left[k]--
			found++
		} else {
			bogus++
		}
	}
	return found, bogus
}

// enveloped wraps p in envelopes of size bytes.
func enveloped(p []byte, size int) []byte {
	var b []byte
	for len(p) > 0 {
		n := min(len(p), size)
		b = binary.LittleEndian.AppendUint32(b, uint32(n))
		b = append(b, p[:n]...)
		p = p[n:]
	}
	return b
}

// A segment lost from an enveloped stream costs what it costs a bare one, whether it falls
// inside a body or takes a header.
func TestEnvelopeGap(t *testing.T) {
	plain, want := bodies(3000, 0x04)
	decode := func(stream []byte) (found, bogus int) {
		d := NewDecoder(Config{})
		for i, seq := 0, 0; seq < len(stream); i++ {
			n := min(len(stream)-seq, 1400)
			if i != 20 {
				d.FeedSegment(segment(1+uint32(seq), ACK, stream[seq:seq+n], time.Duration(i)))
			}
			seq += n
		}
		d.Flush()
		return recovered(d, want)
	}
	bareFound, bareBogus := decode(plain)
	for _, size := range []int{300, 1000, 4000} {
		found, bogus := decode(enveloped(plain, size))
		if found < bareFound-3 || bogus > bareBogus+1 {
			t.Errorf("envelopes of %d: %d frames found, %d bogus; bare, %d and %d", size, found, bogus, bareFound, bareBogus)
		}
	}
}

// touched counts the frames of plain that the bytes from, to of stream cut into; plain begins at
// offset at in stream.
func touched(plain []byte, at, from, to int) (n int) {
	for len(plain) > 0 {
		v, w := binary.Uvarint(plain)
		size := int(v) + w - 4
		if at < to && at+size > from {
			n++
		}
		at += size
		plain = plain[size:]
	}
	return n
}

// A false header at the start, then a gap: no envelopes, and the frames held while undecided are
// kept.
func TestEnvelopeStartGap(t *testing.T) {
	const from, to = 500, 1900 // the bytes lost
	plain, want := bodies(12000, 0x04)
	stream := slices.Concat(binary.LittleEndian.AppendUint32(nil, 1000), plain)
	d := NewDecoder(Config{})
	d.FeedSegment(segment(1, ACK, stream[:from], 0))
	for seq := to; seq < len(stream); seq += 1400 {
		d.FeedSegment(segment(1+uint32(seq), ACK, stream[seq:min(len(stream), seq+1400)], 1))
	}
	if st := d.streams[key{src: srv, dst: cli}]; st.fr.env.on {
		t.Fatal("envelopes on")
	}
	cut := touched(plain, 4, from, to)
	if found, bogus := recovered(d, want); found != len(want)-cut || bogus > 0 {
		t.Errorf("%d of %d frames found, %d bogus; the gap cut into %d", found, len(want), bogus, cut)
	}
}

func TestEnvelopeGiveUp(t *testing.T) {
	var (
		tick       = wiretest.AppendFrame(nil, 0x00, 0x36, 8)
		first, _   = bodies(30, 0x05) // apart from the rest, which alone is counted
		rest, want = bodies(12000, 0x04)
		env        = enveloped(first, 400)
		stream     = slices.Concat(tick, env, rest)
		from, to   = len(tick) + 600, len(tick) + len(env) + 50 // lost: the last header, and the envelopes' end
		d          = NewDecoder(Config{})
	)
	d.FeedSegment(segment(1, ACK, stream[:from], 0))
	for seq := to; seq < len(stream); seq += 1400 {
		d.FeedSegment(segment(1+uint32(seq), ACK, stream[seq:min(len(stream), seq+1400)], 1))
	}
	d.Flush()
	if st := d.streams[key{src: srv, dst: cli}]; st.fr.env.on {
		t.Fatal("envelopes still on")
	}
	var restFrames []Frame
	for f := range d.Frames() {
		if f.Opcode == 0x3804 {
			restFrames = append(restFrames, f)
		}
	}
	cut := touched(rest, len(tick)+len(env), from, to)
	if found, bogus := count(restFrames, want); found != len(want)-cut || bogus > 0 {
		t.Errorf("%d of %d frames found, %d bogus; the gap cut into %d", found, len(want), bogus, cut)
	}
}

func BenchmarkNoise(b *testing.B) {
	p := make([]byte, 1<<20)
	rand.NewChaCha8([32]byte{1}).Read(p)
	noise := netip.MustParseAddrPort("10.0.0.9:443")
	b.SetBytes(int64(len(p)))
	for b.Loop() {
		d := NewDecoder(Config{})
		for rest := p; len(rest) > 0; {
			n := min(len(rest), 1400)
			d.Feed(epoch, noise, cli, rest[:n])
			rest = rest[n:]
			for range d.Frames() {
			}
		}
	}
}

// A full buffer drops bytes that were already stripped, so a header split across writes stays
// where it was.
func TestEnvelopeSkipNothing(t *testing.T) {
	e := envelopes{on: true, have: 2}
	e.skip(0)
	if e.lost || e.have != 2 {
		t.Errorf("lost %v, have %d; want the split header kept", e.lost, e.have)
	}
}

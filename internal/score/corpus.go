package main

import (
	"encoding/binary"
	"math"
	"math/rand/v2"
	"net/netip"
	"time"

	"github.com/nuriland/a2kit/internal/wiretest"
	"github.com/nuriland/a2kit/wire"
)

// The endpoints of every capture.
var (
	srv = netip.MustParseAddrPort("10.0.0.2:13328")
	cli = netip.MustParseAddrPort("10.0.0.1:10000")
)

// Opcodes the game sends often, and the families, as a stream draws them.
var (
	hints    = [...][2]byte{{0x04, 0x38}, {0x05, 0x38}, {0x02, 0x38}, {0x06, 0x38}, {0x22, 0x38}, {0x2A, 0x38}, {0x33, 0x36}, {0x00, 0x36}, {0x00, 0x8D}, {0x1B, 0x92}, {0x0D, 0x92}}
	families = [...]byte{0x36, 0x38, 0x8D, 0x92, 0x96, 0x97}
	small    = [...]int{0, 1, 2, 5, 12, 41, 200, 300}
)

// A corpus is captures of one server stream each, damaged the way captures are.
type corpus struct {
	name string
	big  float64 // the share of pieces that are big frames
	seed uint64
}

// frame is what a frame must come out as.
type frame struct {
	op      wire.Opcode
	payload string
}

// sampler draws one stream, and notes the frames in it.
type sampler struct {
	r    *rand.Rand
	big  float64
	want []frame
}

// sampler draws capture i of c, for the pcap or, with feed set, the pieces fed.
func (c corpus) sampler(i uint64, feed bool) *sampler {
	seed := i << 1
	if feed {
		seed |= 1
	}
	return &sampler{r: rand.New(rand.NewPCG(c.seed, seed)), big: c.big}
}

// stream draws 30 to 250 pieces. Three times in ten it starts a few bytes before one of the
// first half of them, as a live capture does, and the frames before that are not in it.
func (s *sampler) stream() ([]byte, []frame) {
	var (
		b      []byte
		starts []int // where each piece begins
		before []int // the frames noted before it
	)
	for range 30 + s.r.IntN(221) {
		starts = append(starts, len(b))
		before = append(before, len(s.want))
		b = s.piece(b)
	}
	if s.r.Float64() >= 0.3 {
		return b, s.want
	}
	k := 1 + s.r.IntN(len(starts)/2-1)
	from := max(0, starts[k]-1-s.r.IntN(7))
	for k > 0 && starts[k-1] >= from {
		k-- // a piece wholly after the cut is still whole
	}
	return b[from:], s.want[before[k]:]
}

// piece is a big frame, a small one, a bundle, or padding.
func (s *sampler) piece(b []byte) []byte {
	if s.r.Float64() < s.big {
		return s.frame(b, s.bigSize())
	}
	switch c := s.r.Float64(); {
	case c < 0.65:
		return s.frame(b, small[s.r.IntN(len(small))])
	case c < 0.95:
		return s.bundle(b, 0)
	}
	return append(b, make([]byte, 1+s.r.IntN(2))...)
}

// bigSize is log-uniform from 1 to 512 KiB, so that no size is favored over another.
func (s *sampler) bigSize() int {
	return int(1024 * math.Exp(s.r.Float64()*math.Log(512)))
}

// bundle holds 1 to 5 small frames, now and then with padding between, or a bundle of its own,
// three deep at most. One in ten is flagged.
func (s *sampler) bundle(b []byte, depth int) []byte {
	var plain []byte
	for range 1 + s.r.IntN(5) {
		if depth < 3 && s.r.Float64() < 0.2 {
			plain = s.bundle(plain, depth+1)
		} else {
			plain = s.frame(plain, small[s.r.IntN(len(small))])
		}
		if s.r.Float64() < 0.2 {
			plain = append(plain, make([]byte, 1+s.r.IntN(2))...)
		}
	}
	if s.r.Float64() < 0.1 {
		return wiretest.AppendFlagged(b, byte(0xF0+s.r.IntN(15)), plain)
	}
	return wiretest.AppendBundle(b, plain)
}

// frame appends a frame with size bytes of random payload, its opcode known six times in ten,
// of a family most of the rest, and anything else otherwise.
func (s *sampler) frame(b []byte, size int) []byte {
	var op0, op1 byte
	for {
		switch c := s.r.Float64(); {
		case c < 0.6:
			h := hints[s.r.IntN(len(hints))]
			op0, op1 = h[0], h[1]
		case c < 0.85:
			op0, op1 = byte(s.r.Uint32()), families[s.r.IntN(len(families))]
		default:
			op0, op1 = byte(s.r.Uint32()), byte(s.r.Uint32())
		}
		if op1 != 0xFF { // FF there begins a bundle
			break
		}
	}
	payload := make([]byte, size)
	for i := 0; i < size; i += 8 {
		var w [8]byte
		binary.LittleEndian.PutUint64(w[:], s.r.Uint64())
		copy(payload[i:], w[:])
	}
	s.want = append(s.want, frame{wire.Opcode(op0) | wire.Opcode(op1)<<8, string(payload)})
	b = binary.AppendUvarint(b, uint64(2+size+4))
	b = append(b, op0, op1)
	return append(b, payload...)
}

// capture cuts b into segments of 100 to 1400 bytes, sends one in ten a few places late, loses
// one to three, and writes what is left as an Ethernet pcap, a millisecond or so apart.
func (s *sampler) capture(b []byte) []byte {
	type segment struct{ off, n int }
	var segs []segment
	for off := 0; off < len(b); {
		n := min(len(b)-off, 100+s.r.IntN(1300))
		segs = append(segs, segment{off, n})
		off += n
	}
	order := make([]int, len(segs))
	for i := range order {
		order[i] = i
	}
	for i := range order {
		if s.r.Float64() < 0.1 {
			j := min(len(order)-1, i+1+s.r.IntN(4))
			order[i], order[j] = order[j], order[i]
		}
	}
	for range 1 + s.r.IntN(3) {
		if len(order) > 4 {
			i := 1 + s.r.IntN(len(order)-1)
			order = append(order[:i], order[i+1:]...)
		}
	}

	var (
		isn = s.r.Uint32()
		t   = time.Unix(1700000000, 0)
		pc  = wiretest.NewPcap(binary.LittleEndian, false, 1)
	)
	for _, i := range order {
		seg := segs[i]
		pc.Add(t, wiretest.Ethernet(wiretest.TCP(srv, cli, isn+uint32(seg.off), byte(wire.PSH|wire.ACK), b[seg.off:seg.off+seg.n])))
		t = t.Add(time.Duration(1+s.r.IntN(2000)) * time.Microsecond)
	}
	return pc.Bytes()
}

// feed gives b to d in pieces of up to 40 or up to 4000 bytes, and sends one piece in sixteen
// the other way, so that the server's stream loses it with nothing to say so.
func (s *sampler) feed(d *wire.Decoder, b []byte) {
	t := time.Unix(1700000000, 0)
	for len(b) > 0 {
		n := 1 + s.r.IntN(40)
		if s.r.IntN(2) == 0 {
			n = 1 + s.r.IntN(4000)
		}
		n = min(n, len(b))
		if s.r.IntN(16) == 0 {
			d.Feed(t, cli, srv, b[:n])
		} else {
			d.Feed(t, srv, cli, b[:n])
		}
		b = b[n:]
		t = t.Add(time.Microsecond)
	}
}

package main

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/nuriland/a2kit/wire"
)

// A session is a capture read through the decoder
type session struct {
	start          time.Time // the capture's first segment, which offsets count from
	first, last    time.Time // the session's own first and last frame or segment
	server, client netip.AddrPort
	locks          int          // the pairs the decoder locked on
	frames         []wire.Frame // the server's, by time
	sent           []segment    // the client's data segments, in order

	background map[wire.Opcode]bool // what the server sends whether the player acts or not
	usual      map[int]bool         // the sizes the client sends every second
}

// A flow is one direction of a connection, as the decoder keys its streams.
type flow struct {
	src, dst netip.AddrPort
	ifIndex  int
}

// segment is a data segment's header, which is all there is to know of the client's.
type segment struct {
	flow
	t    time.Time
	size int
}

// tee reads segments for the decoder and keeps the headers of those that carry new bytes
type tee struct {
	r     wire.SegmentReader
	first time.Time
	ends  map[flow]uint32 // the furthest byte each flow has sent
	segs  []segment
}

// ReadSegment reads a segment from the tee
func (t *tee) ReadSegment() (wire.Segment, error) {
	s, err := t.r.ReadSegment()
	if err != nil {
		return s, err
	}
	if t.first.IsZero() || s.Time.Before(t.first) {
		t.first = s.Time
	}
	if len(s.Payload) == 0 {
		return s, nil
	}
	k := flow{s.Src, s.Dst, s.IfIndex}
	end := s.Seq + uint32(len(s.Payload))
	if seen, ok := t.ends[k]; !ok || int32(end-seen) > 0 {
		t.ends[k] = end
		t.segs = append(t.segs, segment{k, s.Time, len(s.Payload)})
	}
	return s, nil
}

// read decodes a capture
// @TODO: add documentation
func read(r wire.SegmentReader) (*session, error) {
	t := &tee{r: r, ends: make(map[flow]uint32)}
	var frames []wire.Frame
	locked := make(map[flow]int)
	for f, err := range wire.NewDecoder(wire.Config{}).Decode(t) {
		if err != nil {
			return nil, err
		}
		frames = append(frames, f)
		if f.Flags&wire.FromServer != 0 {
			locked[flow{f.Src, f.Dst, f.IfIndex}]++
		}
	}
	if len(locked) == 0 {
		return nil, errors.New("no game stream: the decoder never locked")
	}
	var srv flow
	for _, f := range frames { // in order, so that a tie goes to the earlier pair
		if k := (flow{f.Src, f.Dst, f.IfIndex}); locked[k] > locked[srv] {
			srv = k
		}
	}
	s := &session{start: t.first, server: srv.src, client: srv.dst, locks: len(locked)}
	for _, f := range frames {
		if (flow{f.Src, f.Dst, f.IfIndex}) == srv {
			s.frames = append(s.frames, f)
		}
	}
	slices.SortStableFunc(s.frames, func(a, b wire.Frame) int { return a.Time.Compare(b.Time) })
	back := flow{srv.dst, srv.src, srv.ifIndex}
	for _, g := range t.segs {
		if g.flow == back {
			s.sent = append(s.sent, g)
		}
	}
	s.first, s.last = s.frames[0].Time, s.frames[len(s.frames)-1].Time
	for _, g := range s.sent {
		if g.t.Before(s.first) {
			s.first = g.t
		}
		if g.t.After(s.last) {
			s.last = g.t
		}
	}
	s.usual = usualSizes(s.sent)
	s.background = s.ambient()
	return s, nil
}

// usualSizes picks the sizes the client sends all the time
func usualSizes(sent []segment) map[int]bool {
	secs := make(map[int64]bool)
	by := make(map[int]map[int64]bool)
	for _, g := range sent {
		secs[g.t.Unix()] = true
		if by[g.size] == nil {
			by[g.size] = make(map[int64]bool)
		}
		by[g.size][g.t.Unix()] = true
	}
	usual := make(map[int]bool)
	for size, in := range by {
		if 2*len(in) > len(secs) {
			usual[size] = true
		}
	}
	return usual
}

// ambient picks what the server sends whether the player acts or not
func (s *session) ambient() map[wire.Opcode]bool {
	acting := make(map[int64]bool)
	for _, g := range s.sent {
		if !s.usual[g.size] {
			acting[g.t.Unix()] = true
		}
	}
	if len(acting) == 0 {
		return nil
	}
	quiet := s.last.Unix() - s.first.Unix() + 1 - int64(len(acting))
	inQuiet, inActing := make(map[wire.Opcode]int64), make(map[wire.Opcode]int64)
	for _, f := range s.frames {
		if acting[f.Time.Unix()] {
			inActing[f.Opcode]++
		} else {
			inQuiet[f.Opcode]++
		}
	}
	ambient := make(map[wire.Opcode]bool)
	for op, n := range inQuiet {
		if 2*n >= quiet && 2*n*int64(len(acting)) >= inActing[op]*quiet {
			ambient[op] = true
		}
	}
	return ambient
}

// between returns the frames from t0 up to t1.
func (s *session) between(t0, t1 time.Time) []wire.Frame {
	byTime := func(f wire.Frame, t time.Time) int { return f.Time.Compare(t) }
	i, _ := slices.BinarySearchFunc(s.frames, t0, byTime)
	j, _ := slices.BinarySearchFunc(s.frames, t1, byTime)
	return s.frames[i:j]
}

// since is how far into the capture t is, the way -at takes it
func (s *session) since(t time.Time) string { return fmt.Sprintf("%.2fs", t.Sub(s.start).Seconds()) }

// summary is the session in a line: the endpoints, the span, the frames, and what the client sends all the time.
func (s *session) summary() string {
	ops := make(map[wire.Opcode]bool)
	for _, f := range s.frames {
		ops[f.Opcode] = true
	}
	return fmt.Sprintf("%v to %v: %.1fs, %d frames of %d opcodes; the client sent %d segments, of %s bytes all the time",
		s.server, s.client, s.last.Sub(s.first).Seconds(), len(s.frames), len(ops), len(s.sent), listed(s.usual))
}

// listed returns the keys of m in order, or "none".
func listed[K cmp.Ordered](m map[K]bool) string {
	if len(m) == 0 {
		return "none"
	}
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		parts = append(parts, fmt.Sprint(k))
	}
	return strings.Join(parts, ", ")
}

// sizes describes payload sizes, frames by size: "7", or "9..12 (4 sizes)".
func sizes(m map[int]int) string {
	all := slices.Sorted(maps.Keys(m))
	if len(all) == 1 {
		return fmt.Sprint(all[0])
	}
	return fmt.Sprintf("%d..%d (%d sizes)", all[0], all[len(all)-1], len(all))
}

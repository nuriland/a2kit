package wire

import (
	"bytes"
	"cmp"
	"maps"
	"net/netip"
	"slices"
	"time"
)

const (
	maxStreams   = 64              // streams a decoder holds at once
	maxHeld      = 64              // segments held past a gap
	maxHeldBytes = 256 << 10       // bytes held past a gap
	maxGapWait   = time.Second     // how long a segment waits behind a gap
	closeGrace   = 2 * time.Second // how long a closed stream is kept
)

// key identifies one direction of a connection.
type key struct {
	src, dst netip.AddrPort
	ifIndex  int
}

func (k key) reverse() key { return key{k.dst, k.src, k.ifIndex} }

// stream is one direction of one TCP connection.
type stream struct {
	key    key
	dir    Flags     // FromServer, FromClient, or 0 while hunting
	last   time.Time // the time of its newest bytes
	at     time.Time // the capture time of the bytes being parsed
	closed time.Time // the time of its FIN or RST, zero while open
	fr     framer
	born   uint64
	frames int // frames counted toward the lock

	// Reassembly, for FeedSegment.
	synced    bool   // next is set
	next      uint32 // the sequence number of the next byte in order
	syn       uint32 // the sequence number after its SYN, if one was seen
	heldBytes int
	held      []piece
}

// piece is a segment held past a gap.
type piece struct {
	seq  uint32
	t    time.Time
	data []byte
}

// after reports whether sequence number a comes after b, allowing for wraparound.
func after(a, b uint32) bool { return int32(a-b) > 0 }

// hold inserts a segment into held, in sequence order. It reports whether the segment is held,
// including when a copy of it already was.
func (d *Decoder) hold(st *stream, seq uint32, t time.Time, p []byte) bool {
	i := len(st.held)
	for i > 0 && after(st.held[i-1].seq, seq) {
		i--
	}
	if i > 0 && st.held[i-1].seq == seq && len(st.held[i-1].data) >= len(p) {
		return true // a retransmit
	}
	if len(st.held) == maxHeld || st.heldBytes+len(p) > maxHeldBytes {
		return false
	}
	st.held = slices.Insert(st.held, i, piece{seq, t, bytes.Clone(p)})
	st.heldBytes += len(p)
	d.held++
	return true
}

// stale reports whether a held segment has waited maxGapWait.
func (st *stream) stale(t time.Time) bool {
	return slices.ContainsFunc(st.held, func(pc piece) bool { return t.Sub(pc.t) >= maxGapWait })
}

// sweep drops the streams closed longer than closeGrace ago.
func (d *Decoder) sweep(t time.Time) {
	if d.closing == 0 {
		return
	}
	for _, st := range d.streams {
		if !st.closed.IsZero() && t.Sub(st.closed) >= closeGrace {
			d.drop(st)
		}
	}
}

// stream returns the stream for k, making it if needed. When the table is full, the stalest
// hunting stream is dropped; there always is one, since a lock admits only its own pair.
func (d *Decoder) stream(k key, t time.Time) *stream {
	if st := d.last; st != nil && st.key == k {
		return st
	}
	if st := d.streams[k]; st != nil {
		d.last = st
		return st
	}

	if len(d.streams) >= maxStreams {
		d.drop(d.stalest())
	}

	st := &stream{key: k, last: t, born: d.born}
	st.fr = framer{
		knownOnly: d.c.KnownOnly,
		log:       d.l,
		emit:      func(body []byte, flags Flags) { d.emit(st, body, flags) },
	}
	if d.srv != nil {
		st.dir = FromClient // made while locked, so its reverse is the server
	}
	d.born++
	d.streams[k] = st
	d.last = st
	return st
}

// stalest returns the hunting stream heard from longest ago. Ties go to the oldest stream, so
// that the choice does not depend on map order.
func (d *Decoder) stalest() *stream {
	var old *stream
	for _, st := range d.streams {
		if st.dir != 0 {
			continue
		}
		if old == nil || cmp.Or(st.last.Compare(old.last), cmp.Compare(st.born, old.born)) < 0 {
			old = st
		}
	}
	return old
}

// drop removes st, and ends the lock if st is its server.
func (d *Decoder) drop(st *stream) {
	if d.srv == st {
		d.unlock()
	}
	if !st.closed.IsZero() {
		d.closing--
	}
	if d.last == st {
		d.last = nil
	}
	d.held -= len(st.held)
	delete(d.streams, st.key)
}

// place discards what is old, delivers what is next, and holds what is early. A gap that has held
// a segment for maxGapWait is given up first.
func (d *Decoder) place(st *stream, seq uint32, p []byte, t time.Time) {
	for st.stale(t) {
		d.skip(st, st.held[0].seq)
	}
	for {
		if !after(seq+uint32(len(p)), st.next) {
			return
		}
		if !after(seq, st.next) {
			d.deliver(st, p[st.next-seq:], t)
			d.release(st)
			return
		}
		if d.hold(st, seq, t, p) {
			return
		}
		d.skip(st, seq) // no room left to wait
	}
}

// acked gives up the gaps in k's stream that its receiver has acknowledged: the receiver has
// those bytes, so no retransmit is coming for the capture to see. A gap is given up only once the
// ACK reaches the data held past it, so the stream never jumps further than bytes it has.
func (d *Decoder) acked(k key, ack uint32) {
	st := d.streams[k]
	if st == nil {
		return
	}
	for len(st.held) > 0 && !after(st.held[0].seq, ack) {
		d.skip(st, st.held[0].seq)
	}
}

// deliver advances the sequence past p and hands p to the framer.
func (d *Decoder) deliver(st *stream, p []byte, t time.Time) {
	st.next += uint32(len(p))
	d.take(st, p, t)
}

// take hands p, captured at t, to the stream's framer. Unless ParseTLS is set, a segment that
// starts like a TLS record is skipped and counted as lost. The locked pair is never skipped.
func (d *Decoder) take(st *stream, p []byte, t time.Time) {
	st.at = t
	if !d.c.ParseTLS && st.dir == 0 && tlsLike(p) {
		st.fr.lose(len(p))
		return
	}
	st.fr.write(p)
}

// release delivers the held segments that are in order now.
func (d *Decoder) release(st *stream) {
	i := 0
	for ; i < len(st.held) && !after(st.held[i].seq, st.next); i++ {
		pc := st.held[i]
		if old := st.next - pc.seq; old < uint32(len(pc.data)) {
			d.deliver(st, pc.data[old:], pc.t)
		}
		st.heldBytes -= len(pc.data)
	}
	st.held = slices.Delete(st.held, 0, i)
	d.held -= i
}

// skip gives up the oldest gap. The stream jumps to the first data it has, held or at seq, and
// the framer is told that the bytes between are lost.
func (d *Decoder) skip(st *stream, seq uint32) {
	var to = seq
	if len(st.held) > 0 && after(seq, st.held[0].seq) {
		to = st.held[0].seq
	}
	d.l.Warn("tcp gap lost", "bytes", to-st.next)
	st.fr.lose(int(to - st.next))
	st.next = to
	d.release(st)
}

// Flush treats the capture as ended: every gap is given up, and what streams held while waiting
// for more bytes is parsed. Decode calls Flush when its reader ends.
func (d *Decoder) Flush() {
	sts := slices.SortedFunc(maps.Values(d.streams), func(a, b *stream) int { return cmp.Compare(a.born, b.born) })
	for _, st := range sts {
		for d.streams[st.key] == st && len(st.held) > 0 { // a lock taken here drops the other streams
			d.skip(st, st.held[0].seq)
		}
		if d.streams[st.key] == st {
			st.fr.end()
		}
	}
}

// tlsLike reports whether p starts like a TLS record: a type from 20 to 23, then version 3.0 to 3.4.
func tlsLike(p []byte) bool {
	return len(p) >= 5 && p[0] >= 0x14 && p[0] <= 0x17 && p[1] == 0x03 && p[2] <= 0x04
}

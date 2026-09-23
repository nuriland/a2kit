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
	maxStreams   = 64              // the most streams a decoder holds at once
	maxHeld      = 64              // segments held past a gap
	maxHeldBytes = 256 << 10       // and their bytes
	maxGapWait   = time.Second     // how long a gap holds segments back; a retransmit comes sooner
	closeGrace   = 2 * time.Second // after its FIN, a stream is dropped
)

type key struct {
	src, dst netip.AddrPort
	ifIndex  int
}

func (k key) reverse() key { return key{k.dst, k.src, k.ifIndex} }

// stream is one direction of one TCP connection.
type stream struct {
	key    key
	dir    Flags     // FromServer, FromClient, or 0 while hunting
	last   time.Time // its newest bytes
	at     time.Time // when the bytes being parsed were captured, for their frames
	closed time.Time // its FIN or RST, and zero while open
	fr     framer
	born   uint64
	frames int // known frames since the last resync, toward the lock

	// Reassembly, for FeedSegment.
	synced    bool   // next is set
	next      uint32 // the sequence number of the next byte in order
	syn       uint32 // the sequence number after its SYN
	heldBytes int
	held      []piece
}

// piece is a segment held past a gap.
type piece struct {
	seq  uint32
	t    time.Time
	data []byte
}

// after compares sequence numbers across wraparound
func after(a, b uint32) bool { return int32(a-b) > 0 }

// hold keeps held in sequence order. It reports whether the segment is held, now or already held
func (st *stream) hold(seq uint32, t time.Time, p []byte) bool {
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
	return true
}

// stale is whether a segment has waited maxGapWait behind a gap.
func (st *stream) stale(t time.Time) bool {
	return slices.ContainsFunc(st.held, func(pc piece) bool { return t.Sub(pc.t) >= maxGapWait })
}

// sweep drops the streams closed longer than closeGrace ago.
func (d *Decoder) sweep(t time.Time) {
	for _, st := range d.streams {
		if !st.closed.IsZero() && t.Sub(st.closed) >= closeGrace {
			d.drop(st)
		}
	}
}

// stream finds or makes the stream for k.
// With every slot taken, the stalest hunting stream gives way, and there always is one, a lock admits only its own pair.
func (d *Decoder) stream(k key, t time.Time) *stream {
	if st := d.streams[k]; st != nil {
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
		st.dir = FromClient // admitted while locked, so its reverse is the lock
	}
	d.born++
	d.streams[k] = st
	return st
}

// stalest breaks ties by age, since map order is random and Feed's times tie.
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

func (d *Decoder) drop(st *stream) {
	if d.srv == st {
		d.unlock()
	}
	delete(d.streams, st.key)
}

// place drops what is old, delivers what is next, and holds what is early.
// A gap that has held segments back for maxGapWait is given up first: the capture missed it.
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
		if st.hold(seq, t, p) {
			return
		}
		d.skip(st, seq) // no room left to wait
	}
}

func (d *Decoder) deliver(st *stream, p []byte, t time.Time) {
	st.next += uint32(len(p))
	d.take(st, p, t)
}

// take hands p, captured at t, to the stream's framer. A segment that starts like TLS is skipped, and
// counted lost so that the framer does not join what comes after onto what came before. The lock's pair
// is never skipped: it is the game's.
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
}

// skip gives up the oldest gap. The stream jumps to the first data it has, held or at seq, not past it, so a lost packet costs only its own frames.
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

// Flush gives up every gap, so what is held behind one is parsed now. Decode calls it when its reader ends.
func (d *Decoder) Flush() {
	sts := slices.SortedFunc(maps.Values(d.streams), func(a, b *stream) int { return cmp.Compare(a.born, b.born) })
	for _, st := range sts {
		for d.streams[st.key] == st && len(st.held) > 0 { // a lock found on the way drops the others
			d.skip(st, st.held[0].seq)
		}
	}
}

// tlsLike reports whether p starts a TLS record, a record type from 20 to 23, then version 3.0 to 3.4.
func tlsLike(p []byte) bool {
	return len(p) >= 5 && p[0] >= 0x14 && p[0] <= 0x17 && p[1] == 0x03 && p[2] <= 0x04
}

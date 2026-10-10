package wire

import (
	"bytes"
	"cmp"
	"io"
	"iter"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"time"
)

// Config configures a Decoder. The zero Config is ready to use.
type Config struct {
	EmitClient   bool          // keep the client side's frames too, whose bodies are encrypted
	EmitUnlocked bool          // keep what the hunt finds too, on every stream, with no direction
	KnownOnly    bool          // keep only known opcodes, and take no others as plausible
	ParseTLS     bool          // parse segments that start like TLS records
	LockIdle     time.Duration // the silence that ends the lock, 60s if zero
	Logger       *slog.Logger  // resyncs, locks and lost gaps, nil is silent
}

// slabSize is the allocation that payloads are copied into, many frames to one.
const slabSize = 16 << 10

// Decoder turns TCP segments into frames, and keeps them until they are taken. It is not safe
// for concurrent use.
type Decoder struct {
	config Config
	log    *slog.Logger

	born    uint64          // streams made
	closing int             // streams that have seen a FIN or RST, for sweep
	held    int             // segments held past gaps, in every stream
	head    int             // index of the first unyielded frame
	streams map[key]*stream // streams by source and destination
	last    *stream         // the stream looked up last
	srv     *stream         // the locked server side, nil while hunting
	lockAt  time.Time       // the newest traffic on the lock
	stats   Stats           // the locks, and the resyncs of streams no longer locked
	queue   []Frame         // frames to yield
	slab    []byte          // room for the payloads of the next frames
}

// NewDecoder returns a Decoder configured by config.
func NewDecoder(config Config) *Decoder {
	if config.LockIdle <= 0 {
		config.LockIdle = 60 * time.Second
	}
	log := config.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Decoder{config: config, log: log, streams: make(map[key]*stream)}
}

// Feed adds a payload that has no sequence number. Each direction's payloads must be fed in
// order, and Flush called when the input ends.
func (d *Decoder) Feed(t time.Time, src, dst netip.AddrPort, payload []byte) {
	if len(payload) == 0 {
		return
	}
	k := key{src: src, dst: dst}
	if !d.admit(k, t) {
		return
	}
	st := d.stream(k, t)
	st.last = t
	d.take(st, payload, t)
}

// FeedSegment adds a segment, placed by its sequence number. Old bytes are discarded, and bytes
// past a gap are held until the gap fills or is given up. An ACK gives up the gaps in the other
// direction that it acknowledges.
func (d *Decoder) FeedSegment(s Segment) {
	k := key{s.Src, s.Dst, s.IfIndex}
	if !d.admit(k, s.Time) {
		return
	}
	if s.Flags&ACK != 0 && d.held > 0 { // with nothing held, there is no gap to give up
		d.acked(k.reverse(), s.Ack)
	}
	if len(s.Payload) == 0 && s.Flags&(SYN|FIN|RST) == 0 {
		return // a bare ack
	}

	var (
		st  = d.stream(k, s.Time)
		seq = s.Seq
	)
	if s.Flags&SYN != 0 {
		seq++ // the SYN takes a sequence number of its own
		if st.synced && seq != st.syn {
			d.drop(st) // a new connection on the same ports
			st = d.stream(k, s.Time)
		}
		st.syn = seq
	}
	st.last = s.Time
	if s.Flags&(FIN|RST) != 0 {
		if st.closed.IsZero() {
			d.closing++
		}
		st.closed = s.Time
	}
	seen := st.synced
	if !st.synced {
		st.synced, st.next = true, seq
	}
	if len(s.Payload) > 0 {
		d.place(st, seq, s.Payload, s.Time)
	}
	if d.srv != nil && seen && s.Flags&(FIN|RST) != 0 && st.next == seq+uint32(len(s.Payload)) {
		d.letGo(st, s.Time)
	}
}

// Frames yields the frames found so far, oldest first, and removes them.
func (d *Decoder) Frames() iter.Seq[Frame] {
	return func(yield func(Frame) bool) {
		for d.head < len(d.queue) {
			f := d.queue[d.head]
			d.queue[d.head] = Frame{}
			d.head++
			if !yield(f) {
				return
			}
		}
		d.queue, d.head = d.queue[:0], 0
	}
}

// Flush treats the capture as ended: every gap is given up, and what streams held while waiting
// for more bytes is parsed. The frames still waiting for a lock were not the game's, and are
// dropped. Decode calls Flush when its reader ends.
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
	for _, st := range d.streams {
		st.early, st.earlyBytes = nil, 0
	}
}

// Decode reads r to its end and yields frames as its segments complete them. It calls Flush
// when r ends. A read error other than io.EOF is yielded last.
func (d *Decoder) Decode(r SegmentReader) iter.Seq2[Frame, error] {
	return func(yield func(Frame, error) bool) {
		drain := func() bool {
			for f := range d.Frames() {
				if !yield(f, nil) {
					return false
				}
			}
			return true
		}
		for drain() {
			s, err := r.ReadSegment()
			if err != nil {
				d.Flush()
				if drain() && err != io.EOF {
					yield(Frame{}, err)
				}
				return
			}
			d.FeedSegment(s)
		}
	}
}

// emit queues a frame, or while hunting keeps it on its stream until the lock says whose it is.
//
//	The payload is copied, since body points into a buffer that is reused.
func (d *Decoder) emit(st *stream, body []byte, flags Flags) {
	op := opcode(body)
	if d.srv == nil {
		d.hunt(st, op, flags) // a lock queues the pair's early frames, before this one
	}
	flags |= st.dir
	if flags&FromClient != 0 && !d.config.EmitClient {
		return
	}
	if d.config.KnownOnly && !op.listed() {
		return
	}
	f := Frame{
		Time:    st.at,
		Src:     st.key.src,
		Dst:     st.key.dst,
		IfIndex: st.key.ifIndex,
		Opcode:  op,
		Payload: d.keep(body[2:]),
		Flags:   flags,
	}
	if st.dir == 0 && !d.config.EmitUnlocked {
		st.wait(f)
		return
	}
	d.queue = append(d.queue, f)
}

// keep returns a copy of p for a frame to own. Payloads share slabs, so that a frame costs an
// allocation only once in a while, and a frame that is kept keeps its slab. A copy from a slab is
// capped at its length, so that appending to one cannot reach the next.
func (d *Decoder) keep(p []byte) []byte {
	if len(p) > slabSize/4 {
		return bytes.Clone(p)
	}
	if len(p) >= len(d.slab) { // >=, so that an empty payload is never nil
		d.slab = make([]byte, slabSize)
	}
	c := d.slab[:len(p):len(p)]
	d.slab = d.slab[len(p):]
	copy(c, p)
	return c
}

// admit reports whether bytes on k are parsed. While locked, only the pair is admitted, and its traffic keeps the lock alive.
func (d *Decoder) admit(k key, t time.Time) bool {
	d.sweep(t)
	if d.srv == nil {
		return true
	}
	if d.srv.key == k || d.srv.key == k.reverse() {
		if t.After(d.lockAt) {
			d.lockAt = t
		}
		return true
	}

	if t.Sub(d.lockAt) > d.config.LockIdle {
		d.log.Info("flow idle, hunting")
		d.unlock()
		return true
	}
	return false
}

// hunt counts a frame toward the lock, and locks on its stream once it has earned it.
func (d *Decoder) hunt(st *stream, op Opcode, flags Flags) {
	if st.dir != 0 {
		return
	}
	if flags&Resynced != 0 {
		st.frames = 0
	}
	if !op.Known() || !st.fr.trusted() {
		return
	}
	st.frames++
	switch {
	case combat(op) && st.frames >= 2:
		d.lock(st, "combat opcode")
	case st.frames >= 3:
		d.lock(st, "3 known frames")
	}
}

// lock makes st the server side and its peer the client, queues the frames they found while hunting, and drops every other stream.
func (d *Decoder) lock(st *stream, why string) {
	d.srv, d.lockAt = st, st.last
	d.stats.Locks++
	d.stats.Server, d.stats.Client = st.key.src, st.key.dst
	st.dir = FromServer
	d.queueEarly(st)

	var peer *stream
	if peer = d.streams[st.key.reverse()]; peer != nil {
		peer.dir = FromClient
		d.queueEarly(peer)
	}
	dropped := 0
	for _, o := range d.streams {
		if o != st && o != peer {
			d.drop(o)
			dropped++
		}
	}
	d.log.Info("flow locked", "src", st.key.src, "dst", st.key.dst, "why", why, "dropped", dropped)
}

// queueEarly queues the frames st found while hunting, marked as the lock found it.
func (d *Decoder) queueEarly(st *stream) {
	if st.dir == FromServer || d.config.EmitClient {
		for _, f := range st.early {
			f.Flags |= st.dir
			d.queue = append(d.queue, f)
		}
	}
	st.early, st.earlyBytes = nil, 0
}

// letGo ends the lock when one side of its pair closes, as the lobby's does when it hands the
// client to a world server, and hunts at once.
func (d *Decoder) letGo(st *stream, t time.Time) {
	d.log.Info("flow closed, hunting", "src", st.key.src, "dst", st.key.dst)
	d.srv = nil
	if peer := d.streams[st.key.reverse()]; peer != nil && peer.closed.IsZero() {
		peer.closed = t
		d.closing++
	}
}

// unlock resets the decoder to hunting
func (d *Decoder) unlock() {
	d.srv = nil
	for _, st := range d.streams {
		d.fold(st)
		st.dir, st.frames = 0, 0
	}
}

// fold adds st's resyncs to the totals, and starts it counting again.
func (d *Decoder) fold(st *stream) {
	d.stats.count(st)
	st.fr.resyncs = 0
}

// Stats reports what d has seen so far
func (d *Decoder) Stats() Stats {
	s := d.stats
	s.Locked = d.srv != nil
	for _, st := range d.streams {
		s.count(st)
	}
	return s
}

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

// stream returns the stream for k, making it if needed. When the table is full, the stalest hunting stream is dropped.
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
		knownOnly: d.config.KnownOnly,
		log:       d.log.With("src", k.src, "dst", k.dst),
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

// stalest returns the hunting stream heard from longest ago.
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
	d.fold(st)
	if !st.closed.IsZero() {
		d.closing--
	}
	if d.last == st {
		d.last = nil
	}
	d.held -= len(st.held)
	delete(d.streams, st.key)
}

// place discards what is old, delivers what is next, and holds what is early.
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

// acked gives up the gaps in k's stream that its receiver has acknowledged.
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

// take hands p, captured at t, to the stream's framer.
func (d *Decoder) take(st *stream, p []byte, t time.Time) {
	st.at = t
	if !d.config.ParseTLS && st.dir == 0 && tlsLike(p) {
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

// skip gives up the oldest gap.
func (d *Decoder) skip(st *stream, seq uint32) {
	var to = seq
	if len(st.held) > 0 && after(seq, st.held[0].seq) {
		to = st.held[0].seq
	}
	st.fr.log.Warn("tcp gap lost", "bytes", to-st.next)
	st.fr.lose(int(to - st.next))
	st.next = to
	d.release(st)
}

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
	EmitClient bool          // keep the client side's frames too, whose bodies are encrypted
	KnownOnly  bool          // keep only known opcodes, and take no others as plausible
	ParseTLS   bool          // parse segments that start like TLS records
	LockIdle   time.Duration // the silence that ends the lock, 60s if zero
	Logger     *slog.Logger  // resyncs, locks and lost gaps, nil is silent
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
	if !st.synced {
		st.synced, st.next = true, seq
	}
	if len(s.Payload) > 0 {
		d.place(st, seq, s.Payload, s.Time)
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

// emit queues a frame. The payload is copied, since body points into a buffer that is reused.
func (d *Decoder) emit(st *stream, body []byte, flags Flags) {
	op := opcode(body)
	if d.srv == nil {
		d.hunt(st, op, flags)
	}
	flags |= st.dir
	if flags&FromClient != 0 && !d.config.EmitClient {
		return
	}
	if d.config.KnownOnly && !op.Known() {
		return
	}
	d.queue = append(d.queue, Frame{
		Time:    st.at,
		Src:     st.key.src,
		Dst:     st.key.dst,
		IfIndex: st.key.ifIndex,
		Opcode:  op,
		Payload: d.keep(body[2:]),
		Flags:   flags,
	})
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

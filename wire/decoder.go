package wire

import (
	"bytes"
	"io"
	"iter"
	"log/slog"
	"net/netip"
	"time"
)

type Config struct {
	EmitClient bool          // keep the client side's frames, default false
	KnownOnly  bool          // keep only known opcodes, and hunt by them alone, default false
	ParseTLS   bool          // parse segments that start like TLS records, default false
	LockIdle   time.Duration // the silence that ends the lock, default 60s
	Logger     *slog.Logger  // resyncs, locks and lost gaps, default silent
}

// Decoder turns TCP segments into frames, and keeps them until taken. It is
// not safe for concurrent use.
type Decoder struct {
	c Config
	l *slog.Logger

	born    uint64          // streams made
	head    int             // index of the first unyielded frame
	streams map[key]*stream // streams by source and destination
	srv     *stream         // the locked server side, nil while hunting
	lockAt  time.Time       // the newest traffic on the lock
	queue   []Frame         // frames to yield
}

func NewDecoder(config Config) *Decoder {
	if config.LockIdle <= 0 {
		config.LockIdle = 60 * time.Second
	}
	log := config.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Decoder{c: config, l: log, streams: make(map[key]*stream)}
}

// Feed takes a segment's payload with no sequence number to place it by, so
// each direction's payloads must come in order.
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

// FeedSegment places a segment by its sequence number. Old bytes are dropped, and early ones
// held until the gap before them fills or is given up.
func (d *Decoder) FeedSegment(s Segment) {
	k := key{s.Src, s.Dst, s.IfIndex}
	if !d.admit(k, s.Time) {
		return
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
		st.closed = s.Time
	}
	if !st.synced {
		st.synced, st.next = true, seq
	}
	if len(s.Payload) > 0 {
		d.place(st, seq, s.Payload, s.Time)
	}
}

// Frames yields the frames found so far, oldest first, and forgets them.
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

// Decode reads r to its end, and yields frames as its segments complete them.
// At the end it flushes, so nothing waits on a gap that can no longer fill.
// A read error other than io.EOF is yielded last.
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

// emit copies the payload: the body is in a stream buffer or bundle plaintext, and both are reused.
func (d *Decoder) emit(st *stream, body []byte, flags Flags) {
	op := Opcode(body[0]) | Opcode(body[1])<<8
	flags |= d.lockFrame(st, op, flags)
	if flags&FromClient != 0 && !d.c.EmitClient {
		return
	}
	if d.c.KnownOnly && !op.Known() {
		return
	}
	d.queue = append(d.queue, Frame{
		Time:    st.at,
		Src:     st.key.src,
		Dst:     st.key.dst,
		IfIndex: st.key.ifIndex,
		Opcode:  op,
		Payload: bytes.Clone(body[2:]),
		Flags:   flags,
	})
}

package a2kit

import (
	"net/netip"
	"slices"
	"time"

	"github.com/nuriland/a2kit/capture"
	"github.com/nuriland/a2kit/wire"
)

const copyGap = 10 * time.Millisecond

// Connection is one TCP connection as a recording shows it, from its first packet to its last.
type Connection struct {
	Client, Server netip.AddrPort
	IfIndex        int // the adapter it was seen on, a packet seen on two is two connections
	Start, End     time.Time
	SYN, SYNACK    int
	FIN, RST       bool
	Sent, Received int
	Game           bool // the decoder read the game's messages on it
	Status         string
}

// Connections lists a recording's TCP connections in the order they began, with what became of each, and marks the game's.
func Connections(name string, cfg Config) ([]Connection, error) {
	f, err := capture.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return connections(f, cfg.decoder())
}

func connections(src wire.SegmentReader, d *wire.Decoder) ([]Connection, error) {
	var (
		l    = &ledger{SegmentReader: src, open: make(map[pair]*conn)}
		game = make(map[pair]bool)
	)
	for m, err := range New(d, l).Messages() {
		if err != nil {
			return nil, err
		}
		if m.Flags&wire.FromServer != 0 {
			game[pairOf(m.Src, m.Dst, m.IfIndex)] = true
		}
	}

	out := make([]Connection, len(l.conns))
	for i, c := range l.conns {
		c.Game, c.Status = game[pairOf(c.Client, c.Server, c.IfIndex)], c.status()
		out[i] = c.Connection
	}
	slices.SortStableFunc(out, func(x, y Connection) int { return x.Start.Compare(y.Start) })
	return out, nil
}

// ledger reads a recording's segments for the decoder, and tallies every connection they belong to.
type ledger struct {
	wire.SegmentReader

	open  map[pair]*conn // the connection a pair of endpoints is in
	conns []*conn        // every connection, in the order it began
}

// pair is the two ends of a connection and the adapter, the same whichever way a packet goes.
type pair struct {
	lo, hi  netip.AddrPort
	ifIndex int
}

func pairOf(a, b netip.AddrPort, ifIndex int) pair {
	if a.Compare(b) > 0 {
		a, b = b, a
	}
	return pair{a, b, ifIndex}
}

// header is what tells one segment from another: who sent it, its flags, its numbers and its length.
type header struct {
	src      netip.AddrPort
	flags    wire.TCPFlags
	seq, ack uint32
	n        int
}

func headerOf(s wire.Segment) header {
	return header{s.Src, s.Flags, s.Seq, s.Ack, len(s.Payload)}
}

func (c *conn) copied(s wire.Segment) bool {
	return headerOf(s) == c.last && s.Time.Sub(c.lastAt) < copyGap
}

// edge is the furthest byte one side has sent, so that a retransmit is not a send.
type edge struct {
	end  uint32
	seen bool
}

// advance takes a segment's sequence number and length, and returns how many of its bytes are new.
func (e *edge) advance(seq uint32, n int) int {
	end := seq + uint32(n)
	switch {
	case !e.seen:
		e.end, e.seen = end, true
		return n
	case int32(end-e.end) > 0:
		n = min(n, int(end-e.end))
		e.end = end
		return n
	}
	return 0
}

// conn is a Connection being read from.
type conn struct {
	Connection

	sent, received edge      // how far each side has sent
	acked          bool      // the client answered the SYN-ACK
	refused        bool      // the server reset before any SYN-ACK
	last           header    // the segment before, to tell a copy of it
	lastAt         time.Time // when it came
}

func (l *ledger) ReadSegment() (wire.Segment, error) {
	s, err := l.SegmentReader.ReadSegment()
	if err == nil {
		l.tally(s)
	}
	return s, err
}

// tally adds s to its connection, starting one when none is open, or at a SYN after a close, a reused port.
func (l *ledger) tally(s wire.Segment) {
	var (
		k   = pairOf(s.Src, s.Dst, s.IfIndex)
		c   = l.open[k]
		syn = s.Flags&wire.SYN != 0 && s.Flags&wire.ACK == 0
	)
	if c == nil || syn && (c.FIN || c.RST) {
		c = &conn{Connection: Connection{Client: s.Src, Server: s.Dst, IfIndex: s.IfIndex, Start: s.Time}}

		if s.Flags&wire.SYN != 0 && s.Flags&wire.ACK != 0 || !syn && s.Src.Port() < s.Dst.Port() {
			c.Client, c.Server = s.Dst, s.Src // caught from the server's side
		}
		l.open[k], l.conns = c, append(l.conns, c)
	}
	if c.copied(s) {
		return
	}

	c.last, c.lastAt, c.End = headerOf(s), s.Time, s.Time
	client := s.Src == c.Client

	switch {
	case syn && client:
		c.SYN++
	case s.Flags&wire.SYN != 0 && !client:
		c.SYNACK++
	case client && s.Flags&wire.ACK != 0 && c.SYNACK > 0:
		c.acked = true
	}
	if s.Flags&wire.FIN != 0 {
		c.FIN = true
	}
	if s.Flags&wire.RST != 0 {
		c.RST, c.refused = true, c.refused || !client && c.SYNACK == 0
	}
	if client {
		c.Sent += c.sent.advance(s.Seq, len(s.Payload))
	} else {
		c.Received += c.received.advance(s.Seq, len(s.Payload))
	}
}

func (c *conn) status() string {
	switch {
	case c.FIN:
		return "closed" // a FIN then a RST is how the client closes
	case c.SYN > 0 && c.SYNACK == 0 && c.refused:
		return "refused"
	case c.SYN > 0 && c.SYNACK == 0:
		return "no answer"
	case c.RST:
		return "reset"
	case c.SYN == 0 && c.SYNACK == 0:
		return "already open"
	case !c.acked:
		return "half open"
	}
	return "open"
}

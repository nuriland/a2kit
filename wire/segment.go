package wire

import (
	"net/netip"
	"time"
)

// Segment is one TCP segment, stripped to what a Decoder needs.
type Segment struct {
	Time     time.Time
	Src, Dst netip.AddrPort
	Flags    TCPFlags
	IfIndex  int
	Seq      uint32
	Payload  []byte // may alias the reader's buffer until its next read
}

// TCPFlags are the TCP header's flag bits.
type TCPFlags uint8

const (
	FIN TCPFlags = 1 << iota
	SYN
	RST
	PSH
	ACK
)

// SegmentReader is a capture. It reads segments until io.EOF.
type SegmentReader interface {
	ReadSegment() (Segment, error)
}

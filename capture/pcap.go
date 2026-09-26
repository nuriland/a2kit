package capture

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
	"time"
)

// Classic pcap is a 24-byte file header, then a 16-byte header per packet.
// The magic says the byte order, and micro or nanosecond timestamps.
const (
	pcapMicro = 0xA1B2C3D4
	pcapNano  = 0xA1B23C4D
	maxSnap   = 262144 // the most libpcap takes of one packet
)

var errTruncated = fmt.Errorf("truncated: %w", io.ErrUnexpectedEOF)

type classic struct {
	r        *bufio.Reader
	order    binary.ByteOrder
	head     [16]byte
	data     []byte
	tick     int64 // nanoseconds in a tick of a timestamp's fraction
	linkType int
}

func newClassic(r *bufio.Reader) (*classic, error) {
	var h [24]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, errNotCapture
	}
	p := &classic{r: r}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		switch order.Uint32(h[:]) {
		case pcapMicro:
			p.order, p.tick = order, 1000
		case pcapNano:
			p.order, p.tick = order, 1
		}
	}
	if p.order == nil {
		return nil, errNotCapture
	}
	p.linkType = int(p.order.Uint32(h[20:]) & 0x03FFFFFF) // the upper bits say other things
	return p, nil
}

func (p *classic) next() (packet, error) {
	if _, err := io.ReadFull(p.r, p.head[:]); err != nil {
		if err == io.EOF {
			return packet{}, io.EOF
		}
		return packet{}, errTruncated
	}
	sec := p.order.Uint32(p.head[0:])
	frac := p.order.Uint32(p.head[4:])
	n := p.order.Uint32(p.head[8:])
	orig := p.order.Uint32(p.head[12:])
	if n > maxSnap {
		return packet{}, fmt.Errorf("packet length %d exceeds %d", n, maxSnap)
	}
	p.data = slices.Grow(p.data[:0], int(n))[:n]
	if _, err := io.ReadFull(p.r, p.data); err != nil {
		return packet{}, errTruncated
	}
	return packet{
		time:     time.Unix(int64(sec), int64(frac)*p.tick),
		linkType: p.linkType,
		orig:     int(orig),
		data:     p.data,
	}, nil
}

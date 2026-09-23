package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"slices"
	"time"
)

// pcapng is a run of blocks: type | length | body | length. A section header
// sets the byte order of what follows, and each packet block names an
// interface described before it.
const (
	ngSection   = 0x0A0D0D0A
	ngInterface = 0x00000001
	ngObsolete  = 0x00000002 // the obsolete packet block
	ngSimple    = 0x00000003
	ngEnhanced  = 0x00000006
	ngByteOrder = 0x1A2B3C4D
	maxBlock    = 16 << 20
)

var (
	errNoSection = errors.New("pcapng: no section header")
	errShort     = errors.New("pcapng: short block")
	errNoIface   = errors.New("pcapng: packet on an undescribed interface")
)

type pcapng struct {
	r      *bufio.Reader
	order  binary.ByteOrder // nil until the first section header
	ifaces []iface
	block  []byte
}

// iface is what an interface description block says about its packets.
type iface struct {
	linkType int
	snapLen  int
	ticks    uint64 // timestamp ticks a second
	offset   int64  // seconds added to every timestamp
}

func (n *pcapng) next() (packet, error) {
	for {
		typ, body, err := n.readBlock()
		if err != nil {
			return packet{}, err
		}
		switch typ {
		case ngInterface:
			in, err := n.iface(body)
			if err != nil {
				return packet{}, err
			}
			n.ifaces = append(n.ifaces, in)
		case ngEnhanced:
			return n.packetBlock(body, false)
		case ngObsolete:
			return n.packetBlock(body, true)
		case ngSimple:
			return n.simpleBlock(body)
		}
	}
}

// readBlock returns the next block's type and body. A section header resets
// the byte order and the interfaces.
func (n *pcapng) readBlock() (typ uint32, body []byte, err error) {
	var h [8]byte
	if _, err := io.ReadFull(n.r, h[:]); err != nil {
		if err == io.EOF {
			return 0, nil, io.EOF
		}
		return 0, nil, errTruncated
	}

	section := binary.LittleEndian.Uint32(h[:]) == ngSection // the same either way round
	if section {
		magic, err := n.r.Peek(4)
		if err != nil {
			return 0, nil, errTruncated
		}
		switch {
		case binary.LittleEndian.Uint32(magic) == ngByteOrder:
			n.order = binary.LittleEndian
		case binary.BigEndian.Uint32(magic) == ngByteOrder:
			n.order = binary.BigEndian
		default:
			return 0, nil, errors.New("pcapng: bad byte-order magic")
		}
		n.ifaces = n.ifaces[:0]
	}
	if n.order == nil {
		return 0, nil, errNoSection
	}

	typ = n.order.Uint32(h[0:])
	size := n.order.Uint32(h[4:])
	if size < 12 || size%4 != 0 || size > maxBlock {
		return 0, nil, fmt.Errorf("pcapng: bad block length %d", size)
	}

	n.block = slices.Grow(n.block[:0], int(size)-8)[:size-8]
	if _, err := io.ReadFull(n.r, n.block); err != nil {
		return 0, nil, errTruncated
	}

	body = n.block[:len(n.block)-4]
	if n.order.Uint32(n.block[len(body):]) != size {
		return 0, nil, errors.New("pcapng: block lengths disagree")
	}
	if section && (len(body) < 16 || n.order.Uint16(body[4:]) != 1) {
		return 0, nil, errors.New("pcapng: unsupported version")
	}
	return typ, body, nil
}

// iface keeps the timestamp resolution and offset, and skips other options.
func (n *pcapng) iface(b []byte) (iface, error) {
	if len(b) < 8 {
		return iface{}, errShort
	}

	in := iface{
		linkType: int(n.order.Uint16(b[0:])),
		snapLen:  int(n.order.Uint32(b[4:])),
		ticks:    1e6,
	}
	for opts := b[8:]; len(opts) >= 4; {
		code := n.order.Uint16(opts[0:])
		size := int(n.order.Uint16(opts[2:]))
		if code == 0 {
			break // the end of the options
		}
		if 4+size > len(opts) {
			return iface{}, errors.New("pcapng: option past end of block")
		}
		v := opts[4 : 4+size]
		switch {
		case code == 9 && size == 1: // if_tsresol
			ticks, ok := resolution(v[0])
			if !ok {
				return iface{}, fmt.Errorf("pcapng: bad timestamp resolution %#x", v[0])
			}
			in.ticks = ticks
		case code == 14 && size == 8: // if_tsoffset
			in.offset = int64(n.order.Uint64(v))
		}
		opts = opts[min(len(opts), 4+(size+3)&^3):] // values are padded to 32 bits
	}
	return in, nil
}

// resolution turns if_tsresol into ticks a second.
//
//	a tick is 10^-v seconds, or 2^-(v&0x7F) with the high bit set
func resolution(v byte) (uint64, bool) {
	if v&0x80 != 0 {
		if v&0x7F > 63 {
			return 0, false
		}
		return 1 << (v & 0x7F), true
	}
	if v > 19 {
		return 0, false
	}
	ticks := uint64(1)
	for range v {
		ticks *= 10
	}
	return ticks, true
}

// time converts ticks to a time, exact to the nanosecond.
func (in iface) time(hi, lo uint32) time.Time {
	var (
		t         = uint64(hi)<<32 | uint64(lo)
		sec, frac = t / in.ticks, t % in.ticks
		h, l      = bits.Mul64(frac, 1e9)
		ns, _     = bits.Div64(h, l, in.ticks) // frac < ticks, so the quotient fits
	)
	return time.Unix(int64(sec)+in.offset, int64(ns))
}

// packetBlock reads an enhanced packet block, or an obsolete one, which differs only in a
// shorter interface id.
func (n *pcapng) packetBlock(b []byte, obsolete bool) (packet, error) {
	if len(b) < 20 {
		return packet{}, errShort
	}

	id := n.order.Uint32(b[0:])
	if obsolete {
		id = uint32(n.order.Uint16(b[0:]))
	}
	if id >= uint32(len(n.ifaces)) {
		return packet{}, errNoIface
	}
	size := n.order.Uint32(b[12:])
	if size > uint32(len(b)-20) {
		return packet{}, errors.New("pcapng: packet past end of block")
	}

	in := n.ifaces[id]
	return packet{
		time:     in.time(n.order.Uint32(b[4:]), n.order.Uint32(b[8:])),
		linkType: in.linkType,
		ifIndex:  int(id),
		data:     b[20 : 20+size],
	}, nil
}

// simpleBlock reads a simple packet block. It belongs to the first interface and has no
// timestamp, so it gets the epoch, as libpcap gives it.
func (n *pcapng) simpleBlock(b []byte) (packet, error) {
	if len(b) < 4 {
		return packet{}, errShort
	}
	if len(n.ifaces) == 0 {
		return packet{}, errNoIface
	}

	in := n.ifaces[0]
	size := min(int(n.order.Uint32(b[0:])), len(b)-4)
	if in.snapLen > 0 {
		size = min(size, in.snapLen)
	}
	return packet{time: time.Unix(0, 0), linkType: in.linkType, data: b[4 : 4+size]}, nil
}

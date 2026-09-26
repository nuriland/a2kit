package wiretest

import (
	"encoding/binary"
	"time"
)

// A Pcap builds a classic pcap file in memory.
type Pcap struct {
	order binary.AppendByteOrder
	nano  bool
	b     []byte
}

// NewPcap starts a pcap file, version 2.4, of the given link type. Its
// timestamps are in nanoseconds if nano is set, microseconds if not.
func NewPcap(order binary.AppendByteOrder, nano bool, linkType int) *Pcap {
	magic := uint32(0xA1B2C3D4)
	if nano {
		magic = 0xA1B23C4D
	}
	p := &Pcap{order: order, nano: nano}
	p.b = order.AppendUint32(p.b, magic)
	p.b = order.AppendUint16(p.b, 2)
	p.b = order.AppendUint16(p.b, 4)
	p.b = order.AppendUint32(p.b, 0) // time zone
	p.b = order.AppendUint32(p.b, 0) // significant figures
	p.b = order.AppendUint32(p.b, 65535)
	p.b = order.AppendUint32(p.b, uint32(linkType))
	return p
}

func (p *Pcap) Add(t time.Time, data []byte) { p.AddCut(t, data, len(data)) }

// AddCut adds the first n bytes of data, as a capture with a snap length of n would.
func (p *Pcap) AddCut(t time.Time, data []byte, n int) {
	frac := t.Nanosecond() / 1000
	if p.nano {
		frac = t.Nanosecond()
	}
	p.b = p.order.AppendUint32(p.b, uint32(t.Unix()))
	p.b = p.order.AppendUint32(p.b, uint32(frac))
	p.b = p.order.AppendUint32(p.b, uint32(n))
	p.b = p.order.AppendUint32(p.b, uint32(len(data)))
	p.b = append(p.b, data[:n]...)
}

func (p *Pcap) Bytes() []byte { return p.b }

// A Pcapng builds a pcapng file of one section in memory.
type Pcapng struct {
	order  binary.AppendByteOrder
	ifaces []resolution
	b      []byte
}

// A resolution is an interface's clock, as Interface takes it.
type resolution struct {
	res    byte
	offset int64
}

// NewPcapng starts a pcapng file with a section header.
func NewPcapng(order binary.AppendByteOrder) *Pcapng {
	p := &Pcapng{order: order}
	var body []byte
	body = order.AppendUint32(body, 0x1A2B3C4D) // byte-order magic
	body = order.AppendUint16(body, 1)
	body = order.AppendUint16(body, 0)
	body = order.AppendUint64(body, ^uint64(0)) // section length: not said
	p.Block(0x0A0D0D0A, body)
	return p
}

// Interface describes an interface and returns its id. Its timestamps count
// from offset seconds, in ticks of 10^-res seconds, or of 2^-(res&0x7F) if
// res has its high bit set; a decimal res goes up to 9. The pcapng default
// is res 6, offset 0.
func (p *Pcapng) Interface(linkType int, res byte, offset int64) int {
	var body []byte
	body = p.order.AppendUint16(body, uint16(linkType))
	body = p.order.AppendUint16(body, 0)
	body = p.order.AppendUint32(body, 0) // no snaplen
	if res != 6 {
		body = p.option(body, 9, []byte{res})
	}
	if offset != 0 {
		body = p.option(body, 14, p.order.AppendUint64(nil, uint64(offset)))
	}
	body = p.option(body, 0, nil) // the end of the options
	p.Block(1, body)
	p.ifaces = append(p.ifaces, resolution{res, offset})
	return len(p.ifaces) - 1
}

// Packet adds an enhanced packet block on interface id.
func (p *Pcapng) Packet(id int, t time.Time, data []byte) { p.PacketCut(id, t, data, len(data)) }

// PacketCut adds the first n bytes of data, as a capture with a snap length of n would.
func (p *Pcapng) PacketCut(id int, t time.Time, data []byte, n int) {
	ticks := p.ifaces[id].ticks(t)
	var body []byte
	body = p.order.AppendUint32(body, uint32(id))
	body = p.order.AppendUint32(body, uint32(ticks>>32))
	body = p.order.AppendUint32(body, uint32(ticks))
	body = p.order.AppendUint32(body, uint32(n))
	body = p.order.AppendUint32(body, uint32(len(data)))
	body = append(body, data[:n]...)
	p.Block(6, body)
}

// Simple adds a simple packet block: interface 0, and no timestamp.
func (p *Pcapng) Simple(data []byte) {
	body := p.order.AppendUint32(nil, uint32(len(data)))
	p.Block(3, append(body, data...))
}

// Block adds a block of any type, its body padded to 32 bits.
func (p *Pcapng) Block(typ uint32, body []byte) {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	n := uint32(12 + len(body))
	p.b = p.order.AppendUint32(p.b, typ)
	p.b = p.order.AppendUint32(p.b, n)
	p.b = append(p.b, body...)
	p.b = p.order.AppendUint32(p.b, n)
}

func (p *Pcapng) Bytes() []byte { return p.b }

func (p *Pcapng) option(b []byte, code uint16, value []byte) []byte {
	b = p.order.AppendUint16(b, code)
	b = p.order.AppendUint16(b, uint16(len(value)))
	b = append(b, value...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func (r resolution) ticks(t time.Time) uint64 {
	sec := uint64(t.Unix() - r.offset)
	ns := uint64(t.Nanosecond())
	if r.res&0x80 != 0 {
		k := r.res & 0x7F
		return sec<<k + ns<<k/1e9
	}
	scale := uint64(1)
	for range 9 - int(r.res) {
		scale *= 10
	}
	per := 1e9 / scale // ticks a second
	return sec*per + ns/scale
}

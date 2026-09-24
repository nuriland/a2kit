package game

import (
	"encoding/binary"
	"math"
	"time"
	"unicode/utf8"

	"github.com/nuriland/a2kit/wire"
)

// Event is what one frame means, like a hit, a cast, a spawn, a death, a position update, or a clock tick
type Event interface{ event() }

// The opcodes Parse reads, in wire order.
//
// @TODO: add documentation for all available frames
const (
	opTick    wire.Opcode = 0x3600 // 00 36
	opPing    wire.Opcode = 0x3603 // 03 36
	opZone    wire.Opcode = 0x3623 // 23 36
	opSelf    wire.Opcode = 0x3633 // 33 36
	opSpawn   wire.Opcode = 0x3641 // 41 36
	opDeath   wire.Opcode = 0x3642 // 42 36
	opPlayer  wire.Opcode = 0x3645 // 45 36
	opMoveA   wire.Opcode = 0x371A // 1A 37
	opMoveB   wire.Opcode = 0x371B // 1B 37
	opMoveC   wire.Opcode = 0x371C // 1C 37
	opCast    wire.Opcode = 0x3802 // 02 38
	opHit     wire.Opcode = 0x3804 // 04 38
	opCastEnd wire.Opcode = 0x3806 // 06 38
	opOwner   wire.Opcode = 0x8D04 // 04 8D
)

// dotnetEpoch is 0001-01-01 UTC in Unix milliseconds, the epoch of the client's clock
const dotnetEpoch = -62135596800000

// Parse reads what f means. It reports false for a frame it does not know
func Parse(f wire.Frame) (Event, bool) {
	if f.Flags&wire.FromClient != 0 {
		return nil, false
	}
	var (
		e Event = nil
		r       = reader{p: f.Payload}
	)
	switch f.Opcode {
	case opHit:
		e = r.hit()
	case opSpawn:
		e = r.spawn()
	case opDeath:
		e = r.death()
	case opOwner:
		e = r.owner()
	case opPlayer, opSelf:
		e = r.player(f.Opcode == opSelf)
	case opCast:
		e = r.cast()
	case opCastEnd:
		e = r.castEnd()
	case opMoveA, opMoveB, opMoveC:
		e = r.move(f.Opcode == opMoveA)
	case opTick:
		e = r.tick()
	case opPing:
		e = r.ping()
	case opZone:
		e = r.zone()
	default:
		return nil, false
	}
	if r.bad || e == nil {
		return nil, false
	}
	return e, true
}

func (r *reader) hit() Event {
	var (
		h  = Hit{Target: r.varint()}
		sw = r.varint()
	)

	r.varint()
	h.Actor = r.varint()
	h.Skill = r.u32()
	r.skip(1)
	h.Type = r.small()
	switch sw & 0xF {
	case 4:
	case 6:
		h.Mods = r.u8()
		r.skip(1)
		h.Direction = r.u8()
	default:
		return nil // a form no fixture has
	}
	r.skip(4)
	seq := r.u32()
	h.Scalar = r.varint()
	h.Damage = r.varint()
	if sw&0x20 != 0 {
		n := r.varint()
		if n > uint32(len(r.p)-r.i) {
			return nil
		}
		h.Extra = make([]uint32, n)
		for i := range h.Extra {
			h.Extra[i] = r.varint()
		}
	}
	if seq > 255 || r.u8() != byte(seq) || r.u8() != 0 || !r.done() {
		return nil
	}
	return h
}

func (r *reader) spawn() Event {
	s := Spawn{Entity: r.varint(), Mask: r.u32()}
	if r.u8()&1 != 0 {
		return nil // a name follows, which no fixture has, @TODO: add support for this
	}
	s.NPC = r.u32()
	r.skip(2)
	s.X, s.Y, s.Z = r.f32(), r.f32(), r.f32()
	return s
}

func (r *reader) death() Event {
	d := Death{Entity: r.varint()}
	if r.varint() != 0 {
		return nil
	}
	d.Flag = r.small()
	if !r.done() {
		return nil
	}
	return d
}

func (r *reader) owner() Event {
	o := Owner{Entity: r.varint(), Skill: r.u32(), Actor: r.varint()}
	r.varint()
	o.Name = r.name()
	return o
}

func (r *reader) player(self bool) Event {
	p := Player{Entity: r.varint(), Self: self}
	r.skip(4)
	if r.u8()&1 != 0 {
		p.Name = r.name()
	}
	return p
}

func (r *reader) cast() Event {
	c := Cast{Actor: r.varint()}
	r.skip(1)
	c.Skill = r.u32()
	r.skip(2)
	c.Target = r.varint()
	r.skip(4)
	c.X, c.Y, c.Z = r.f32(), r.f32(), r.f32()
	return c
}

func (r *reader) castEnd() Event {
	c := CastEnd{Actor: r.varint(), Skill: r.u32()}
	r.skip(2)
	if !r.done() {
		return nil
	}
	return c
}

// move reads 1A 37, or with a false arg, 1B 37 and 1C 37, whose prefix byte may add one more
func (r *reader) move(a bool) Event {
	m := Move{Entity: r.varint()}
	if a {
		r.skip(2)
	} else if r.u8()&1 != 0 {
		r.skip(1)
	}
	m.X, m.Y, m.Z = r.f32(), r.f32(), r.f32()
	return m
}

func (r *reader) tick() Event {
	t := Tick{Server: unixMilli(int64(r.u64()))}
	if !r.done() {
		return nil
	}
	return t
}

func (r *reader) ping() Event {
	r.skip(2)
	p := Ping{Client: unixMilli(int64(r.u64()) + dotnetEpoch), Server: unixMilli(int64(r.u64()))}
	if !r.done() {
		return nil
	}
	return p
}

func (r *reader) zone() Event {
	if r.varint() != 0 {
		return nil
	}
	r.skip(5)
	return Zone{X: r.f32(), Y: r.f32(), Z: r.f32()}
}

func unixMilli(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

// reader reads a payload front to back. A read past the end sets bad and returns zero
//
// @TODO: cleanup the whole reader
type reader struct {
	p   []byte
	i   int
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.i+n > len(r.p) {
		r.bad, r.i = true, len(r.p)
		return nil
	}
	b := r.p[r.i : r.i+n]
	r.i += n
	return b
}

func (r *reader) skip(n int) { r.take(n) }
func (r *reader) done() bool { return r.i == len(r.p) }

func (r *reader) u8() byte {
	if b := r.take(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *reader) u32() uint32 {
	if b := r.take(4); b != nil {
		return binary.LittleEndian.Uint32(b)
	}
	return 0
}

func (r *reader) u64() uint64 {
	if b := r.take(8); b != nil {
		return binary.LittleEndian.Uint64(b)
	}
	return 0
}

func (r *reader) f32() float32 { return math.Float32frombits(r.u32()) }

// varint reads a LEB128 value of at most five bytes.
func (r *reader) varint() uint32 {
	v, n := binary.Uvarint(r.p[r.i:])
	if n <= 0 || n > 5 || v > math.MaxUint32 {
		r.bad, r.i = true, len(r.p)
		return 0
	}
	r.i += n
	return uint32(v)
}

// small reads a varint that has to fit a byte.
func (r *reader) small() byte {
	v := r.varint()
	if v > 255 {
		r.bad = true
	}
	return byte(v)
}

// name reads a length byte and that much UTF-8.
func (r *reader) name() string {
	b := r.take(int(r.u8()))
	if !utf8.Valid(b) {
		r.bad = true
	}
	return string(b)
}

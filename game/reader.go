package game

import (
	"encoding/binary"
	"math"
	"unicode/utf8"
)

// reader reads a payload front to back.
//
// The first read that fails sets bad and holds i where it stopped. Every read after returns zero.
type reader struct {
	p   []byte
	i   int
	bad bool
}

func (r *reader) left() int { return len(r.p) - r.i }

// end fails if bytes remain.
func (r *reader) end() {
	if r.i != len(r.p) {
		r.bad = true
	}
}

// take reads n bytes and returns them.
func (r *reader) take(n int) []byte {
	if r.bad || n > r.left() {
		r.bad = true
		return nil
	}
	b := r.p[r.i : r.i+n]
	r.i += n
	return b
}

// skip reads n bytes and discards them.
func (r *reader) skip(n int) { r.take(n) }

// u8 reads a single byte.
func (r *reader) u8() byte {
	if b := r.take(1); b != nil {
		return b[0]
	}
	return 0
}

// u32 reads a 32-bit unsigned integer.
func (r *reader) u32() uint32 {
	if b := r.take(4); b != nil {
		return binary.LittleEndian.Uint32(b)
	}
	return 0
}

// u64 reads a 64-bit unsigned integer.
func (r *reader) u64() uint64 {
	if b := r.take(8); b != nil {
		return binary.LittleEndian.Uint64(b)
	}
	return 0
}

// f32 reads a 32-bit floating point number.
func (r *reader) f32() float32 { return math.Float32frombits(r.u32()) }

// pos reads a 3D position.
func (r *reader) pos() Pos { return Pos{r.f32(), r.f32(), r.f32()} }

// varint reads a LEB128 value of at most five bytes.
func (r *reader) varint() uint32 {
	if r.bad {
		return 0
	}
	v, n := binary.Uvarint(r.p[r.i:])
	if n <= 0 || n > 5 || v > math.MaxUint32 {
		r.bad = true
		return 0
	}
	r.i += n
	return uint32(v)
}

// entity reads an entity id.
func (r *reader) entity() Entity { return Entity(r.varint()) }

// skill reads a skill id.
func (r *reader) skill() Skill { return Skill(r.u32()) }

// npc reads an NPC id.
func (r *reader) npc() NPC { return NPC(r.u32()) }

// small reads a varint that has to fit in a byte.
func (r *reader) small() byte {
	v := r.varint()
	if v > 255 {
		r.bad = true
	}
	return byte(v)
}

// name reads a length byte and that many UTF-8 bytes.
func (r *reader) name() string {
	b := r.take(int(r.u8()))
	if !utf8.Valid(b) {
		r.bad = true
	}
	return string(b)
}

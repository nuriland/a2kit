package game

import (
	"fmt"
	"time"

	"github.com/nuriland/a2kit/wire"
)

// Event is what one frame means, like a hit, a cast, a spawn, a death, a position update, or a clock tick.
type Event interface{ event() }

// dotnetEpoch is 0001-01-01 UTC in Unix milliseconds, the epoch of the client's clock.
const dotnetEpoch = -62135596800000

// Parse reads what f means, or fails with ErrUnread or ErrLayout.
func Parse(f wire.Frame) (Event, error) {
	if f.Flags&wire.FromClient != 0 {
		return nil, ErrUnread
	}
	o := opcodes[f.Opcode]
	if o.read == nil {
		return nil, ErrUnread
	}
	r := reader{p: f.Payload}
	e := o.read(&r)
	if r.bad {
		return nil, fmt.Errorf("%w at byte %d of %d", ErrLayout, r.i, len(r.p))
	}
	if e == nil {
		return nil, ErrUnread
	}
	return e, nil
}

// hit parses a hit event from a frame
func (r *reader) hit() Event {
	var (
		h  = Hit{Target: r.entity()}
		sw = r.varint()
	)
	r.varint() // 0 so far
	h.Actor = r.entity()
	h.Skill = r.skill()
	r.skip(1) // the actor's hit count
	h.Type = r.small()
	switch sw & 0xF {
	case 4:
	case 6:
		h.Mods = r.u8()
		r.skip(1) // 00
		h.Direction = r.u8()
	default:
		return nil // a form no fixture has
	}
	r.skip(4) // varies with the skill, not a float
	seq := r.u32()
	h.Scalar = r.varint()
	h.Damage = r.varint()
	if sw&0x20 != 0 {
		n := r.varint()
		if n > uint32(r.left()) {
			r.bad = true
			return nil
		}
		h.Extra = make([]uint32, n)
		for i := range h.Extra {
			h.Extra[i] = r.varint()
		}
	}
	if seq > 255 || r.u8() != byte(seq) || r.u8() != 0 {
		r.bad = true
	}
	r.end()
	return h
}

// spawn parses a spawn event from a frame
func (r *reader) spawn() Event {
	s := Spawn{Entity: r.entity(), Mask: r.u32()}
	if r.u8()&1 != 0 {
		return nil // a name follows; no fixture
	}
	s.NPC = r.npc()
	r.skip(2)
	s.Pos = r.pos()
	return s
}

// death parses a death event from a frame
func (r *reader) death() Event {
	d := Death{Entity: r.entity()}
	if r.varint() != 0 {
		r.bad = true
	}
	d.Flag = r.small()
	r.end()
	return d
}

// owner parses an owner event from a frame
func (r *reader) owner() Event {
	o := Owner{Entity: r.entity(), Skill: r.skill(), Actor: r.entity()}
	r.varint() // 504 so far
	o.Name = r.name()
	return o
}

// player parses a player event from a frame
func (r *reader) player() Event { return r.character(false) }

// self parses a self event from a frame
func (r *reader) self() Event { return r.character(true) }

// character parses a character event from a frame
func (r *reader) character(self bool) Event {
	p := Player{Entity: r.entity(), Self: self}
	r.skip(4) // a mask, like Spawn's
	if r.u8()&1 != 0 {
		p.Name = r.name()
	}
	return p
}

// cast parses a cast event from a frame
func (r *reader) cast() Event {
	c := Cast{Actor: r.entity()}
	r.skip(1)
	c.Skill = r.skill()
	r.skip(2)
	c.Target = r.entity()
	if r.left() < 16 {
		return nil // the short self-cast form, without a position
	}
	r.skip(4)
	c.Pos = r.pos()
	return c
}

// castEnd parses a cast end event from a frame
func (r *reader) castEnd() Event {
	c := CastEnd{Actor: r.entity(), Skill: r.skill()}
	r.skip(2)
	r.end()
	return c
}

// moveA parses a move event from a frame
func (r *reader) moveA() Event {
	m := Move{Entity: r.entity()}
	r.skip(2)
	m.Pos = r.pos()
	return m
}

// moveB parses a move event from a frame
func (r *reader) moveB() Event {
	m := Move{Entity: r.entity()}
	if r.u8()&1 != 0 {
		r.skip(1)
	}
	m.Pos = r.pos()
	return m
}

// tick parses a tick event from a frame
func (r *reader) tick() Event {
	t := Tick{Server: unixMilli(int64(r.u64()))}
	r.end()
	return t
}

// ping parses a ping event from a frame
func (r *reader) ping() Event {
	r.skip(2) // 00 00
	p := Ping{Client: unixMilli(int64(r.u64()) + dotnetEpoch), Server: unixMilli(int64(r.u64()))}
	r.end()
	return p
}

// zone parses a zone event from a frame
func (r *reader) zone() Event {
	if r.varint() != 0 {
		r.bad = true
	}
	r.skip(5)
	return Zone{Pos: r.pos()}
}

// unixMilli converts a Unix milliseconds timestamp to a time.Time in UTC.
func unixMilli(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

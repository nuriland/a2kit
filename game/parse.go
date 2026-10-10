package game

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/nuriland/a2kit/wire"
)

// Event is what one frame means, like a hit, a cast, a spawn, a death, a position update, or a clock tick.
type Event interface{ event() }

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
func hit(r *reader) Event {
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
func spawn(r *reader) Event {
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
func death(r *reader) Event {
	d := Death{Entity: r.entity()}
	if r.varint() != 0 {
		r.bad = true
	}
	d.Flag = r.small()
	r.end()
	return d
}

// owner parses an owner event from a frame
func owner(r *reader) Event {
	o := Owner{Entity: r.entity(), Skill: r.skill(), Actor: r.entity()}
	r.varint() // 504 so far
	o.Name = r.name()
	return o
}

// player parses a player event from a frame
func player(r *reader) Event { return character(r, false) }

// self parses a self event from a frame
func self(r *reader) Event { return character(r, true) }

// character parses a character event from a frame
func character(r *reader, self bool) Event {
	p := Player{Entity: r.entity(), Self: self}
	r.skip(4) // a mask, like Spawn's
	if r.u8()&1 != 0 {
		p.Name = r.name()
	}
	return p
}

// cast parses a cast event from a frame
func cast(r *reader) Event {
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
func castEnd(r *reader) Event {
	c := CastEnd{Actor: r.entity(), Skill: r.skill()}
	r.skip(2)
	r.end()
	return c
}

// moveA parses a move event from a frame
func moveA(r *reader) Event {
	m := Move{Entity: r.entity()}
	r.skip(2)
	m.Pos = r.pos()
	return m
}

// moveB parses a move event from a frame
func moveB(r *reader) Event {
	m := Move{Entity: r.entity()}
	if r.u8()&1 != 0 {
		r.skip(1)
	}
	m.Pos = r.pos()
	return m
}

// tick parses a tick event from a frame
func tick(r *reader) Event {
	t := Tick{Server: unixMilli(int64(r.u64()))}
	r.end()
	return t
}

// ping parses a ping event from a frame
func ping(r *reader) Event {
	r.skip(2) // 00 00
	p := Ping{Client: r.u64(), Server: unixMilli(int64(r.u64()))}
	r.end()
	return p
}

// zone parses a zone event from a frame
func zone(r *reader) Event {
	if r.varint() != 0 {
		r.bad = true
	}
	r.skip(5)
	return Zone{Pos: r.pos()}
}

// nameCheck parses a name check event from a frame
func nameCheck(r *reader) Event {
	n := NameCheck{Code: r.u16(), Name: r.name()}
	if r.u8() != 1 { // unsure what 01 means here yet, the race, class, gender, character slot or server doesn't affect this value
		r.bad = true
	}
	r.end()
	n.Taken = n.Code != 0
	return n
}

// servers parses the lobby's server list from a frame
func servers(r *reader) Event {
	if r.u16() != 0 {
		r.bad = true
	}
	var (
		s    = Servers{List: make([]Server, r.u8())}
		mask byte
		load bool
	)
	for i := range s.List {
		v := Server{ID: r.u16(), Faction: r.u8()}
		if r.u16() != v.ID || r.u16() != 0 {
			r.bad = true // the ID twice, then 00 00
		}

		v.Name = r.name()
		v.Mask = groupBits(r, i, len(s.List), &mask)
		v.Status = r.u8()
		if i == 0 {
			load = bytes.HasSuffix(r.peek(4), []byte{0x50, 0x01, 0x00})
		}
		if load {
			v.Load = r.u8()
		} else {
			v.Capacity = r.u16()
			v.Players = r.u32()
		}
		r.skip(3)

		s.List[i] = v
	}
	if r.u16() != 0x0101 {
		r.bad = true // 01 01 so far
	}
	r.end()

	return s
}

// redirect parses the lobby's hand off to a world server from a frame
func redirect(r *reader) Event {
	if r.u16() != 0 {
		r.bad = true
	}
	d := Redirect{Server: r.u16(), Host: r.name(), Port: r.u16()}
	if d.Host == "" {
		r.bad = true
	}
	r.end()
	return d
}

// join parses the server the client picked in the lobby from a frame
func join(r *reader) Event {
	if r.u16() != 0 || r.u8() != 0 {
		r.bad = true // 00 00 00 so far
	}
	j := Join{Server: r.u16()}
	if j.Server == 0 {
		r.bad = true
	}
	r.end()
	return j
}

// account parses who logged in to the lobby from a frame
func account(r *reader) Event {
	if r.u16() != 0 || r.u8() != 0 {
		r.bad = true
	}
	var a Account
	a.Session[0] = r.name()

	r.skip(3) // 01 00 00 so far

	// The account's number, then the other GUID
	id, session, ok := strings.Cut(r.name(), ":")
	if !ok {
		r.bad = true
	}
	a.ID, a.Session[1] = id, session
	a.Server = r.u16()
	a.Faction = r.u8() // 01 on a Light server, 02 on a Dark one so far

	// What follows is nine bytes that hold the Server again. In older captures four zeros come before it, and 03 09 03 after,
	// in the one from 10 October 2026 six zeros come before it, and a bare 03 after.
	t := r.take(9)
	if t != nil && binary.LittleEndian.Uint16(t[4:]) != a.Server && binary.LittleEndian.Uint16(t[6:]) != a.Server {
		r.bad = true
	}
	r.end()

	return a
}

// characters parses the account's characters from a frame
func characters(r *reader) Event {
	if r.u16() != 0 {
		r.bad = true
	}
	var (
		c    = Characters{List: make([]Character, r.u8())}
		mask byte
	)
	for i := range c.List {
		ch := Character{Server: r.u16(), Name: r.name(), Level: r.u32(), Exp: r.u32()}

		if r.u32() != 0 || ch.Server == 0 || len(ch.Name) > 0 && ch.Name[0] < 0x20 {
			r.bad = true // a check on the layout
		}

		ch.Code = r.u32()
		ch.Flags = r.u8()
		ch.Time = unixMilli(int64(r.u64()))

		r.skip(8) // 0 so far

		ch.Mask = groupBits(r, i, len(c.List), &mask)
		c.List[i] = ch
	}
	if r.u16() != 0x0101 {
		r.bad = true // 01 01 so far
	}
	r.end()

	return c
}

// groupBits returns the two bits that entry i of a list of n has in its group's mask.
//
// The lists in Servers and Characters split their entries into groups of four,
// and the first entry of each group carries one mask byte for the whole group
func groupBits(r *reader, i, n int, mask *byte) byte {
	if i%4 == 0 {
		*mask = r.u8()
		if left := n - i; left < 4 && *mask>>(2*left) != 0 {
			r.bad = true // bits for entries past the end
		}
	}
	return *mask >> (2 * (i % 4)) & 3
}

// lobbyPing parses the lobby's answer to a ping from a frame
func lobbyPing(r *reader) Event {
	if r.u16() != 0 {
		r.bad = true
	}
	p := LobbyPing{Client: r.u64(), Server: unixMilli(int64(r.u64()))}
	r.end()
	return p
}

// unixMilli converts a Unix milliseconds timestamp to a time.Time in UTC.
func unixMilli(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

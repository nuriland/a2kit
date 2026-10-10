package game

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/bits"
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
		h        = Hit{Target: r.entity()}
		sw       = r.varint()
		noDamage bool
	)
	r.varint() // 0 so far
	h.Actor = r.entity()
	h.Skill = r.skill()
	r.skip(1) // the actor's hit count
	h.Type = r.small()
	switch sw & 0xF {
	case 0:
		noDamage = true // a hit that deals none: Damage stays 0, and its varint is not sent
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
	if !noDamage {
		h.Damage = r.varint()
	}
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

// spawn parses a spawn event from a frame.
//
// A mask of two bytes comes before the flag since the game's patch of October 2026, and four bytes
// came before it. The NPC's id is at most three bytes, so its fourth is 00 in the layout that is
// right, and the one that is wrong finds a byte there that is not.
func spawn(r *reader) Event {
	s := Spawn{Entity: r.entity()}
	if p := r.peek(9); p != nil && p[6] == 0 && p[8] != 0 {
		s.Mask = uint32(r.u16())
	} else {
		s.Mask = r.u32()
	}
	if r.u8()&1 != 0 {
		return nil // a name follows; no fixture
	}
	s.NPC = r.npc()
	r.skip(2) // 00 02 so far, 08 02 twice
	s.Pos = r.pos()
	return s
}

// spawnStatic parses 34 36, the spawn of an entity that never moved or died in the recording, from a frame
func spawnStatic(r *reader) Event {
	s := Spawn{Entity: r.entity(), Mask: uint32(r.u16())}
	s.NPC = r.npc()
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
	c.Angle = r.f32()
	if r.left() >= 12 {
		c.Pos = r.pos()
	}
	r.varint() // 10000 so far
	if r.u8() != 1 {
		r.bad = true
	}
	c.Duration = r.varint()
	r.end()
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

// turn parses a lighter movement update, with no position, from a frame.
//
// The flag's low four bits each say that one more byte follows it, which of them it is not
// understood. Then two u16 headings, and a trailing 01 unless the flag's bit 0 is set.
func turn(r *reader) Event {
	t := Turn{Entity: r.entity()}
	flag := r.u8()
	r.skip(bits.OnesCount8(flag & 0x0F))
	t.Heading = r.u16()
	t.Heading2 = r.u16()
	if flag&1 == 0 && r.u8() != 1 {
		r.bad = true // 01 so far
	}
	r.end()
	return t
}

// headingWithPos parses 28 37 and 29 37's entity, position and heading from a frame
func headingWithPos(r *reader) Event {
	h := Heading{Entity: r.entity()}
	r.skip(1) // 04 on 28 37, 02 on 29 37, likely redundant with the opcode
	h.Pos = r.pos()
	return heading(r, h)
}

// headingOnly parses 2A 37's entity and heading from a frame, with no position
func headingOnly(r *reader) Event {
	h := Heading{Entity: r.entity()}
	if n := r.left() - 15; n >= 0 {
		r.skip(n) // not understood; its length varies
	} else {
		r.bad = true
	}
	return heading(r, h)
}

// heading reads the 15 bytes 28 37, 29 37 and 2A 37 end with: two headings, a speed, a changing
// u16 not understood, and a trailing 01.
func heading(r *reader, h Heading) Event {
	h.Heading1 = r.f32()
	h.Heading2 = r.f32()
	h.Speed = r.f32()
	r.skip(2) // changes often, not understood
	if r.u8() != 1 {
		r.bad = true // 01 so far
	}
	r.end()
	return h
}

// stats parses an entity's attributes from a frame: a mask whose bit 0 says a group of u32 values
// follows, and bit 1 a group of u64 ones, each a count and then an id and a value that many times.
func stats(r *reader) Event {
	s := Stats{Entity: r.entity()}
	mask := r.u8()
	if mask == 0 || mask&^3 != 0 {
		r.bad = true
		return nil
	}
	for bit, width := range [...]int{4, 8} {
		if mask>>bit&1 == 0 {
			continue
		}
		n := int(r.u8())
		if n*(1+width) > r.left() {
			r.bad = true
			return nil
		}
		for range n {
			id, v := r.u8(), r.take(width)
			var buf [8]byte
			copy(buf[:], v)
			s.Values = append(s.Values, Stat{ID: id, Value: binary.LittleEndian.Uint64(buf[:])})
		}
	}
	r.end()
	return s
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

// ref parses a message of an entity and nothing else from a frame
func ref(r *reader) Event {
	e := Ref{r.entity()}
	r.end()
	return e
}

// tagged parses an entity and the bytes after it from a frame
func tagged(r *reader) Event {
	t := Tagged{Entity: r.entity()}
	t.Data = append([]byte(nil), r.take(r.left())...)
	return t
}

// signal parses a message of one to four bytes from a frame
func signal(r *reader) Event {
	var s Signal
	if n := r.left(); n >= 1 && n <= 4 {
		for i, b := range r.take(n) {
			s.Code |= uint32(b) << (8 * i)
		}
	} else {
		r.bad = true
	}
	return s
}

// target parses a mob's change of target from a frame
func target(r *reader) Event {
	t := Target{Entity: r.entity()}
	if r.u8() != 0 {
		r.bad = true
	}
	t.Target = r.entity()
	r.end()
	return t
}

// combo parses a skill chain, 18 38, from a frame
func combo(r *reader) Event {
	c := Combo{From: r.skill()}
	if r.u8() != 1 {
		r.bad = true
	}
	c.To = r.skill()
	r.end()
	return c
}

// comboNext parses 19 38, the next skill of a chain, from a frame
func comboNext(r *reader) Event {
	if r.u8() != 1 {
		r.bad = true
	}
	c := Combo{To: r.skill()}
	r.end()
	return c
}

// skillUse parses the player's skill use from a frame
func skillUse(r *reader) Event {
	if r.u8() != 0 {
		r.bad = true
	}
	s := SkillUse{Info: r.u16()}
	s.Skill = r.skill()
	r.end()
	return s
}

// windup parses the notice of a cast to come from a frame
func windup(r *reader) Event {
	w := Windup{Actor: r.entity()}
	if r.u8() != 0 {
		r.bad = true
	}
	w.Skill = r.skill()
	r.skip(2) // as Cast: a counter and 02
	w.Target = r.entity()
	w.Angle = r.f32()
	w.Pos = r.pos()
	w.Duration = r.varint()
	if r.u8() != 1 {
		r.bad = true
	}
	r.end()
	return w
}

// engage parses a mob about to take the player as its target from a frame
func engage(r *reader) Event {
	if r.u16() != 0 || r.u8() != 0 {
		r.bad = true
	}
	e := Engage{r.entity()}
	r.end()
	return e
}

// threat parses 31 38 from a frame
func threat(r *reader) Event {
	if r.u16() != 0 {
		r.bad = true
	}
	t := Threat{Entity: r.entity()}
	t.Value = r.u16()
	r.end()
	return t
}

// attributes parses the player's attribute table, 49 36, with no entity, from a frame
func attributes(r *reader) Event {
	if r.u16() != 0 {
		r.bad = true
	}
	return attributeTable(r, Attributes{})
}

// attributesOf parses an entity's attribute table, 4A 36, from a frame
func attributesOf(r *reader) Event { return attributeTable(r, Attributes{Entity: r.entity()}) }

func attributeTable(r *reader, a Attributes) Event {
	n := int(r.u8())
	if n*6+8 != r.left() {
		r.bad = true
		return nil
	}
	a.Values = make([]Attribute, n)
	for i := range a.Values {
		a.Values[i] = Attribute{ID: r.u16(), Value: int32(r.u32())}
	}
	r.skip(8) // zeros so far
	r.end()
	return a
}

// height parses an entity's height from a frame
func height(r *reader) Event {
	h := Height{Entity: r.entity()}
	h.Z = r.f32()
	r.end()
	return h
}

// effectAdded parses an effect put on an entity, 2A 38, from a frame
func effectAdded(r *reader) Event { return effect(r, false) }

// effectChanged parses an effect's change, 2B 38, from a frame
func effectChanged(r *reader) Event { return effect(r, true) }

func effect(r *reader, refresh bool) Event {
	e := Effect{Entity: r.entity(), Refresh: refresh}
	if !refresh && r.u8() != 1 {
		r.bad = true
	}
	e.Kind = r.u8()
	if e.Kind&^0x13 != 0 {
		r.bad = true // a kind no recording has
	}
	e.Instance = r.varint()
	e.ID = r.u32()
	e.Value = r.u32()
	r.skip(4) // 0, or FFFFFFFF with the permanent ones
	e.Time = unixMilli(int64(r.u64()))
	e.Source = r.entity()
	r.skip(1) // 01
	if e.Kind&2 != 0 {
		e.Skill = r.skill()
	}
	r.skip(1) // 00, or 02 on 2B 38
	if e.Kind&0x10 != 0 {
		e.Pos = r.pos()
	}
	r.end()
	return e
}

// area parses a skill that lands, 03 38 and 0E 38, from a frame
func area(r *reader) Event {
	a := Area{Actor: r.entity()}
	flag := r.u8() // 00 on 03 38, 02 on 0E 38
	a.Target = r.entity()
	a.Skill = r.skill()
	r.skip(1) // a counter
	a.Instance = r.u32()
	a.Pos = r.pos()
	if flag == 2 {
		r.skip(7)
		a.Pos2 = r.pos()
		r.end()
	}
	return a
}

// cutscene parses the start of a scene from a frame
func cutscene(r *reader) Event {
	c := Cutscene{Kind: r.u32(), ID: r.u32()}
	r.skip(8) // a u32 that changes, and a u32 of zeros so far
	c.Pos = r.pos()
	// A name, when there is one, is the last thing there: its length, its bytes, and 00.
	for rest := r.p[min(r.i, len(r.p)):]; len(rest) > 2; {
		n := int(rest[0])
		if n > 0 && len(rest) == n+2 && rest[len(rest)-1] == 0 {
			c.Name = string(rest[1 : n+1])
			break
		}
		rest = rest[1:]
	}
	r.i = len(r.p)
	return c
}

// script parses a named trigger from a frame
func script(r *reader) Event {
	s := Script{Flag: r.u8(), Kind: r.u8()}
	s.Name = r.name()
	return s
}

// moveFlagged parses a move whose position follows a flag byte from a frame
func moveFlagged(r *reader) Event {
	m := Move{Entity: r.entity()}
	r.skip(1)
	m.Pos = r.pos()
	return m
}

// moveLead parses a move whose position follows an id, and 00 01, from a frame
func moveLead(r *reader) Event {
	m := Move{Entity: r.entity()}
	r.skip(6)
	m.Pos = r.pos()
	return m
}

// leadEntity parses 37 36, whose entity follows three bytes of zeros, from a frame
func leadEntity(r *reader) Event {
	if r.u16() != 0 || r.u8() != 0 {
		r.bad = true
	}
	return tagged(r)
}

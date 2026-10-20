package game

import (
	"bytes"
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

	h.Form = r.varint()
	if h.Form&^0x15 != 0 {
		return nil
	}
	h.Actor = r.entity()
	h.Skill = r.skill()
	r.skip(1) // the actor's hit count

	h.Type = r.small()

	switch sw & 0xF {
	case 0, 4:
	case 6:
		h.Mods = r.u8()
		r.varint() // 0 unless Mods has bit 0x20
		h.Direction = r.u8()
	default:
		return nil
	}
	h.Effect = r.u32()

	if r.u32() > 255 { // counts the cast's hits on the target, 1 to 5 so far
		r.bad = true
	}
	h.Speed = r.varint()

	if sw&0xF != 0 {
		h.Damage = r.varint()
	}
	if sw&0x1F == 0x14 {
		r.skip(1) // 01 so far
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
	if h.Form&1 != 0 {
		h.Effects = r.u32s()
	}
	if sw&0x40 != 0 {
		h.Buffs = r.u32s()
	}
	r.skip(1) // the low byte of the count, except on some of a mob's hits
	if r.u8() != 0 {
		r.bad = true
	}
	if h.Form&4 != 0 {
		h.Tail = r.varint()
	}
	if h.Form&0x10 != 0 && sw&0xF == 4 {
		r.skip(1) // 01 so far
	}
	r.end()
	return h
}

// spawn parses a spawn event from a frame
func spawn(r *reader) Event {
	s := Spawn{Entity: r.entity(), Mask: r.u16()}
	switch r.varint() {
	case 0:
	case 1:
		s.Owner = r.name()
	default:
		return nil
	}
	s.NPC = r.npc()
	flags := r.u8()
	if r.u8() != 2 {
		r.bad = true
	}

	s.Pos = r.pos()
	s.Heading = r.f32()
	r.skip(2) // the heading again, as a 16-bit angle

	if flags&8 != 0 {
		r.skip(12) // three floats near 0
	}
	alive := r.u8() // 01, or 00 on a corpse
	s.HP, s.MaxHP = r.varint(), r.varint()
	if alive > 1 || alive == 0 && s.HP != 0 {
		r.bad = true
	}
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

// fall parses a fall event from a frame
func fall(r *reader) Event {
	f := Fall{Entity: r.entity(), Damage: r.varint()}
	r.end()
	return f
}

// gearScore parses the character's gear score from a frame
func gearScore(r *reader) Event {
	g := GearScore{Now: r.u32(), Best: r.u32()}
	if g.Best < g.Now {
		r.bad = true
	}
	r.end()
	return g
}

// combatPower parses the character's combat power from a frame
func combatPower(r *reader) Event {
	c := CombatPower{Now: r.u64(), Best: r.u64()}
	if c.Best < c.Now {
		r.bad = true
	}
	r.end()
	return c
}

// kill parses a kill event from a frame
func kill(r *reader) Event {
	k := Kill{Entity: r.entity(), Skill: r.skill(), Actor: r.entity(), Server: r.u16(), Name: r.name(), Legion: r.name()}
	if (r.u16() != 0) != (k.Legion != "") { // 1 with a legion
		r.bad = true
	}
	k.NPC = NPC(r.varint())
	r.skip(4) // a u32, 0 but on some summons running out

	if (r.u8() == 1) != (k.Actor != 0 || k.Skill != 0) { // 1 with a killer or a skill
		r.bad = true
	}
	r.skip(1) // 0 when a player killed a mob, 1 when a player killed a player, 2 when no player or entity is credited
	r.end()
	return k
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
	flags := r.u8()
	if flags&^0xC != 0 {
		return nil
	}

	c.Skill = r.skill()
	r.skip(1) // counts the actor's casts

	placed := r.u8() == 2 // 02 with a position, 00 without
	c.Target = r.entity()
	r.skip(4) // likely the heading, in degrees

	if placed {
		c.Pos = r.pos()
	}

	r.varint() // the actor's Speed, as in Hit
	r.skip(1)  // 01 or 02 so far

	r.varint() // 0 mostly, else 150 to 111700
	if flags&4 != 0 {
		c.Count = r.u8()
	}
	if flags&8 != 0 {
		c.Tail = r.varint()
	}
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

// zone parses a zone event from a frame
func zone(r *reader) Event {
	if r.varint() != 0 {
		r.bad = true
	}
	r.skip(5)
	return Zone{Pos: r.pos()}
}

// sheet parses the player's whole stat table from a frame
func sheet(r *reader) Event {
	if r.u16() != 0 {
		r.bad = true
	}
	return rows(r, Stats{Full: true})
}

// sheetUpdate parses the rows of an entity's stat table that changed from a frame
func sheetUpdate(r *reader) Event { return rows(r, Stats{Entity: r.entity()}) }

// rows reads a stat table's rows into s, and the trailer that repeats its base HP.
func rows(r *reader, s Stats) Event {
	n := r.varint()
	if n > uint32(r.left()/6) { // six bytes a row
		r.bad = true
		return nil
	}

	s.Rows = make(map[Stat]int32, n)
	for range n {
		id := Stat(r.u16())
		s.Rows[id] = int32(r.u32())
	}
	if int32(r.u32()) != s.Rows[193] || r.u32() != 0 { // the base HP row again, 0 without it, @TODO: named stats instead of numbers
		r.bad = true
	}

	r.end()
	return s
}

// gauges parses what changed of an entity's HP, MP and flight time from a frame
func gauges(r *reader) Event {
	var (
		g    = Gauges{Entity: r.entity(), Rows: map[Gauge]uint64{}}
		mask = r.u8()
	)
	if mask&^3 != 0 {
		r.bad = true
		return nil
	}

	if mask&1 != 0 { // MP, flight time and the maxes
		for range r.u8() {
			g.Rows[Gauge(r.u8())] = uint64(r.u32())
		}
	}

	if mask&2 != 0 { // HP and max HP
		for range r.u8() {
			g.Rows[Gauge(r.u8())] = r.u64()
		}
	}

	r.end()
	return g
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
	r.skip(5) // 01, then a u32 0 so far
	if r.u16() != a.Server {
		r.bad = true
	}

	r.skip(3) // 03 09 03 so far
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

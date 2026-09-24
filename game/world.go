package game

// Spawn announces a mob or summon entering view, from 41 36. NPC is its type id
type Spawn struct {
	Entity  uint32
	Mask    uint32 // its low byte varies with the kind of entity
	NPC     uint32
	X, Y, Z float32
}

// Player announces a player entering view, from 45 36, or the client's own character, from 33 36.
type Player struct {
	Entity uint32
	Name   string
	Self   bool
}

// Move is an entity's position update, from 1A 37, 1B 37 and/or 1C 37.
//
// @TODO: still not fully understood, revisit later
type Move struct {
	Entity  uint32
	X, Y, Z float32
}

// Zone places the client's character in the world after a zone change, from 23 36.
type Zone struct {
	X, Y, Z float32
}

func (Spawn) event()  {}
func (Player) event() {}
func (Move) event()   {}
func (Zone) event()   {}

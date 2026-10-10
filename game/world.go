package game

// Spawn announces a mob or summon entering view
type Spawn struct {
	Entity Entity
	NPC    NPC
	Mask   uint32 // its low byte varies with the kind of entity
	Pos
}

// Player announces a player entering view
type Player struct {
	Entity Entity
	Name   string
	Self   bool
}

// Move is an entity's position update
//
// @TODO: still not fully understood, revisit later
type Move struct {
	Entity Entity
	Pos
}

// Turn is a lighter update than Move, with no position.
//
// Every sample seen so far sends Heading twice, always the same value, so what a change would
// look like, or whether this is a heading at all, is not confirmed.
type Turn struct {
	Entity  Entity
	Heading uint16
}

// Zone places the client's character in the world after a zone change
type Zone struct{ Pos }

// NameCheck is the server's answer when the client registers a name for a new character
type NameCheck struct {
	Name  string
	Taken bool   // the server refused the name
	Code  uint16 // 0 when the name is free, 0x2023 when it is taken
}

func (Spawn) event()     {}
func (Player) event()    {}
func (Move) event()      {}
func (Turn) event()      {}
func (Zone) event()      {}
func (NameCheck) event() {}

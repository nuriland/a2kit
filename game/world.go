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

// Zone places the client's character in the world after a zone change
type Zone struct{ Pos }

func (Spawn) event()  {}
func (Player) event() {}
func (Move) event()   {}
func (Zone) event()   {}

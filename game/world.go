package game

import "time"

// Spawn announces a mob or summon entering view
type Spawn struct {
	Entity    Entity
	Owner     string // the player whose summon it is, else ""
	NPC       NPC
	Mask      uint16  // its low byte varies with the kind of entity
	Heading   float32 // degrees
	HP, MaxHP uint32  // HP never passes MaxHP, which is one value per NPC except on summons
	Pos
}

// Object announces a thing in the world a player can use entering view
type Object struct {
	Entity  Entity
	Mask    uint16    // which bytes follow, 4 mostly, 12 and 1 on a few types
	Type    uint32    // the type of the object (id)
	State   byte      // 1 mostly, 6 on one just reset
	Heading float32   // degrees
	Since   time.Time // likely when it last appeared
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

// NameCheck is the server's answer when the client registers a name for a new character
type NameCheck struct {
	Name  string
	Taken bool   // the server refused the name
	Code  uint16 // 0 when the name is free, 0x2023 when it is taken
}

func (Spawn) event()     {}
func (Object) event()    {}
func (Player) event()    {}
func (Move) event()      {}
func (Zone) event()      {}
func (NameCheck) event() {}

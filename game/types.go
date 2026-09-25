package game

// Entity identifies something in the world for the session. Anything from a player, a mob, a summon, etc.
type Entity uint32

// Skill is a skill's id from the game files.
type Skill uint32

// NPC is a mob's type id from the game files.
type NPC uint32

// Pos is a position in the zone.
type Pos struct{ X, Y, Z float32 }

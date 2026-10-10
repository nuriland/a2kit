package game

import "time"

// What is in this file is read from one recording and named by a guess. A name, a field or a
// layout here may change when another recording says otherwise. Each doc comment says what the
// guess rests on.

// Ref names an entity and nothing more.
type Ref struct{ Entity Entity }

// Tagged is a message that starts with an entity, followed by the bytes a2k does not read yet.
type Tagged struct {
	Entity Entity
	Data   []byte
}

// Signal is a message of one to four bytes and no entity, which holds a small number, 0 so far.
type Signal struct{ Code uint32 }

// Target is the entity a mob has picked to attack, from 35 38, with Target 0 when it lets go.
//
// Guess: it follows a mob's first Cast on the player by a few tenths of a second, and ends with
// a 0 when the fight is over.
type Target struct{ Entity, Target Entity }

// Combo is a chain of the player's skills, from 18 38: the skill that was used, and the one that
// can follow it. From is 0 when the message, 19 38, names only the next skill.
//
// Guess: the three skills 9865 to 9867 and the next three 9868 to 9870 follow each other in the
// order a basic attack chain would, one of these each time the player casts one.
type Combo struct{ From, To Skill }

// SkillUse is the player's own Cast, again, from 01 38.
//
// Guess: it comes with each of the player's own Cast, with its skill. Info is 0 on most, and
// 0x1813 on a few that came late.
type SkillUse struct {
	Skill Skill
	Info  uint16
}

// Windup announces a Cast before it comes, from 09 38, as a mob's skill is about to land.
//
// Guess: it comes 500 to 600 ms before the Cast of the same skill from the same mob, and carries
// a number of the same size in Duration, in milliseconds.
type Windup struct {
	Actor, Target Entity
	Skill         Skill
	Angle         float32
	Pos
	Duration uint32
}

// Engage names the mob that is about to pick the player as its Target, from 34 38. The entity is 0 on some.
//
// Guess: it comes right before Target, with the same mob in it.
type Engage struct{ Entity Entity }

// Threat is the other end of a fight with a mob, from 31 38: the mob, and a number that varies.
//
// Guess: it comes with the mob's Target letting go, and its number, a u16, is not understood.
type Threat struct {
	Entity Entity
	Value  uint16
}

// Attributes is an entity's whole table of attributes, from 49 36 for the player's own, which
// has no entity, and 4A 36 for another's.
//
// Guess: the ids are the game's attribute ids and a value goes with each. Ids 0x5d and 0x59
// hold 1500 and 2500 on a new character, and 0x60 and 0x61 hold 100000, as Stats' 1 and 3 do.
type Attributes struct {
	Entity Entity
	Values []Attribute
}

// Attribute is one of Attributes' ids and its value.
type Attribute struct {
	ID    uint16
	Value int32
}

// Height is an entity's height, from 46 37.
//
// Guess: the value is the Z of the entity's position, to the unit, in every sample.
type Height struct {
	Entity Entity
	Z      float32
}

// Effect is something put on an entity, from 2A 38, and the change of one from 2B 38, a buff or
// a debuff.
//
// Guess: Instance counts up with each one, an effect's ID repeats, and what Value holds changes
// with it, 5000 or 300 or 200, which looks like its strength or its length. Time is when, and
// Source is who. The kinds seen are 01, 11 and 13: 02 adds a Skill and 10 adds a position.
type Effect struct {
	Entity   Entity
	Kind     byte
	Instance uint32
	ID       uint32
	Value    uint32 // 0xFFFFFFFF with the permanent ones
	Time     time.Time
	Source   Entity
	Skill    Skill
	Refresh  bool // 2B 38
	Pos
}

// Area is a skill that lands somewhere, from 03 38, and from 0E 38 with a second position.
//
// Guess: a mob's skill, with the player for its target, comes right after the Cast of a mob.
// The layout of what follows the position is not understood, and is not read.
type Area struct {
	Actor, Target Entity
	Skill         Skill
	Instance      uint32
	Pos
	Pos2 Pos // 0E 38 only
}

// Cutscene starts a scripted scene for the player, from 21 36, at a position, and with the scene's name.
//
// Guess: its names are Cutscene_L_A_QM_1001 and Cutscene_L_A_Seq_1278, and 15 8D names the same one a moment later.
type Cutscene struct {
	Kind uint32 // 1 to 5
	ID   uint32 // 100001 mostly
	Name string // a name comes with some of them
	Pos
}

// Script is a named trigger of the game's scripts, from 15 8D: a cutscene, a talk, or a step of the tutorial.
//
// Guess: its names are Cutscene_L_A_Seq_1273, Talk_L_Starter_InstanceLayer_1_08 and Tutorial_Basic_05.
type Script struct {
	Flag, Kind byte // Kind is 09 for a cutscene, 13 for a talk, 2E for a tutorial
	Name       string
}

func (Ref) event()        {}
func (Tagged) event()     {}
func (Signal) event()     {}
func (Target) event()     {}
func (Combo) event()      {}
func (SkillUse) event()   {}
func (Windup) event()     {}
func (Engage) event()     {}
func (Threat) event()     {}
func (Attributes) event() {}
func (Height) event()     {}
func (Effect) event()     {}
func (Area) event()       {}
func (Cutscene) event()   {}
func (Script) event()     {}

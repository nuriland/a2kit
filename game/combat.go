package game

// Hit is one skill landing on a target
//
// @REVIEW: fields and documentation
type Hit struct {
	Actor, Target   Entity
	Skill           Skill
	Damage          uint32   // the amount of damage dealt, unless it's a buff, then it's 0
	Extra           []uint32 // a tiny share of Damage each
	Type            byte     // 3 on the hits that look critical, else 2
	Scalar          uint32   // 10000, 10910, 12491 or 13491 so far, one value per actor
	Mods, Direction byte     // with some hits, else 0
}

// Cast opens a skill use, from 02 38. Its position is the target's.
type Cast struct {
	Actor, Target Entity
	Skill         Skill
	Pos
}

// CastEnd closes the skill use a Cast opened, from 06 38.
type CastEnd struct {
	Actor Entity
	Skill Skill
}

// Owner binds an entity to the actor whose skill holds it, from 04 8D: a summon to its summoner,
// or a mob to the player fighting it. It carries the actor's name.
type Owner struct {
	Entity, Actor Entity
	Skill         Skill
	Name          string
}

// Death reports an entity killed, from 42 36.
type Death struct {
	Entity Entity
	Flag   byte // 3 on a kill; 1 also comes
}

func (Hit) event()     {}
func (Cast) event()    {}
func (CastEnd) event() {}
func (Owner) event()   {}
func (Death) event()   {}

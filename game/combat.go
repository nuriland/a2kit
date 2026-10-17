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
	Speed           uint32   // 10000 plus the actor's combat speed row
	Mods, Direction byte     // with some hits, else 0
	Form            uint32   // 0 mostly, 4 on the hits that carry a Tail, 1 once on a type 6 hit
	Tail            uint32   // after the trailer with Form 4, 349 to 399 so far and 1551 once, rises with Damage, unsure
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

// Kill reports an entity's HP reaching 0 and who did it. Actor is 0 on a summon running out.
type Kill struct {
	Entity, Actor Entity
	Skill         Skill
	Server        uint16 // the actor's, likely
	Name          string
	Legion        string // a second name after the actor's, likely their legion
}

// Death reports an entity leaving view.
type Death struct {
	Entity Entity
	Flag   byte // 3 on a corpse, 1 on anything out of range
}

// Fall reports a hard landing.
type Fall struct {
	Entity Entity
	Damage uint32 // what the HP gauge drops by
}

func (Hit) event()     {}
func (Cast) event()    {}
func (CastEnd) event() {}
func (Kill) event()    {}
func (Death) event()   {}
func (Fall) event()    {}

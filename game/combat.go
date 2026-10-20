package game

// Hit is one skill landing on a target
//
// @REVIEW: fields and documentation
type Hit struct {
	Actor, Target   Entity
	Skill           Skill
	Effect          uint32   // a skill's id times 100 plus two digits, mostly the hit's own skill's
	Damage          uint32   // the amount of damage dealt, unless it's a buff, then it's 0
	Extra           []uint32 // a tiny share of Damage each
	Type            byte     // 2 mostly, 3 on the hits that look critical, 6 with Effects, 0 or 1 on some without damage
	Speed           uint32   // 10000 plus the actor's combat speed row
	Mods, Direction byte     // with some hits, else 0
	Form            uint32   // 1 adds Effects, 4 a Tail //@TODO: needs more documentation
	Tail            uint32   // after the trailer with Form 4, rises with Damage, unsure
	Effects         []uint32 // with Form 1, likely the effects the hit puts on the target, ids of another space than Effect's
	Buffs           []uint32 // on a mob's or summon's hit on a player, likely the Effect of buffs on the target, unsure what for
}

// Cast opens a skill use. Its position is the target's.
type Cast struct {
	Actor, Target Entity
	Skill         Skill
	Pos
	Count byte   // with flag 4 of the byte after the actor, 1 or 2 so far, maybe how far the skill was charged, unsure
	Tail  uint32 // with flag 8, a multiple of 50, likely ms, on casts that no CastEnd follows
}

// CastEnd closes the skill use a Cast opened.
type CastEnd struct {
	Actor Entity
	Skill Skill
}

// Kill reports an entity's HP reaching 0 and who did it. Actor is 0 on a summon running out, and on every kill by a player in the dungeon runs so far.
type Kill struct {
	Entity, Actor Entity
	Skill         Skill
	Server        uint16 // the actor's, 0 when it is a mob
	Name          string
	Legion        string // a second name after the actor's, likely their legion
	NPC           NPC    // the actor's type when it is a mob
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

package game

import "github.com/nuriland/a2kit/wire"

// op is what the table knows of an opcode: its name, and the function that reads it, or nil for one seen but not read.
type op struct {
	name string
	read func(*reader) Event
}

// @TODO: add more opcodes

// opcodes is every opcode game has a name for.
var opcodes = map[wire.Opcode]op{
	// 36: the login, the world, and its clocks
	0x3600: {"Tick", tick},
	0x3603: {"Ping", ping},
	0x3611: {"Handshake", nil}, // a login's first frame: 00 00, a u32 60000, a varint 256 and that many random bytes, then 12 more (8 zeros, f9 ff ff ff)
	0x3615: {"Login", nil},     // the login time, that time plus 8 h, and the account
	0x361A: {"NameCheck", nameCheck},
	0x3623: {"Zone", zone},
	0x3633: {"Self", self},
	0x3641: {"Spawn", spawn},
	0x3642: {"Death", death},
	0x3645: {"Player", player},
	0x3634: {"Spawn", spawnStatic},

	// 39: the lobby, which lists the servers and hands the client to the one picked
	0x3901: {"LobbyHandshake", nil}, // the lobby's first frame: 00 00, a u16 60, a varint 256 and that many random bytes, then 10 zeros
	0x3903: {"LobbyPing", lobbyPing},
	0x3906: {"Account", account},
	0x3909: {"Servers", servers},
	0x390B: {"Characters", characters},
	0x390D: {"Join", join}, // the server picked
	0x390F: {"Redirect", redirect},

	// 37: movement
	0x371A: {"Move", moveA},
	0x371B: {"Move", moveB},
	0x371C: {"Move", moveB},
	0x371D: {"Turn", turn},              // a lighter update than Move, with no position
	0x3728: {"Heading", headingWithPos}, // flag 04, with a position
	0x3729: {"Heading", headingWithPos}, // flag 02, with a position
	0x372A: {"Heading", headingOnly},    // no position
	0x372F: {"Move", moveB},             // with more fields after the position, not understood

	// 38: skills
	0x3802: {"Cast", cast},
	0x3804: {"Hit", hit},
	0x3805: {"DoT", nil},
	0x3806: {"CastEnd", castEnd},

	0x8D00: {"Stats", stats},
	0x8D04: {"Owner", owner},
	0x8D2F: {"Notice", nil}, // text to the players, the same in each of its slots
	0x921B: {"HP", nil},
	0x9702: {"Party", nil},
}

// guesses are opcodes named, and read, on the strength of one recording. Each is a guess until
// another confirms it, see guess.go, and each comment says what the guess is.
var guesses = map[wire.Opcode]op{
	// 36: the world
	0x3618: {"Signal", signal},
	0x3621: {"Cutscene", cutscene},
	0x3631: {"Signal", signal},
	0x3635: {"ObjectState", tagged},     // of the objects that never move: two small numbers, and 00
	0x3637: {"InteractAck", leadEntity}, // the last of five messages that name one object after the player touches it
	0x3638: {"Interact", tagged},        // an object, the player, and 01
	0x363A: {"InteractEnd", tagged},     // an object, the player, and eight zeros
	0x363B: {"InteractDone", ref},       // an object
	0x3646: {"Ready", tagged},           // the player's entity and 00, as a zone is entered
	0x3647: {"State", tagged},           // an entity and two bytes that change
	0x3649: {"Attributes", attributes},
	0x364A: {"Attributes", attributesOf},
	0x364B: {"Status", tagged},   // a mob, 01, an id, and a value that is 3000 or -2500
	0x364E: {"Waypoint", tagged}, // an entity, two floats under 500, and 00 or 01

	// 37: movement
	0x371E: {"Move", moveFlagged},
	0x3721: {"Land", ref}, // players only
	0x3722: {"Stop", ref}, // the player and others
	0x3723: {"Move", moveFlagged},
	0x3724: {"Move", moveFlagged},
	0x372B: {"Move", moveFlagged},
	0x372E: {"Move", moveLead},
	0x373C: {"Move", moveFlagged},
	0x3741: {"Rest", tagged}, // the player's entity and a u16
	0x3742: {"Jump", ref},    // the player only
	0x3746: {"Height", height},

	// 38: skills
	0x3801: {"SkillUse", skillUse},
	0x3803: {"Area", area},
	0x3809: {"Windup", windup},
	0x380C: {"Casting", tagged}, // a mob, 00 00, a skill and 00 00
	0x380E: {"Area", area},
	0x3818: {"Combo", combo},
	0x3819: {"Combo", comboNext},
	0x382A: {"Effect", effectAdded},
	0x382B: {"Effect", effectChanged},
	0x382C: {"Charge", tagged}, // an entity, 01 00, and two bytes that count up with the player's casts
	0x3831: {"Threat", threat},
	0x3834: {"Engage", engage},
	0x3835: {"Target", target},
	0x383B: {"ActionBegin", signal}, // 0.1 s before 3D 38, when the player starts a skill of a chain
	0x383D: {"ActionEnd", signal},

	// 8D
	0x8D03: {"Notify", tagged}, // an entity and four zeros
	0x8D15: {"Script", script},
	0x8D21: {"Notify", tagged}, // an entity, 00, 01
	0x8D41: {"Signal", signal},
	0x8D43: {"Signal", signal},
	0x8D52: {"Notify", ref}, // a mob
	0x8D6D: {"InteractOpen", ref},
	0x8D91: {"Notify", tagged}, // a player, 02 00 00 00
	0x8D93: {"Notify", tagged}, // an object, 01 00 00 00

	// seen but not read: the names are guesses from what is in them
	0x8D53: {"Season", nil},        // names like Season_Main_Live
	0xE349: {"Mail", nil},          // a gift mail's title and text
	0x5600: {"Skills", nil},        // the player's skill ids, each twice, and a flag
	0x5684: {"Item", nil},          // one item: an id, a count, and the time it came
	0x5683: {"Items", nil},         // 39691 bytes at login, a table that holds Item's ids
	0x5611: {"Bag", nil},           // 819 bytes at login
	0x922E: {"MapEvent", nil},      // an id, and a name like World_L_Starter_Layer_1_1_MapEvent
	0x922D: {"MapEventState", nil}, // the same id, and two bytes that change
	0x9231: {"MapEventState", nil}, // another event's id, and a count
	0xFFA5: {"Time", nil},          // a zero u64, and the time as the other messages carry it
	0xFFAC: {"Time", nil},
	0xFFA9: {"Time", nil},
	0x9508: {"MobState", nil}, // a mob, 20001 or 20003, and 02

	// seen once or twice, mostly as a zone loads: named from the family and what is in them
	0xE324: {"Quest", nil},         // 24 E3
	0xE335: {"QuestScene", nil},    // 35 E3
	0xE343: {"QuestList", nil},     // 43 E3
	0xE32A: {"QuestList", nil},     // 2A E3
	0xE33A: {"QuestMarker", nil},   // 3A E3
	0xE347: {"QuestState", nil},    // 47 E3
	0xE002: {"QuestState", nil},    // 02 E0
	0xE004: {"QuestState", nil},    // 04 E0
	0xE200: {"Settings", nil},      // 00 E2
	0xE215: {"Settings", nil},      // 15 E2
	0xE223: {"Settings", nil},      // 23 E2
	0xE224: {"Settings", nil},      // 24 E2
	0xE22E: {"Settings", nil},      // 2E E2
	0xE241: {"Settings", nil},      // 41 E2
	0xE243: {"Settings", nil},      // 43 E2
	0xE248: {"Settings", nil},      // 48 E2
	0xE250: {"Settings", nil},      // 50 E2
	0xE251: {"Settings", nil},      // 51 E2
	0xE256: {"Settings", nil},      // 56 E2
	0xE258: {"Settings", nil},      // 58 E2
	0xE25A: {"Settings", nil},      // 5A E2
	0xE25C: {"Settings", nil},      // 5C E2
	0xE262: {"Settings", nil},      // 62 E2
	0xE263: {"Settings", nil},      // 63 E2
	0xE274: {"Settings", nil},      // 74 E2
	0xE28C: {"Settings", nil},      // 8C E2
	0xE28D: {"Settings", nil},      // 8D E2
	0xE213: {"Settings", nil},      // 13 E2
	0x4001: {"SceneState", nil},    // 01 40
	0x4002: {"SceneState", nil},    // 02 40
	0x400A: {"SceneState", nil},    // 0A 40
	0x6000: {"SceneState", nil},    // 00 60
	0x6100: {"SceneData", nil},     // 00 61
	0x6101: {"SceneData", nil},     // 01 61
	0x610B: {"SceneData", nil},     // 0B 61
	0x4301: {"Achievement", nil},   // 01 43
	0x5100: {"Currency", nil},      // 00 51
	0x3656: {"Currency", nil},      // 56 36
	0x3657: {"Currency", nil},      // 57 36
	0x561B: {"ItemUpdate", nil},    // 1B 56
	0x561C: {"ItemUpdate", nil},    // 1C 56
	0x5648: {"ItemUpdate", nil},    // 48 56
	0x5613: {"ItemUpdate", nil},    // 13 56
	0x561D: {"ItemCount", nil},     // 1D 56
	0x8A1D: {"Chat", nil},          // 1D 8A
	0x9000: {"Social", nil},        // 00 90
	0x9330: {"Social", nil},        // 30 93
	0x9331: {"Social", nil},        // 31 93
	0x361C: {"Social", nil},        // 1C 36
	0x3620: {"Social", nil},        // 20 36
	0x3626: {"Social", nil},        // 26 36
	0x9501: {"Emotes", nil},        // 01 95
	0x8D10: {"Instance", nil},      // 10 8D
	0x8D2C: {"Instance", nil},      // 2C 8D
	0x8D11: {"Instance", nil},      // 11 8D
	0x8D09: {"Instance", nil},      // 09 8D
	0x8D7E: {"Catalog", nil},       // 7E 8D
	0x8D8C: {"Catalog", nil},       // 8C 8D
	0x922F: {"MapEventState", nil}, // 2F 92
	0x9232: {"MapEventList", nil},  // 32 92
	0x372D: {"Move", nil},          // 2D 37
	0x3725: {"Move", nil},          // 25 37
	0x3732: {"Move", nil},          // 32 37
	0x3720: {"Move", nil},          // 20 37
	0x3730: {"Move", nil},          // 30 37
	0x3734: {"Move", nil},          // 34 37
	0x3900: {"SkillSlots", nil},    // 00 39
	0xE33B: {"Signal", nil},        // 3B E3
	0xE33D: {"Signal", nil},        // 3D E3
	0xE33E: {"Signal", nil},        // 3E E3
	0xE342: {"Signal", nil},        // 42 E3
	0xE226: {"Signal", nil},        // 26 E2
	0xE237: {"Signal", nil},        // 37 E2
	0xE257: {"Signal", nil},        // 57 E2
	0x8D58: {"Signal", nil},        // 58 8D
	0x8D37: {"Signal", nil},        // 37 8D
	0x8AAF: {"Signal", nil},        // AF 8A
	0x5633: {"Signal", nil},        // 33 56
	0x564B: {"Signal", nil},        // 4B 56
	0x5672: {"Signal", nil},        // 72 56
	0x56B6: {"Signal", nil},        // B6 56
	0x56AD: {"Signal", nil},        // AD 56
	0x5679: {"Signal", nil},        // 79 56
	0x5682: {"Signal", nil},        // 82 56
	0x56A8: {"Signal", nil},        // A8 56
	0x570F: {"Signal", nil},        // 0F 57
	0x572D: {"Signal", nil},        // 2D 57
	0x6103: {"Signal", nil},        // 03 61
	0x6108: {"Signal", nil},        // 08 61
	0x6109: {"Signal", nil},        // 09 61
	0x363E: {"Signal", nil},        // 3E 36
	0x8D44: {"Notify", nil},        // 44 8D
	0x8D4B: {"Notify", nil},        // 4B 8D
	0x8D57: {"Notify", nil},        // 57 8D
	0x8D5B: {"Notify", nil},        // 5B 8D
	0x8D4E: {"Notify", nil},        // 4E 8D
	0x8D01: {"Notify", nil},        // 01 8D
	0x8D0F: {"Notify", nil},        // 0F 8D
}

func init() {
	for o, g := range guesses {
		if _, ok := opcodes[o]; ok {
			panic("game: " + o.String() + " is both known and guessed")
		}
		opcodes[o] = g
	}
}

// Name is what the table calls o, or "" for an opcode it has not met.
func Name(o wire.Opcode) string { return opcodes[o].name }

// private is the opcodes that name the account or its characters
var private = map[wire.Opcode]bool{0x3615: true, 0x3906: true, 0x390B: true}

// Private reports whether o names the account or its characters
func Private(o wire.Opcode) bool { return private[o] }

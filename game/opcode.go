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

	// 38: skills
	0x3802: {"Cast", cast},
	0x3804: {"Hit", hit},
	0x3805: {"DoT", nil},
	0x3806: {"CastEnd", castEnd},

	0x8D04: {"Owner", owner},
	0x8D2F: {"Notice", nil}, // text to the players, the same in each of its slots
	0x921B: {"HP", nil},
	0x9702: {"Party", nil},
}

// Name is what the table calls o, or "" for an opcode it has not met.
func Name(o wire.Opcode) string { return opcodes[o].name }

// private is the opcodes that name the account or its characters
var private = map[wire.Opcode]bool{0x3615: true, 0x3906: true, 0x390B: true}

// Private reports whether o names the account or its characters
func Private(o wire.Opcode) bool { return private[o] }

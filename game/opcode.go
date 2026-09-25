package game

import "github.com/nuriland/a2kit/wire"

// op is what the table knows of an opcode: its name, and how to read it, or nil for one seen but not read.
type op struct {
	name string
	read func(*reader) Event
}

// opcodes is every opcode game has a name for.
//
// @TODO: add more opcodes
var opcodes = map[wire.Opcode]op{
	// 36: the world, and its clocks
	0x3600: {"Tick", (*reader).tick},
	0x3603: {"Ping", (*reader).ping},
	0x3623: {"Zone", (*reader).zone},
	0x3633: {"Self", (*reader).self},
	0x3641: {"Spawn", (*reader).spawn},
	0x3642: {"Death", (*reader).death},
	0x3645: {"Player", (*reader).player},

	// 37: movement
	0x371A: {"Move", (*reader).moveA},
	0x371B: {"Move", (*reader).moveB},
	0x371C: {"Move", (*reader).moveB},
	0x371D: {"Move", nil}, // 9–12 bytes, a sibling

	// 38: skills
	0x3802: {"Cast", (*reader).cast},
	0x3804: {"Hit", (*reader).hit},
	0x3805: {"DoT", nil},
	0x3806: {"CastEnd", (*reader).castEnd},

	0x8D04: {"Owner", (*reader).owner},
	0x921B: {"HP", nil},
	0x9702: {"Party", nil},
}

// Name is what the table calls o, or "" for an opcode it has not met.
func Name(o wire.Opcode) string { return opcodes[o].name }

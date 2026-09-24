// Package wire turns TCP segments into AION 2 game frames.
//
// An Opcode is a frame's first two bytes read as a little-endian integer.
// Wire bytes 04 38 are Opcode(0x3804), printed "04 38"
package wire

//go:generate go run ../internal/genfixtures -root ..

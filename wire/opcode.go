package wire

import (
	"fmt"
	"slices"
)

// Opcode is the two bytes that begin a frame's body, the first in the low byte: wire bytes
// 04 38 are 0x3804. The high byte is the family.
type Opcode uint16

func (o Opcode) Bytes() [2]byte { return [2]byte{byte(o), byte(o >> 8)} }

// String is the opcode in wire order, "04 38".
func (o Opcode) String() string { return fmt.Sprintf("%02X %02X", byte(o), byte(o>>8)) }

// Known reports whether o is in the table of known opcodes.
func (o Opcode) Known() bool { return slices.Contains(known[:], o) }

// known lists the opcodes the lock counts and KnownOnly keeps, by family.
var known = [...]Opcode{
	0x3804, 0x3805, 0x3802, 0x3806, 0x3822, 0x382A, 0x382B, 0x382C, 0x3835, 0x3847,
	0x3633, 0x3623, 0x3640, 0x3641, 0x3644, 0x3645, 0x3646, 0x3649,
	0x3600, // the tick
	0x8D00, 0x8D04, 0x8D21,
	0x921B, 0x9200, 0x920D,
}

// inFamily reports whether b, an opcode's high byte, is one of the families. Unless KnownOnly
// is set, an opcode in a family is plausible. Every known opcode is in one.
func inFamily(b byte) bool {
	switch b {
	case 0x36, 0x37, 0x38, 0x56, 0x8A, 0x8D, 0x92, 0x96, 0x97:
		return true
	}
	return false
}

// combat reports whether o is damage: 04 38, or damage over time, 05 38.
func combat(o Opcode) bool { return o == 0x3804 || o == 0x3805 }

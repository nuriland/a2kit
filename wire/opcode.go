package wire

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Opcode is the two bytes that begin a frame's body, read little-endian: wire bytes 04 38 are 0x3804. The high byte is the family.
type Opcode uint16

// opcode reads the opcode at the start of b.
func opcode(b []byte) Opcode { return Opcode(binary.LittleEndian.Uint16(b)) }

// Bytes returns the opcode's two bytes in wire order.
func (o Opcode) Bytes() [2]byte { return [2]byte{byte(o), byte(o >> 8)} }

// String is the opcode in wire order, "04 38".
func (o Opcode) String() string { return fmt.Sprintf("%02X %02X", byte(o), byte(o>>8)) }

// MarshalText is String.
func (o Opcode) MarshalText() ([]byte, error) { return []byte(o.String()), nil }

// UnmarshalText reads the form String writes, "04 38", in either case.
func (o *Opcode) UnmarshalText(b []byte) error {
	var p [2]byte
	if len(b) != 5 || b[2] != ' ' {
		return fmt.Errorf("wire: opcode %q is not two hex bytes, like \"04 38\"", b)
	}
	if _, err := hex.Decode(p[:], []byte{b[0], b[1], b[3], b[4]}); err != nil {
		return fmt.Errorf("wire: opcode %q: %w", b, err)
	}
	*o = opcode(p[:])
	return nil
}

// Known reports whether o is in the table of known opcodes.
func (o Opcode) Known() bool { return knownBits[o>>6]&(1<<(o&63)) != 0 }

// knownBits is known as a bitmap, one bit an opcode.
var knownBits = func() (bits [1 << 10]uint64) {
	for _, o := range known {
		bits[o>>6] |= 1 << (o & 63)
	}
	return bits
}()

// known lists the opcodes the lock counts and KnownOnly keeps
var known = [...]Opcode{
	0x3804, 0x3805, 0x3802, 0x3806, 0x3822, 0x382A, 0x382B, 0x382C, 0x3835, 0x3847,
	0x3603, 0x361A, 0x3623, 0x3633, 0x3640, 0x3641, 0x3634, 0x3642, 0x3645, 0x3646, 0x3647, 0x3649, 0x364A,
	0x3600, // Server tick
	0x371A, 0x371B, 0x371C, 0x371D, 0x3728, 0x3729, 0x372A, 0x372F,
	0x8D00, 0x8D04, 0x8D21,
	0x921B, 0x9200, 0x920D,
	0x3901, 0x3903, 0x3906, 0x3909, 0x390B, 0x390D, 0x390F, // Lobby opcodes
}

// guessed lists the opcodes package game reads on a guess. A decoder that keeps only known opcodes
// keeps them too, but the lock does not count them: a guess more in the list would make noise
// look like the game's frames sooner.
var guessed = [...]Opcode{
	0x3618, 0x3621, 0x3631, 0x3635, 0x3637, 0x3638, 0x363A, 0x363B, 0x364B, 0x364E,
	0x371E, 0x3721, 0x3722, 0x3723, 0x3724, 0x372B, 0x372E, 0x373C, 0x3741, 0x3742, 0x3746,
	0x3801, 0x3803, 0x3809, 0x380C, 0x380E, 0x3818, 0x3819, 0x3831, 0x3834, 0x383B, 0x383D,
	0x8D03, 0x8D15, 0x8D41, 0x8D43, 0x8D52, 0x8D6D, 0x8D91, 0x8D93,
}

// Guessed reports whether o is one package game reads on a guess, and the lock does not count.
func (o Opcode) Guessed() bool { return guessedBits[o>>6]&(1<<(o&63)) != 0 }

// guessedBits is guessed as a bitmap, one bit an opcode.
var guessedBits = func() (bits [1 << 10]uint64) {
	for _, o := range guessed {
		bits[o>>6] |= 1 << (o & 63)
	}
	return bits
}()

// listed reports whether o is known, or guessed: what KnownOnly keeps.
func (o Opcode) listed() bool { return o.Known() || o.Guessed() }

// inFamily reports whether b, an opcode's high byte, is one of the families. Unless KnownOnly
// is set, an opcode in a family is plausible. Every known opcode is in one.
func inFamily(b byte) bool {
	switch b {
	case 0x36, 0x37, 0x38, 0x39, 0x56, 0x8A, 0x8D, 0x92, 0x96, 0x97:
		return true
	}
	return false
}

// combat reports whether o is damage: 04 38, or damage over time, 05 38.
func combat(o Opcode) bool { return o == 0x3804 || o == 0x3805 }

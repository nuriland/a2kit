// Package wiretest builds bytes for tests: AION 2 frames and bundles, the
// TCP packets that carry them, and the pcap and pcapng files that hold those.
package wiretest

import (
	"encoding/binary"
	"slices"

	"github.com/pierrec/lz4/v4"
)

// AppendFrame appends a frame with size bytes of payload. The varint counts the opcode, the
// payload, and 4 for itself. The payload is pseudo-random bytes, the same for the same opcode
// and size; a constant fill would itself parse as frames.
func AppendFrame(b []byte, op0, op1 byte, size int) []byte {
	b = binary.AppendUvarint(b, uint64(2+size+4))
	b = append(b, op0, op1)
	x := uint32(op0)<<24 | uint32(op1)<<16 | uint32(size)<<1 | 1 // xorshift wants it nonzero
	for range size {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b = append(b, byte(x))
	}
	return b
}

func AppendBundle(b, plain []byte) []byte {
	return appendBundle(b, nil, plain)
}

// AppendFlagged puts a flag byte from F0 to FE before the bundle.
func AppendFlagged(b []byte, flag byte, plain []byte) []byte {
	return appendBundle(b, []byte{flag}, plain)
}

func appendBundle(b, flag, plain []byte) []byte {
	block := make([]byte, lz4.CompressBlockBound(len(plain)))
	n, err := lz4.CompressBlock(plain, block, nil)
	if err != nil {
		panic(err) // cannot happen: block has room for the worst case
	}
	body := slices.Concat(flag, []byte{0xFF, 0xFF}, binary.LittleEndian.AppendUint32(nil, uint32(len(plain))), block[:n])
	b = binary.AppendUvarint(b, uint64(len(body)+4))
	return append(b, body...)
}

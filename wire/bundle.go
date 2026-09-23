package wire

import (
	"encoding/binary"
	"slices"

	"github.com/pierrec/lz4/v4"
)

const (
	maxDepth  = 4       // maximum number of nesting levels
	maxPlain  = 8000000 // plaintext, all levels together
	minBundle = 7       // FF FF, the size, and a block of at least a byte
	maxGrowth = 255     // the most LZ4 can grow a block: a byte of match length says 255 more
)

// unwrap opens FF FF | u32le size | lz4 block and parses the frames inside.
// It reports whether the block held exactly size bytes.
//
// Plaintext goes on a stack, so maxPlain bounds every level at once.
// When the stack grows it moves, and a parent mid-walk still has its bytes where they were.
// A size the block could never give is garbage, and is refused before anything is allocated for it.
func (f *framer) unwrap(body []byte, depth int, flags Flags) bool {
	var size uint32
	if len(body) >= minBundle {
		size = binary.LittleEndian.Uint32(body[2:])
	}
	if depth >= maxDepth || size == 0 || uint64(size) > maxGrowth*uint64(len(body)-6) || size > uint32(maxPlain-len(f.plain)) {
		f.log.Warn("bundle refused", "size", size, "depth", depth)
		return false
	}

	var base = len(f.plain)
	f.plain = slices.Grow(f.plain, int(size))[:base+int(size)]
	out := f.plain[base:]
	n, err := lz4.UncompressBlock(body[6:], out)
	if err != nil || n != int(size) {
		f.log.Warn("bundle corrupt", "size", size, "got", n, "err", err)
		f.plain = f.plain[:base]
		return false
	}

	f.walk(out, depth+1, flags|WasLZ4|WasBundled)
	f.plain = f.plain[:base]
	return true
}

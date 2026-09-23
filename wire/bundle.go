package wire

import (
	"encoding/binary"
	"slices"

	"github.com/pierrec/lz4/v4"
)

const (
	maxDepth  = 4       // nesting levels
	maxPlain  = 8000000 // plaintext across all nesting levels
	minBundle = 7       // FF FF, a u32 size, and a block of at least one byte
	maxGrowth = 255     // the largest ratio of LZ4 output to input
)

// unwrap decompresses FF FF | u32le size | lz4 block and parses the frames inside. It reports
// whether the block decompressed to exactly size bytes. The plaintext of every nesting level
// shares one stack, bounded by maxPlain; a parent's slice stays valid if the stack is
// reallocated. A size the block cannot produce is refused before anything is allocated.
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

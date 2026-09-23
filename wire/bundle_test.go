package wire

import (
	"encoding/binary"
	"fmt"
	"slices"
	"testing"

	"github.com/nuriland/a2kit/internal/wiretest"
)

func three() []byte {
	return slices.Concat(
		wiretest.AppendFrame(nil, 0x04, 0x38, 41),
		wiretest.AppendFrame(nil, 0x2A, 0x38, 16),
		[]byte{0},
		wiretest.AppendFrame(nil, 0x1B, 0x92, 200),
	)
}

const threeWant = "04 38 len=41 lz4,bundled\n" +
	"2A 38 len=16 lz4,bundled\n" +
	"1B 92 len=200 lz4,bundled\n"

func TestBundle(t *testing.T) {
	d := NewDecoder(Config{})
	feed(d, wiretest.AppendBundle(nil, three()))
	expect(t, d, threeWant)
}

// A flag byte from F0 to FE may come before the FF FF.
func TestFlagged(t *testing.T) {
	d := NewDecoder(Config{})
	feed(d, wiretest.AppendFlagged(nil, 0xF2, three()))
	expect(t, d, threeWant)
}

func TestNested(t *testing.T) {
	inner := slices.Concat(wiretest.AppendFrame(nil, 0x05, 0x38, 20), wiretest.AppendFrame(nil, 0x44, 0x36, 12))
	plain := wiretest.AppendBundle(wiretest.AppendFrame(nil, 0x04, 0x38, 8), inner)
	d := NewDecoder(Config{})
	feed(d, wiretest.AppendBundle(nil, plain))
	expect(t, d, "04 38 len=8 lz4,bundled\n05 38 len=20 lz4,bundled\n44 36 len=12 lz4,bundled\n")
}

func TestDepth(t *testing.T) {
	for depth, want := range map[int]string{4: "04 38 len=3 lz4,bundled\n", 5: ""} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			p := wiretest.AppendFrame(nil, 0x04, 0x38, 3)
			for range depth {
				p = wiretest.AppendBundle(nil, p)
			}
			d := NewDecoder(Config{})
			feed(d, p)
			expect(t, d, want)
		})
	}
}

func TestBrokenBundle(t *testing.T) {
	good := wiretest.AppendBundle(nil, wiretest.AppendFrame(nil, 0x04, 0x38, 3))
	size := 1 + 2 // the size field, past the varint and FF FF
	if good[0] >= 0x80 {
		size++
	}
	breaks := map[string]func(b []byte){
		"size 0":     func(b []byte) { clear(b[size : size+4]) },
		"too big":    func(b []byte) { b[size+3] = 0x7F },
		"corrupt":    func(b []byte) { b[len(b)-1] ^= 0xFF; b[size]++ },
		"size short": func(b []byte) { b[size]++ },
	}
	for name, spoil := range breaks {
		t.Run(name, func(t *testing.T) {
			bad := slices.Clone(good)
			spoil(bad)
			d := NewDecoder(Config{})
			feed(d, bad)
			feed(d, wiretest.AppendFrame(nil, 0x05, 0x38, 1))
			expect(t, d, "05 38 len=1 -\n")
		})
	}
}

// A size the block cannot produce is refused without allocating, and a block that compresses
// that well still opens.
func TestBundleSize(t *testing.T) {
	d := NewDecoder(Config{})
	feed(d, []byte{0x0D, 0xFF, 0xFF, 0x00, 0x00, 0x7A, 0x00, 1, 2, 3, 4, 5, 6}) // 8 MB, from a 3-byte block
	if st := d.streams[key{src: srv, dst: cli}]; cap(st.fr.plain) != 0 {
		t.Errorf("%d bytes set aside for it", cap(st.fr.plain))
	}

	zeros := slices.Concat(binary.AppendUvarint(nil, 2+60000+4), []byte{0x04, 0x38}, make([]byte, 60000))
	b := wiretest.AppendBundle(nil, zeros)
	d = NewDecoder(Config{})
	feed(d, b)
	expect(t, d, "04 38 len=60000 lz4,bundled\n")
	t.Logf("%d bytes from a %d-byte block, %.0f times", len(zeros), len(b)-9, float64(len(zeros))/float64(len(b)-9))
}

// An FF FF body too short to be a bundle is dropped, and an untrusted stream does not take it for
// one.
func TestShortBundle(t *testing.T) {
	short := []byte{0x07, 0xFF, 0xFF, 0x00}
	d := NewDecoder(Config{})
	tick := wiretest.AppendFrame(nil, 0x00, 0x36, 2)
	feed(d, slices.Concat(tick, tick, short, wiretest.AppendFrame(nil, 0x05, 0x38, 1)))
	expect(t, d, "00 36 len=2 -\n00 36 len=2 -\n05 38 len=1 -\n")

	d = NewDecoder(Config{})
	feed(d, slices.Concat(short, wiretest.AppendFrame(nil, 0x05, 0x38, 1)))
	expect(t, d, "05 38 len=1 resynced\n")
}

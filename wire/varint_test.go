package wire

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestUvarint(t *testing.T) {
	tests := []struct {
		hex   string
		v     uint32
		width int
	}{
		{"00", 0, 1},
		{"7f", 127, 1},
		{"80 01", 128, 2},
		{"ff ff 03", 65535, 3},
		{"ff ff ff ff 0f", 0xFFFFFFFF, 5},
		{"80 80 80 80 80 01", 0, -1}, // six bytes
		{"ff ff ff ff 1f", 0, -1},    // past 32 bits
		{"80 00", 0, -1},             // not minimal
		{"80 80", 0, 0},              // cut short: wait for more
	}
	for _, tt := range tests {
		p, err := hex.DecodeString(strings.ReplaceAll(tt.hex, " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		if v, width := uvarint(p); v != tt.v || width != tt.width {
			t.Errorf("uvarint(%s) = %d, %d; want %d, %d", tt.hex, v, width, tt.v, tt.width)
		}
	}
}

func TestUvarintRoundTrip(t *testing.T) {
	for v := uint64(0); v <= 0xFFFFFFFF; v = v*3 + 1 {
		p := binary.AppendUvarint(nil, v)
		if got, width := uvarint(p); uint64(got) != v || width != len(p) {
			t.Errorf("uvarint(% x) = %d, %d; want %d, %d", p, got, width, v, len(p))
		}
	}
}

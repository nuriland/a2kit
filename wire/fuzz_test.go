package wire

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nuriland/a2kit/internal/wiretest"
)

func FuzzFeed(f *testing.F) {
	paths, _ := filepath.Glob("testdata/*.bin")
	for _, path := range paths {
		p, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(p, uint8(7))
	}
	f.Fuzz(func(t *testing.T, p []byte, piece uint8) {
		var (
			d = NewDecoder(Config{})
			n = 1 + int(piece)
		)
		for len(p) > 0 {
			k := min(len(p), n)
			feed(d, p[:k])
			p = p[k:]
		}
		for _, st := range d.streams {
			if len(st.fr.buf) > maxBuf+3 || len(st.fr.plain) != 0 {
				t.Fatalf("stream holds %d bytes, %d of plaintext", len(st.fr.buf), len(st.fr.plain))
			}
		}
		for fr := range d.Frames() {
			if len(fr.Payload) > maxFrame {
				t.Fatalf("a payload of %d bytes", len(fr.Payload))
			}
		}
	})
}

func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte{0x05, 0x04, 0x38, 0x13, 0x33, 0x36, 0x02, 0, 0, 0x27, 0x05, 0x38}, uint8(7), false)
	f.Add([]byte{0xFF, 0x2A, 0x38, 0x01, 0x12, 0x34, 0x83, 0x00, 0x92, 0x10, 0xF2, 0xFF}, uint8(200), true)
	f.Fuzz(func(t *testing.T, spec []byte, piece uint8, inEnvelopes bool) {
		var (
			stream = wiretest.AppendFrame(nil, 0x00, 0x36, 0)
			want   = []string{"00 36 "}
		)
		frame := func(b []byte, op0, op1 byte, size int) []byte {
			f := wiretest.AppendFrame(nil, op0, op1, size)
			want = append(want, fmt.Sprintf("%02X %02X %x", op0, op1, f[len(f)-size:]))
			return append(b, f...)
		}
		for ; len(spec) >= 3; spec = spec[3:] {
			kind, op0, op1 := spec[0], spec[1], spec[2]
			if op1 == 0xFF {
				op1 = 0x38 // FF there begins a bundle
			}
			size := int(kind>>2) * 37
			switch kind & 3 {
			case 0, 1:
				stream = frame(stream, op0, op1, size)
			case 2:
				stream = append(stream, make([]byte, 1+int(op0)%3)...) // padding
			case 3:
				var plain []byte
				for j := range 1 + int(op0)%3 {
					plain = frame(plain, op0+byte(j), op1, size/(j+1))
				}
				stream = wiretest.AppendBundle(stream, plain)
			}
		}
		if inEnvelopes {
			size := 8 + int(piece)*13
			if r := len(stream) % size; r > 0 && r < minEnvelope {
				stream = append(stream, make([]byte, minEnvelope-r)...) // padding, so no envelope is too short to believe
			}
			stream = enveloped(stream, size)
		}

		d := NewDecoder(Config{ParseTLS: true}) // TLS is judged per segment, and these are not segments
		x := uint32(piece)
		for p := stream; len(p) > 0; {
			x = x*1664525 + 1013904223
			n := 1 + int(x>>16)%8
			if x&(1<<31) != 0 {
				n = 1 + int(x>>16)%1500
			}
			n = min(n, len(p))
			feed(d, p[:n])
			p = p[n:]
		}
		var got []string
		for f := range d.Frames() {
			op := f.Opcode.Bytes()
			got = append(got, fmt.Sprintf("%02X %02X %x", op[0], op[1], f.Payload))
		}
		if !slices.Equal(got, want) {
			t.Fatalf("%d frames out, %d in; first difference at %d", len(got), len(want), firstDiff(got, want))
		}
	})
}

func firstDiff(a, b []string) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

package main

import (
	"cmp"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/nuriland/a2kit/wire"
)

const (
	samples = 8  // how many frames it prints whole
	shown   = 32 // how many positions of a payload bytes prints
)

// bytes prints one opcode's payloads
func (s *session) bytes(w io.Writer, op wire.Opcode) {
	var frames []wire.Frame
	for _, f := range s.frames {
		if f.Opcode == op {
			frames = append(frames, f)
		}
	}
	if len(frames) == 0 {
		fmt.Fprintf(w, "%v: no frames\n", op)
		return
	}

	var (
		longest = 0
		bySize  = make(map[int]int)
	)
	for _, f := range frames {
		bySize[len(f.Payload)]++
		longest = max(longest, len(f.Payload))
	}
	fmt.Fprintf(w, "%v: %d frames, payload %s\n", op, len(frames), sizes(bySize))

	for p := range min(longest, shown) {
		counts := make(map[byte]int)
		for _, f := range frames {
			if p < len(f.Payload) {
				counts[f.Payload[p]]++
			}
		}
		fmt.Fprintf(w, "  byte %2d: %s\n", p, values(counts))
	}
	if longest > shown {
		fmt.Fprintf(w, "  and %d more\n", longest-shown)
	}

	fmt.Fprintf(w, "first varint: %s\n", shared(s.frames, op))
	fmt.Fprintln(w, "first frames:")
	for _, f := range frames[:min(len(frames), samples)] {
		fmt.Fprintf(w, "  %s  %s\n", s.since(f.Time), payload(f.Payload))
	}
}

// value is one byte a position took, and how often
type value struct {
	b byte
	n int
}

// share is another opcode, and how many of the first varint's values it also begins with
type share struct {
	op wire.Opcode
	n  int
}

func values(counts map[byte]int) string {
	var vs []value
	for b, n := range counts {
		vs = append(vs, value{b, n})
	}

	slices.SortFunc(vs, func(a, b value) int { return cmp.Or(cmp.Compare(b.n, a.n), cmp.Compare(a.b, b.b)) })
	var parts []string
	for _, v := range vs[:min(len(vs), 3)] {
		parts = append(parts, fmt.Sprintf("%02x x%d", v.b, v.n))
	}
	if len(vs) > 3 {
		return fmt.Sprintf("%d values: %s, ...", len(vs), strings.Join(parts, ", "))
	}
	return strings.Join(parts, ", ")
}

// shared tells how many values the varint that begins op's payloads takes, and which other opcodes in all begin with some of them
func shared(all []wire.Frame, op wire.Opcode) string {
	begins := make(map[wire.Opcode]map[uint64]bool)
	for _, f := range all {
		v, n := binary.Uvarint(f.Payload)
		if n <= 0 {
			continue
		}
		if begins[f.Opcode] == nil {
			begins[f.Opcode] = make(map[uint64]bool)
		}
		begins[f.Opcode][v] = true
	}

	ids := begins[op]
	if len(ids) == 0 {
		return "none"
	}

	var shares []share
	for o, theirs := range begins {
		n := 0
		for v := range theirs {
			if ids[v] {
				n++
			}
		}
		if o != op && n > 0 {
			shares = append(shares, share{o, n})
		}
	}
	if len(shares) == 0 {
		return counted(len(ids)) + ", shared with no other opcode"
	}

	slices.SortFunc(shares, func(a, b share) int { return cmp.Or(cmp.Compare(b.n, a.n), cmp.Compare(a.op, b.op)) })
	var parts []string
	for _, sh := range shares[:min(len(shares), 8)] {
		parts = append(parts, fmt.Sprintf("%v (%d)", sh.op, sh.n))
	}
	if len(shares) > 8 {
		parts = append(parts, "...")
	}
	return fmt.Sprintf("%s, shared with %s", counted(len(ids)), strings.Join(parts, ", "))
}

func counted(n int) string {
	if n == 1 {
		return "1 value"
	}
	return fmt.Sprintf("%d values", n)
}

// payload is the first bytes of p in hex, "00 00 00 e0 26 a8 00"
func payload(p []byte) string {
	s := fmt.Sprintf("% x", p[:min(len(p), shown)])
	if len(p) > shown {
		s += " ..."
	}
	return s
}

// parseOpcode reads an opcode in wire order, "01 38"
func parseOpcode(s string) (wire.Opcode, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil || len(b) != 2 {
		return 0, fmt.Errorf("-op %q: not two hex bytes like \"01 38\"", s)
	}
	return wire.Opcode(uint16(b[0]) | uint16(b[1])<<8), nil
}

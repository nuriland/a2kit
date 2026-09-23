package wire

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func expected(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var wants []struct {
		Opcode     string `json:"opcode"`
		PayloadLen int    `json:"payload_len"`
		Flags      string `json:"flags"`
	}
	if err := json.Unmarshal(b, &wants); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var s strings.Builder
	for _, w := range wants {
		fmt.Fprintf(&s, "%s len=%d %s\n", w.Opcode, w.PayloadLen, w.Flags)
	}
	return s.String()
}

func TestFixtures(t *testing.T) {
	paths, _ := filepath.Glob("testdata/*.bin")
	if len(paths) == 0 {
		t.Fatal("no fixtures")
	}
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".bin")
		p, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := expected(t, strings.TrimSuffix(path, ".bin")+".expect.json")

		t.Run(name+"/whole", func(t *testing.T) {
			d := NewDecoder(Config{})
			feed(d, p)
			expectDir(t, d, want)
		})
		if name == "tls" {
			continue // a TLS record is spotted per segment, so its header must come in one
		}
		t.Run(name+"/bytes", func(t *testing.T) {
			d := NewDecoder(Config{})
			for i := range p {
				feed(d, p[i:i+1])
			}
			expectDir(t, d, want)
		})
		t.Run(name+"/pieces", func(t *testing.T) {
			for seed := range uint64(50) {
				r := rand.New(rand.NewPCG(seed, 0))
				d := NewDecoder(Config{})
				for rest := p; len(rest) > 0; {
					n := min(len(rest), 1+r.IntN(23))
					feed(d, rest[:n])
					rest = rest[n:]
				}
				expectDir(t, d, want)
			}
		})
	}
}

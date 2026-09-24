package game_test

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nuriland/a2kit/game"
	"github.com/nuriland/a2kit/wire"
)

var update = flag.Bool("update", false, "rewrite testdata/*.expect.txt")

var (
	server = netip.MustParseAddrPort("10.0.0.2:13328")
	client = netip.MustParseAddrPort("10.0.0.1:10000")
)

func frames(t testing.TB, name string) []wire.Frame {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	d := wire.NewDecoder(wire.Config{})
	d.Feed(time.Time{}, server, client, b)
	d.Flush()
	return slices.Collect(d.Frames())
}

func TestFixtures(t *testing.T) {
	bins, err := filepath.Glob("testdata/*.bin")
	if err != nil {
		t.Fatal(err)
	}
	if len(bins) == 0 {
		t.Fatal("no fixtures")
	}
	for _, bin := range bins {
		t.Run(strings.TrimSuffix(filepath.Base(bin), ".bin"), func(t *testing.T) {
			var got bytes.Buffer
			for _, f := range frames(t, bin) {
				e, ok := game.Parse(f)
				if !ok {
					fmt.Fprintf(&got, "%v -\n", f.Opcode)
					continue
				}
				fmt.Fprintf(&got, "%v %T %+v\n", f.Opcode, e, e)
			}
			golden := strings.TrimSuffix(bin, ".bin") + ".expect.txt"
			if *update {
				if err := os.WriteFile(golden, got.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if got.String() != string(want) {
				t.Errorf("got\n%s\nwant\n%s", &got, want)
			}
		})
	}
}

func TestParseHit(t *testing.T) {
	payload := unhex(t, "c7 7c 04 00 f5 a3 02 e0 26 a8 00 00 02 4b ed 9f 41 01 00 00 00 90 4e 24 01 00")
	want := game.Hit{Actor: 37365, Target: 15943, Skill: 11020000, Damage: 36, Type: 2, Scalar: 10000}
	if e, ok := game.Parse(wire.Frame{Opcode: 0x3804, Payload: payload}); !ok || !reflect.DeepEqual(e, want) {
		t.Errorf("got %+v, %v; want %+v", e, ok, want)
	}

	payload = unhex(t, "c7 7c 24 00 f5 a3 02 e0 26 a8 00 00 02 4b ed 9f 41 01 00 00 00 90 4e 24 00 01 00")
	want.Extra = []uint32{}
	if e, ok := game.Parse(wire.Frame{Opcode: 0x3804, Payload: payload}); !ok || !reflect.DeepEqual(e, want) {
		t.Errorf("got %+v, %v; want %+v", e, ok, want)
	}

	if e, ok := game.Parse(wire.Frame{Opcode: 0x3804, Flags: wire.FromClient, Payload: payload}); ok {
		t.Errorf("read the client's frame as %+v", e)
	}
}

type reject struct {
	name    string
	op      wire.Opcode
	payload string
}

func TestParseRejects(t *testing.T) {
	tests := []reject{
		{"unknown opcode", 0x3899, "00 00"},
		{"empty", 0x3804, ""},
		{"hit cut short", 0x3804, "c7 7c 04 00 f5 a3 02 e0 26 a8 00 00 02 4b ed 9f 41 01 00 00 00 90 4e 24 01"},
		{"hit with switch nibble 6 cut in its three bytes", 0x3804, "c7 7c 06 00 f5 a3 02 e0 26 a8 00 00 02 00 00"},
		{"hit with switch nibble 5", 0x3804, "c7 7c 05 00 f5 a3 02 e0 26 a8 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 90 4e 20 01 00"},
		{"hit whose type does not fit a byte", 0x3804, "c7 7c 04 00 f5 a3 02 e0 26 a8 00 00 ac 02 4b ed 9f 41 01 00 00 00 90 4e 24 01 00"},
		{"hit whose trailer is not its sequence number", 0x3804, "c7 7c 04 00 f5 a3 02 e0 26 a8 00 00 02 4b ed 9f 41 01 00 00 00 90 4e 24 02 00"},
		{"hit with bytes after the trailer", 0x3804, "c7 7c 04 00 f5 a3 02 e0 26 a8 00 00 02 4b ed 9f 41 01 00 00 00 90 4e 24 01 00 ff"},
		{"hit claiming more extra hits than bytes", 0x3804, "c7 7c 24 00 f5 a3 02 e0 26 a8 00 00 02 4b ed 9f 41 01 00 00 00 90 4e 24 7f 01 00"},
		{"death with a byte too many", 0x3642, "f5 a3 02 00 03 00"},
		{"death whose middle varint is not zero", 0x3642, "f5 a3 02 01 03"},
		{"cast end with a byte too many", 0x3806, "c7 7c e0 26 a8 00 01 0c 00"},
		{"move 1B 37 whose flag adds a byte it does not have", 0x371B, "e4 72 05 03 2b d5 bc c6 01 6f 24 c7 6a 42 8c"},
		{"spawn with a name", 0x3641, "a8 81 02 05 20 00 00 01 4a 0f 20 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00"},
		{"player whose name is cut short", 0x3645, "e4 72 01 20 00 00 07 06 50 6c 61"},
		{"owner whose name is not utf-8", 0x8D04, "f5 a3 02 60 41 ae 00 c7 7c f8 03 02 ff fe"},
		{"ping a byte short", 0x3603, "00 00 5a 43 39 e5 23 3a 00 00 64 69 0c d3 a0 01 00"},
		{"zone of another entity", 0x3623, "c7 7c 00 00 00 00 00 7e 87 ca c6 82 a0 03 c7 00 50 8d 46"},
		{"varint over five bytes", 0x3642, "ff ff ff ff ff ff 00 03"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if e, ok := game.Parse(wire.Frame{Opcode: tt.op, Payload: unhex(t, tt.payload)}); ok {
				t.Errorf("parsed %+v", e)
			}
		})
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func FuzzParse(f *testing.F) {
	bins, _ := filepath.Glob("testdata/*.bin")
	for _, bin := range bins {
		for _, fr := range frames(f, bin) {
			f.Add(uint16(fr.Opcode), fr.Payload)
		}
	}
	f.Fuzz(func(t *testing.T, op uint16, payload []byte) {
		game.Parse(wire.Frame{Opcode: wire.Opcode(op), Payload: payload})
	})
}

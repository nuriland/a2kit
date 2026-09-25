package game_test

import (
	"bytes"
	"encoding/hex"
	"errors"
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
				e, err := game.Parse(f)
				if err != nil {
					fmt.Fprintf(&got, "%v %v\n", f.Opcode, err)
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
	if e, err := game.Parse(wire.Frame{Opcode: 0x3804, Payload: payload}); err != nil || !reflect.DeepEqual(e, want) {
		t.Errorf("got %+v, %v; want %+v", e, err, want)
	}

	payload = unhex(t, "c7 7c 24 00 f5 a3 02 e0 26 a8 00 00 02 4b ed 9f 41 01 00 00 00 90 4e 24 00 01 00")
	want.Extra = []uint32{}
	if e, err := game.Parse(wire.Frame{Opcode: 0x3804, Payload: payload}); err != nil || !reflect.DeepEqual(e, want) {
		t.Errorf("got %+v, %v; want %+v", e, err, want)
	}

	if e, err := game.Parse(wire.Frame{Opcode: 0x3804, Flags: wire.FromClient, Payload: payload}); !errors.Is(err, game.ErrUnread) {
		t.Errorf("read the client's frame as %+v, %v", e, err)
	}
}

// reject is a frame Parse refuses, and with which error.
type reject struct {
	name    string
	op      wire.Opcode
	payload string
	want    error
}

func TestParseRejects(t *testing.T) {
	tests := []reject{
		{"unknown opcode", 0x3899, "00 00", game.ErrUnread},
		{"empty", 0x3804, "", game.ErrLayout},
		{"hit cut short", 0x3804, "c7 7c 04 00 f5 a3 02 e0 26 a8 00 00 02 4b ed 9f 41 01 00 00 00 90 4e 24 01", game.ErrLayout},
		{"hit with switch nibble 6 cut in its three bytes", 0x3804, "c7 7c 06 00 f5 a3 02 e0 26 a8 00 00 02 00 00", game.ErrLayout},
		{"hit with switch nibble 5", 0x3804, "c7 7c 05 00 f5 a3 02 e0 26 a8 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 90 4e 20 01 00", game.ErrUnread},
		{"hit whose type does not fit a byte", 0x3804, "c7 7c 04 00 f5 a3 02 e0 26 a8 00 00 ac 02 4b ed 9f 41 01 00 00 00 90 4e 24 01 00", game.ErrLayout},
		{"hit whose trailer is not its sequence number", 0x3804, "c7 7c 04 00 f5 a3 02 e0 26 a8 00 00 02 4b ed 9f 41 01 00 00 00 90 4e 24 02 00", game.ErrLayout},
		{"hit with bytes after the trailer", 0x3804, "c7 7c 04 00 f5 a3 02 e0 26 a8 00 00 02 4b ed 9f 41 01 00 00 00 90 4e 24 01 00 ff", game.ErrLayout},
		{"hit claiming more extra hits than bytes", 0x3804, "c7 7c 24 00 f5 a3 02 e0 26 a8 00 00 02 4b ed 9f 41 01 00 00 00 90 4e 24 7f 01 00", game.ErrLayout},
		{"death with a byte too many", 0x3642, "f5 a3 02 00 03 00", game.ErrLayout},
		{"death whose middle varint is not zero", 0x3642, "f5 a3 02 01 03", game.ErrLayout},
		{"cast without a position", 0x3802, "e4 72 00 d8 62 d6 00 0b 00 e4 72 6d d9 90 43 90 4e 01 00", game.ErrUnread},
		{"cast end with a byte too many", 0x3806, "c7 7c e0 26 a8 00 01 0c 00", game.ErrLayout},
		{"move 1B 37 whose flag adds a byte it does not have", 0x371B, "e4 72 05 03 2b d5 bc c6 01 6f 24 c7 6a 42 8c", game.ErrLayout},
		{"spawn with a name", 0x3641, "a8 81 02 05 20 00 00 01 4a 0f 20 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00", game.ErrUnread},
		{"player whose name is cut short", 0x3645, "e4 72 01 20 00 00 07 06 50 6c 61", game.ErrLayout},
		{"owner whose name is not utf-8", 0x8D04, "f5 a3 02 60 41 ae 00 c7 7c f8 03 02 ff fe", game.ErrLayout},
		{"ping a byte short", 0x3603, "00 00 5a 43 39 e5 23 3a 00 00 64 69 0c d3 a0 01 00", game.ErrLayout},
		{"zone of another entity", 0x3623, "c7 7c 00 00 00 00 00 7e 87 ca c6 82 a0 03 c7 00 50 8d 46", game.ErrLayout},
		{"varint over five bytes", 0x3642, "ff ff ff ff ff ff 00 03", game.ErrLayout},
		{"an opcode met but not read", 0x3805, "c7 7c 02 f5 a3 02 00 e0 26 a8 00 24", game.ErrUnread},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := game.Parse(wire.Frame{Opcode: tt.op, Payload: unhex(t, tt.payload)})
			if !errors.Is(err, tt.want) {
				t.Errorf("got %+v, %v; want %v", e, err, tt.want)
			}
		})
	}
}

func TestParseOffset(t *testing.T) {
	check := func(op wire.Opcode, payload, want string) {
		t.Helper()
		_, err := game.Parse(wire.Frame{Opcode: op, Payload: unhex(t, payload)})
		if err == nil || err.Error() != want {
			t.Errorf("%v: got %v; want %s", op, err, want)
		}
	}
	check(0x3804, "c7 7c 04 00 f5 a3 02 e0 26 a8 00 00 02 4b ed 9f 41 01 00 00 00 90 4e 24 01", "game: off the layout at byte 25 of 25")
	check(0x3641, "a8 81 02 05 20 00 00 00 4a 0f", "game: off the layout at byte 8 of 10") // cut inside NPC; the reads after it must not move the byte
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

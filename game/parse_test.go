package game_test

import (
	"bytes"
	"encoding/binary"
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
	d := wire.NewDecoder(wire.Config{EmitUnlocked: true})
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

// The byte before every fourth server's Status holds two bits a server, and its faction is read.
func TestParseServers(t *testing.T) {
	payload := unhex(t, "00 00 03"+
		" 15 05 01 15 05 00 00 03 4c 5f 31 15 04 4c 1d ad 0c 00 00 50 01 00"+
		" 1d 05 01 1d 05 00 00 03 4c 5f 39 02 d0 07 34 02 00 00 50 01 00"+
		" fd 08 02 fd 08 00 00 03 44 5f 31 04 40 1f 67 0e 00 00 50 01 00"+
		" 01 01")
	want := game.Servers{List: []game.Server{
		{ID: 1301, Name: "L_1", Faction: 1, Mask: 1, Status: game.StatusRestricted, Players: 3245, Capacity: 7500},
		{ID: 1309, Name: "L_9", Faction: 1, Mask: 1, Status: game.StatusRecommended, Players: 564, Capacity: 2000},
		{ID: 2301, Name: "D_1", Faction: 2, Mask: 1, Status: game.StatusRestricted, Players: 3687, Capacity: 8000},
	}}
	e, err := game.Parse(wire.Frame{Opcode: 0x3909, Payload: payload})
	if err != nil || !reflect.DeepEqual(e, want) {
		t.Fatalf("got %#v, %v; want %#v", e, err, want)
	}
	if s := fmt.Sprint(e.(game.Servers).List); s != "[1301:L_1 3245/7500 restricted 1309:L_9 564/2000 recommended 2301:D_1 3687/8000 restricted]" {
		t.Errorf("printed %s", s)
	}
}

// Since October 2026 a server carries one load byte where its capacity and players were
func TestParseServersLoad(t *testing.T) {
	payload := unhex(t, "00 00 03"+
		" 15 05 01 15 05 00 00 03 4c 5f 31 15 04 28 50 01 00"+
		" 1e 05 01 1e 05 00 00 04 4c 5f 31 30 03 0a 50 01 00"+
		" fd 08 02 fd 08 00 00 03 44 5f 31 04 34 50 01 00"+
		" 01 01")
	want := game.Servers{List: []game.Server{
		{ID: 1301, Name: "L_1", Faction: 1, Mask: 1, Status: game.StatusRestricted, Load: 40},
		{ID: 1310, Name: "L_10", Faction: 1, Mask: 1, Status: game.StatusNew | game.StatusRecommended, Load: 10},
		{ID: 2301, Name: "D_1", Faction: 2, Mask: 1, Status: game.StatusRestricted, Load: 52},
	}}
	e, err := game.Parse(wire.Frame{Opcode: 0x3909, Payload: payload})
	if err != nil || !reflect.DeepEqual(e, want) {
		t.Fatalf("got %#v, %v; want %#v", e, err, want)
	}
	if s := fmt.Sprint(e.(game.Servers).List); s != "[1301:L_1 40% restricted 1310:L_10 10% new recommended 2301:D_1 52% restricted]" {
		t.Errorf("printed %s", s)
	}
}

func TestParseCharacters(t *testing.T) {
	fs := frames(t, "testdata/characters.bin")
	if len(fs) != 1 {
		t.Fatalf("%d frames, want 1", len(fs))
	}

	e, err := game.Parse(fs[0])
	if err != nil {
		t.Fatal(err)
	}

	list := e.(game.Characters).List
	if len(list) != 17 {
		t.Fatalf("%d characters, want 17", len(list))
	}

	for _, tt := range []struct {
		i    int
		want game.Character
	}{
		{0, game.Character{Server: 1301, Name: "Axxx", Level: 3, Code: 6, Flags: 1, Time: time.Date(2026, time.October, 1, 19, 1, 32, 417e6, time.UTC)}},
		{1, game.Character{Server: 1301, Name: "Bxx", Level: 3, Code: 17, Flags: 1, Time: time.Date(2026, time.October, 1, 18, 58, 49, 923e6, time.UTC)}}, // after the first mask byte
		{6, game.Character{Server: 1303, Name: "Axxx", Level: 29, Exp: 3016813, Code: 14, Flags: 1, Time: time.Date(2026, time.October, 2, 18, 16, 3, 743e6, time.UTC)}},
		{16, game.Character{Server: 2307, Name: "$qqqqqqqqqqq", Level: 1, Code: 44, Flags: 2, Time: time.Date(2026, time.October, 1, 17, 48, 19, 820e6, time.UTC)}},
	} {
		if got := list[tt.i]; !reflect.DeepEqual(got, tt.want) {
			t.Errorf("character %d: got %#v\nwant %#v", tt.i, got, tt.want)
		}
	}
}

func characters(cs []game.Character) []byte {
	b := []byte{0, 0, byte(len(cs))}

	for i, c := range cs {
		b = binary.LittleEndian.AppendUint16(b, c.Server)
		b = append(append(b, byte(len(c.Name))), c.Name...)
		for _, v := range []uint32{c.Level, c.Exp, 0, c.Code} {
			b = binary.LittleEndian.AppendUint32(b, v)
		}
		b = append(b, c.Flags)
		b = binary.LittleEndian.AppendUint64(b, uint64(c.Time.UnixMilli()))
		b = append(b, make([]byte, 8)...)

		if i%4 == 0 {
			var mask byte
			for k, c := range cs[i:min(i+4, len(cs))] {
				mask |= c.Mask << (2 * k)
			}
			b = append(b, mask)
		}
	}
	return append(b, 1, 1)
}

func TestParseCharactersShapes(t *testing.T) {
	at := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)
	var (
		a     = game.Character{Server: 1301, Name: "Abcd", Level: 3, Code: 6, Flags: 1, Time: at}
		odd   = game.Character{Server: 1301, Name: "Bxxx", Level: 1, Code: 9, Flags: 3, Time: time.UnixMilli(0).UTC()}
		dark4 = game.Character{Server: 2304, Name: "Abcdefgh", Level: 1, Code: 6, Flags: 1, Time: at} // 2304 is 00 09
		kor   = game.Character{Server: 1302, Name: "누리", Level: 2, Code: 5, Flags: 1, Time: at}
		long  = game.Character{Server: 1303, Name: strings.Repeat("가", 11), Level: 4, Code: 7, Flags: 1, Time: at}
		none  = game.Character{Server: 2304, Level: 1, Code: 6, Flags: 1, Time: at}
		bits  = game.Character{Server: 1305, Name: "Cc", Level: 1, Code: 6, Flags: 1, Time: at, Mask: 2}
	)
	for _, tt := range []struct {
		name  string
		chars []game.Character
	}{
		{"none", nil},
		{"one", []game.Character{a}},
		{"odd flags and time", []game.Character{a, odd}},
		{"a server ending in 00 after the mask", []game.Character{a, dark4}},
		{"a server ending in 00 first", []game.Character{dark4, a}},
		{"a name in hangul", []game.Character{a, kor}},
		{"a name of 33 bytes", []game.Character{a, long, a}},
		{"an empty name on a server ending in 00", []game.Character{a, none}},
		{"a second group of one", []game.Character{a, kor, odd, long, dark4}},
		{"bits in the masks", []game.Character{bits, a, bits, a, a, bits}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e, err := game.Parse(wire.Frame{Opcode: 0x390B, Payload: characters(tt.chars)})
			if want := (game.Characters{List: append([]game.Character{}, tt.chars...)}); err != nil || !reflect.DeepEqual(e, want) {
				t.Errorf("got %v, %v\nwant %v", e, err, want)
			}
		})
	}
}

// Both tails of an account hold its server twice: the first form until some patch, the second since it, as in the capture of 10 October 2026.
func TestParseAccountTails(t *testing.T) {
	head := "00 00 00 01 41 01 00 00 03 31 3a 42 "
	for _, tt := range []struct {
		name, tail string
		server     uint16
		faction    byte
	}{
		{"four zeros then 03 09 03", "17 05 01 00 00 00 00 17 05 03 09 03", 1303, 1},
		{"six zeros then 03", "06 09 02 00 00 00 00 00 00 06 09 03", 2310, 2},
		{"the server 0903, which the first form holds as its constant", "03 09 02 00 00 00 00 00 00 03 09 03", 2307, 2},
	} {
		e, err := game.Parse(wire.Frame{Opcode: 0x3906, Payload: unhex(t, head+tt.tail)})
		want := game.Account{ID: "1", Server: tt.server, Faction: tt.faction, Session: [2]string{"A", "B"}}
		if err != nil || !reflect.DeepEqual(e, want) {
			t.Errorf("%s: got %+v, %v; want %+v", tt.name, e, err, want)
		}
	}
}

// The last group of four holds fewer, and its mask byte carries bits for those alone.
func TestParseServersGroups(t *testing.T) {
	payload := unhex(t, "00 00 06"+
		" 0e 09 02 0e 09 00 00 03 44 5f 31 55 05 13 50 01 00"+
		" 0f 09 02 0f 09 00 00 03 44 5f 32 01 10 50 01 00"+
		" 10 09 02 10 09 00 00 03 44 5f 33 01 0e 50 01 00"+
		" 11 09 02 11 09 00 00 03 44 5f 34 01 0d 50 01 00"+
		" 12 09 02 12 09 00 00 03 44 5f 35 05 01 0f 50 01 00"+
		" 13 09 02 13 09 00 00 03 44 5f 36 01 0e 50 01 00"+
		" 01 01")
	e, err := game.Parse(wire.Frame{Opcode: 0x3909, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	got := e.(game.Servers).List
	if len(got) != 6 {
		t.Fatalf("got %d servers", len(got))
	}
	for i, s := range got {
		if s.Mask != 1 || s.ID != uint16(2318+i) || s.Faction != 2 {
			t.Errorf("server %d: %+v", i, s)
		}
	}
	if s := fmt.Sprint(got); s != "[2318:D_1 19% new restricted 2319:D_2 16% new 2320:D_3 14% new 2321:D_4 13% new 2322:D_5 15% new 2323:D_6 14% new]" {
		t.Errorf("printed %s", s)
	}
}

func TestParseJoin(t *testing.T) {
	e, err := game.Parse(wire.Frame{Opcode: 0x390D, Payload: unhex(t, "00 00 00 06 09")})
	if want := (game.Join{Server: 2310}); err != nil || e != want {
		t.Errorf("got %+v, %v; want %+v", e, err, want)
	}
}

func TestRedirectAddr(t *testing.T) {
	for _, tt := range []struct {
		payload string
		host    string
		addr    string // "" when Addr fails
	}{
		{"00 00 18 05 07 31 2e 32 2e 33 2e 34 10 34", "1.2.3.4", "1.2.3.4:13328"},
		{"00 00 18 05 03 61 62 63 10 34", "abc", ""},
	} {
		e, err := game.Parse(wire.Frame{Opcode: 0x390F, Payload: unhex(t, tt.payload)})
		d, _ := e.(game.Redirect)
		if err != nil || d.Host != tt.host || d.Port != 13328 || d.Server != 1304 {
			t.Errorf("%s: got %+v, %v", tt.host, e, err)
			continue
		}
		if a, ok := d.Addr(); ok != (tt.addr != "") || ok && a.String() != tt.addr {
			t.Errorf("%s: Addr %v, %v; want %q", tt.host, a, ok, tt.addr)
		}
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
		{"name check without its trailing 01", 0x361A, "00 00 02 48 65", game.ErrLayout},
		{"name check whose trailer is not 01", 0x361A, "00 00 02 48 65 02", game.ErrLayout},
		{"name check with a byte too many", 0x361A, "00 00 02 48 65 01 00", game.ErrLayout},
		{"servers cut short in a server", 0x3909, "00 00 01 15 05 01 15 05 00 00", game.ErrLayout},
		{"servers whose second ID is not the first", 0x3909, "00 00 01 15 05 01 16 05 00 00 01 41 01 00 58 1b 46 09 00 00 50 01 00 01 01", game.ErrLayout},
		{"servers without its trailer", 0x3909, "00 00 01 15 05 01 15 05 00 00 01 41 01 00 58 1b 46 09 00 00 50 01 00", game.ErrLayout},
		{"account cut short", 0x3906, "00 00 00 02 41 42 01 00 00", game.ErrLayout},
		{"account whose first byte is not 0", 0x3906, "01 00 00 01 41 01 00 00 01 42 17 05 01 00 00 00 00 17 05 03 09 03", game.ErrLayout},
		{"characters cut short in a character", 0x390B, "00 00 01 15 05 01 41 03 00 00 00", game.ErrLayout},
		{"characters without its trailer", 0x390B, "00 00 01 15 05 01 41 03 00 00 00 00 00 00 00 00 00 00 00 06 00 00 00 01 81 e0 d7 f8 a0 01 00 00 00 00 00 00 00 00 00 00 00", game.ErrLayout},
		{"account whose Server is not repeated", 0x3906, "00 00 00 01 41 01 00 00 03 31 3a 42 17 05 01 00 00 00 00 18 05 03 09 03", game.ErrLayout},
		{"account of the newer form whose Server is not repeated", 0x3906, "00 00 00 01 41 01 00 00 03 31 3a 42 06 09 02 00 00 00 00 00 00 07 09 03", game.ErrLayout},
		{"account of the newer form cut before its 03", 0x3906, "00 00 00 01 41 01 00 00 03 31 3a 42 06 09 02 00 00 00 00 00 00 06 09", game.ErrLayout},
		{"account with a byte too many", 0x3906, "00 00 00 01 41 01 00 00 03 31 3a 42 06 09 02 00 00 00 00 00 00 06 09 03 00", game.ErrLayout},
		{"join cut short", 0x390D, "00 00 00 06", game.ErrLayout},
		{"join whose first bytes are not 0", 0x390D, "00 00 01 06 09", game.ErrLayout},
		{"join of server 0", 0x390D, "00 00 00 00 00", game.ErrLayout},
		{"join with a byte too many", 0x390D, "00 00 00 06 09 00", game.ErrLayout},
		{"account whose ID has no colon", 0x3906, "00 00 00 01 41 01 00 00 01 42 17 05 01 00 00 00 00 17 05 03 09 03", game.ErrLayout},
		{"characters whose trailer is not 01 01", 0x390B, "00 00 00 01 02", game.ErrLayout},
		{"characters on server 0", 0x390B, "00 00 01 00 00 01 41 03 00 00 00 00 00 00 00 00 00 00 00 06 00 00 00 01 81 e0 d7 f8 a0 01 00 00 00 00 00 00 00 00 00 00 00 01 01", game.ErrLayout},
		{"servers whose trailer is not 01 01", 0x3909, "00 00 00 01 00", game.ErrLayout},
		{"servers whose mask has bits past the end", 0x3909, "00 00 01 15 05 01 15 05 00 00 01 41 05 00 58 1b 46 09 00 00 50 01 00 01 01", game.ErrLayout},
		{"servers cut after a load byte", 0x3909, "00 00 01 15 05 01 15 05 00 00 01 41 01 00 28", game.ErrLayout},
		{"servers with a load byte on one and capacity and players on the next", 0x3909, "00 00 02 15 05 01 15 05 00 00 01 41 05 00 28 50 01 00 16 05 01 16 05 00 00 01 42 00 58 1b 46 09 00 00 50 01 00 01 01", game.ErrLayout},
		{"characters without the mask", 0x390B, "00 00 01 15 05 01 41 03 00 00 00 00 00 00 00 00 00 00 00 06 00 00 00 01 81 e0 d7 f8 a0 01 00 00 00 00 00 00 00 00 00 00 01 01", game.ErrLayout},
		{"characters whose mask has bits past the end", 0x390B, "00 00 01 15 05 01 41 03 00 00 00 00 00 00 00 00 00 00 00 06 00 00 00 01 81 e0 d7 f8 a0 01 00 00 00 00 00 00 00 00 00 00 04 01 01", game.ErrLayout},
		{"redirect to no host", 0x390F, "00 00 18 05 00 10 34", game.ErrLayout},
		{"redirect without a port", 0x390F, "00 00 18 05 07 31 2e 32 2e 33 2e 34", game.ErrLayout},
		{"redirect with a byte too many", 0x390F, "00 00 18 05 07 31 2e 32 2e 33 2e 34 10 34 00", game.ErrLayout},
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

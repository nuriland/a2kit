package a2log

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/nuriland/a2kit/wire"
)

func check[T any](t *testing.T, v T, want string) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
	var back T
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, v) {
		t.Errorf("read back %+v, want %+v", back, v)
	}
}

func TestRoundTrip(t *testing.T) {
	check(t, Header{Schema, "github.com/nuriland/a2kit@v0.1.0", Source{"pcap", "fight.pcap"}, time.Date(2026, 9, 23, 18, 0, 0, 123e6, time.UTC)},
		`{"schema":"a2log/v0.1","decoder":"github.com/nuriland/a2kit@v0.1.0","source":{"kind":"pcap","path":"fight.pcap"},"t0":"2026-09-23T18:00:00.123Z"}`)
	check(t, Header{Schema: Schema, Decoder: "github.com/nuriland/a2kit@(devel)", Source: Source{Kind: "live"}},
		`{"schema":"a2log/v0.1","decoder":"github.com/nuriland/a2kit@(devel)","source":{"kind":"live"}}`)
	check(t, Frame{51, 0x3804, wire.FromServer | wire.WasLZ4, server, client, []byte{1, 2, 3}},
		`{"t":51,"opcode":"04 38","flags":["server","lz4"],"src":"10.0.0.2:13328","dst":"10.0.0.1:10000","payload":"AQID"}`)
	check(t, Frame{-1, 0x3633, 0, server, client, []byte{}},
		`{"t":-1,"opcode":"33 36","flags":[],"src":"10.0.0.2:13328","dst":"10.0.0.1:10000","payload":""}`)
}

var (
	server = netip.MustParseAddrPort("10.0.0.2:13328")
	client = netip.MustParseAddrPort("10.0.0.1:10000")
)

func TestWire(t *testing.T) {
	t0 := time.Date(2026, 9, 23, 18, 0, 0, 123e6, time.UTC)
	f := wire.Frame{Time: t0.Add(-51 * time.Millisecond), Src: server, Dst: client, Opcode: 0x3804, Flags: wire.FromServer, Payload: []byte{1}}
	if got := NewFrame(f, t0).Wire(t0); !reflect.DeepEqual(got, f) {
		t.Errorf("got %+v, want %+v", got, f)
	}
	if got := NewFrame(wire.Frame{Time: t0}, t0); got.Payload == nil {
		t.Error("a frame without a payload logs it null")
	}
}

func TestReadRejects(t *testing.T) {
	var f Frame
	for _, line := range []string{
		`{"opcode":"0438"}`,
		`{"opcode":"04 3g"}`,
		`{"src":"10.0.0.2"}`,
		`{"flags":"server"}`,
	} {
		if err := json.Unmarshal([]byte(line), &f); err == nil {
			t.Errorf("read %s as %+v", line, f)
		}
	}
	if err := json.Unmarshal([]byte(`{"flags":["server","later"]}`), &f); err != nil || f.Flags != wire.FromServer {
		t.Errorf("a flag the reader does not know: got %v, %v", f.Flags, err)
	}
}

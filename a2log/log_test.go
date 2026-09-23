package a2log

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
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
	check(t, Frame{51, "04 38", []string{"server", "lz4"}, "10.0.0.2:13328", "10.0.0.1:10000", []byte{1, 2, 3}},
		`{"t":51,"opcode":"04 38","flags":["server","lz4"],"src":"10.0.0.2:13328","dst":"10.0.0.1:10000","payload":"AQID"}`)
	check(t, Frame{-1, "33 36", []string{}, "10.0.0.2:13328", "10.0.0.1:10000", []byte{}},
		`{"t":-1,"opcode":"33 36","flags":[],"src":"10.0.0.2:13328","dst":"10.0.0.1:10000","payload":""}`)
}

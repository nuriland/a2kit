package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type traced struct {
	Name string
	Ph   string
	TS   int64
	Dur  int64
	PID  int
	TID  uint32
	Args map[string]any
}

func timeline(t *testing.T, name string) []traced {
	t.Helper()

	var out bytes.Buffer
	if err := run(name, &out); err != nil {
		t.Fatal(err)
	}
	var tr struct {
		DisplayTimeUnit string
		TraceEvents     []traced
	}
	if err := json.Unmarshal(out.Bytes(), &tr); err != nil {
		t.Fatalf("%v in\n%s", err, &out)
	}
	return tr.TraceEvents
}

func fight(t *testing.T, lines ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString(`{"schema":"a2log/v0.1","decoder":"github.com/nuriland/a2kit@test","source":{"kind":"pcap","path":"fight.pcap"},"t0":"2026-09-23T18:00:00.123Z"}` + "\n")
	for _, l := range lines {
		var (
			ms                    int
			lo, hi, from, payload string
		)
		if _, err := fmt.Sscan(l, &ms, &lo, &hi, &from, &payload); err != nil {
			t.Fatalf("line %q: %v", l, err)
		}
		fmt.Fprintf(&b, `{"t":%d,"opcode":"%s %s","flags":[%q],"src":"10.0.0.2:13328","dst":"10.0.0.1:10000","payload":%q}`+"\n", ms, lo, hi, from, payload)
	}
	name := filepath.Join(t.TempDir(), "fight.jsonl")
	if err := os.WriteFile(name, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

// tracks lists the names of pid's tracks, in tid order.
func tracks(evs []traced, pid int) []string {
	var names []string
	for _, e := range evs {
		if e.Name == "thread_name" && e.PID == pid {
			names = append(names, e.Args["name"].(string))
		}
	}
	return names
}

func TestFight(t *testing.T) {
	evs := timeline(t, fight(t,
		"0 02 38 server x3wA4CaoAAAA9aMCAAAAAAAAAAAAAAAAAAAAAA==",   // 15943 casts Keen Strike
		"5 04 38 server x3wEAPWjAuAmqAAAAkvtn0EBAAAAkE4kAQA=",       // 37365 hits 15943
		"12 05 38 server x3wC9aMCAOAmqAAk",                          // unread
		"40 04 38 server x3wEAPWjAuAmqAAAAks=",                      // a hit cut short
		"100 02 38 server x3wA4CaoAAAA9aMCAAAAAAAAAAAAAAAAAAAAAA==", // cast again before the first ended
		"470 06 38 server x3zgJqgAAQw=",                             // the cast ends
		"480 02 38 server x3wA4CaoAAAA9aMCAAAAAAAAAAAAAAAAAAAAAA==", // and never ends
		"510 42 36 server x3wAAw==",                                 // 15943 dies
	))

	type span struct {
		Ph      string
		TS, Dur int64
	}
	var (
		errs  int
		casts []span
	)
	for _, e := range evs {
		switch {
		case e.PID == byOpcode && e.Args["error"] != nil:
			errs++
			if e.TS != 40_000 {
				t.Errorf("the hit cut short at %dµs, want 40000", e.TS)
			}
		case e.PID == byEntity && e.Name == "Cast" && e.TID == 15943:
			casts = append(casts, span{e.Ph, e.TS, e.Dur})
		}
	}
	if errs != 1 {
		t.Errorf("%d frames off the layout, want 1", errs)
	}
	if want := []span{{"i", 0, 0}, {"X", 100_000, 370_000}, {"i", 480_000, 0}}; !slices.Equal(casts, want) {
		t.Errorf("15943's casts %v, want %v", casts, want)
	}
	if want := []string{"42 36 Death", "02 38 Cast", "04 38 Hit", "05 38 DoT", "06 38 CastEnd"}; !slices.Equal(tracks(evs, byOpcode), want) {
		t.Errorf("opcode tracks %q, want %q", tracks(evs, byOpcode), want)
	}
	if want := []string{"entity 15943", "entity 37365"}; !slices.Equal(tracks(evs, byEntity), want) {
		t.Errorf("entity tracks %q, want %q", tracks(evs, byEntity), want)
	}
}

func TestNames(t *testing.T) {
	evs := timeline(t, fight(t,
		"0 45 36 server 5HIBIAAABwZQbGF5ZXI=",                 // 14692 is Player
		"1 04 8D server 9aMCYEGuAMd8+AMHUGxheWVyMg==",         // 37365 is owned by 15943, Player2
		"2 45 36 server x3wBIAAABg==",                         // 15943 again, without a name
		"3 41 36 server qIECBSAAAABKDyAAAAAAAAAAAAAAAAAAAAA=", // 32936 spawns as NPC 2101066
		"4 1A 37 server BQAAAADAfwAAAAAAAAAA",                 // 5 moves to NaN
		"5 04 38 client x3w=",
	))
	if want := []string{"Player", "Player2", "npc 2101066", "entity 37365"}; !slices.Equal(tracks(evs, byEntity), want) {
		t.Errorf("entity tracks %q, want %q", tracks(evs, byEntity), want)
	}
	if want := []string{"41 36 Spawn", "45 36 Player", "1A 37 Move", "04 8D Owner", "client 04 38"}; !slices.Equal(tracks(evs, byOpcode), want) {
		t.Errorf("opcode tracks %q, want %q", tracks(evs, byOpcode), want)
	}
	for _, e := range evs {
		switch {
		case e.Name == "Move" && !strings.Contains(fmt.Sprint(e.Args["error"]), "NaN"):
			t.Errorf("the NaN move reads %v, want the payload and the error", e.Args)
		case e.Ph == "i" && e.PID == byOpcode && e.TID&client != 0 && e.Name != "04 38":
			t.Errorf("the client's frame is named %q, not by game's table", e.Name)
		}
	}
}

func TestCapture(t *testing.T) {
	evs := timeline(t, "../../capture/testdata/sample.pcap")
	var ts []int64
	for _, e := range evs {
		if e.PID == byOpcode && e.Ph == "i" {
			ts = append(ts, e.TS)
		}
	}
	if want := []int64{0, 0, -1000, -1000}; !slices.Equal(ts, want) {
		t.Errorf("frames at %vµs, want %v: after the first frame, to the microsecond", ts, want)
	}
	if want := []string{"33 36 Self", "04 38 Hit", "05 38 DoT", "2A 38"}; !slices.Equal(tracks(evs, byOpcode), want) {
		t.Errorf("opcode tracks %q, want %q", tracks(evs, byOpcode), want)
	}
}

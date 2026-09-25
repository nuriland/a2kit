package game_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/nuriland/a2kit/a2log"
	"github.com/nuriland/a2kit/game"
)

func Example() {
	r := strings.NewReader(`{"schema":"a2log/v0.1","decoder":"github.com/nuriland/a2kit@v0.2.0","source":{"kind":"pcap","path":"fight.pcap"},"t0":"2026-09-23T18:00:00.123Z"}
{"t":0,"opcode":"04 38","flags":["server"],"src":"10.0.0.2:13328","dst":"10.0.0.1:10000","payload":"x3wEAPWjAuAmqAAAAkvtn0EBAAAAkE4kAQA="}
{"t":12,"opcode":"05 38","flags":["server"],"src":"10.0.0.2:13328","dst":"10.0.0.1:10000","payload":"x3wC9aMCAOAmqAAk"}
{"t":40,"opcode":"04 38","flags":["server"],"src":"10.0.0.2:13328","dst":"10.0.0.1:10000","payload":"x3wEAPWjAuAmqAAAAks="}
{"t":51,"opcode":"42 36","flags":["server"],"src":"10.0.0.2:13328","dst":"10.0.0.1:10000","payload":"x3wAAw=="}
`)
	dec := json.NewDecoder(r)
	var hdr a2log.Header
	if err := dec.Decode(&hdr); err != nil {
		log.Fatal(err)
	}
	for dec.More() {
		var line a2log.Frame
		if err := dec.Decode(&line); err != nil {
			log.Fatal(err)
		}
		e, err := game.Parse(line.Wire(hdr.T0))
		switch {
		case errors.Is(err, game.ErrUnread):
			continue // an opcode game does not read yet
		case err != nil:
			fmt.Println(line.Opcode, err) // bytes off the layout; many after a game patch
			continue
		}
		switch e := e.(type) {
		case game.Hit:
			fmt.Printf("%d hits %d with %d for %d\n", e.Actor, e.Target, e.Skill, e.Damage)
		case game.Death:
			fmt.Println(e.Entity, "dies")
		}
	}
	// Output:
	// 37365 hits 15943 with 11020000 for 36
	// 04 38 game: off the layout at byte 13 of 14
	// 15943 dies
}

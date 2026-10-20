package main

import (
	"flag"
	"fmt"
	"io"
	"slices"
	"text/tabwriter"
)

func list(w io.Writer) {
	fmt.Fprint(w, "a2k reads AION 2's network traffic and decodes the server's messages\n\n")
	fmt.Fprint(w, "usage: a2k COMMAND [flags] [FILE]\n\n")
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	for _, c := range commands {
		fmt.Fprintf(tw, "  %s\t%s\n", c.name, c.short)
	}
	fmt.Fprintf(tw, "  %s\t%s\n", "help", "what a command does, or with types, what a2k decodes")
	tw.Flush()
	fmt.Fprint(w, "\nFlags go before or after FILE. A command that reads messages ends with a line on stderr\nthat sums up what it read.\n")
}

func help(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		list(stdout)
		return 0
	}
	if args[0] == "types" {
		fmt.Fprint(stdout, typesHelp)
		return 0
	}
	i := slices.IndexFunc(commands, func(c command) bool { return c.name == args[0] })
	if i < 0 {
		fmt.Fprintf(stderr, "a2k: no command %q\n\n", args[0])
		list(stderr)
		return 2
	}
	c := commands[i]
	fs := flag.NewFlagSet("a2k "+c.name, flag.ContinueOnError)
	c.define(fs, &options{stdout: stdout, stderr: stderr})
	c.usage(stdout, fs)
	return 0
}

// @REVIEW: this is good enough for now, but again not maintainable lol
const typesHelp = `What a2k decodes

A message is one thing the game server sent: a hit, a cast, a clock tick. a2k show writes a
line each, and a message is one of three:

  decoded       its fields:     21.050  Hit        actor=37365 target=15943 skill=11020000 effect=1101000011 damage=36 type=2 speed=10000
  not decoded   a type a2k names but does not read yet, or does not know:
                                21.100  Move       (not decoded, 12 bytes)
                                21.120  E2 38      (unknown type, 9 bytes)
  failed        its bytes do not fit what a2k reads, most likely after a game patch:
                                21.130  Hit        (failed: off the layout at byte 13 of 14; 14 bytes)

With -json, each is a line of JSON:

  {"t":21050,"ts":"2026-09-24T10:53:17.746123Z","type":"04 38","flags":["server"],"name":"Hit","event":{...}}

  t        milliseconds after the first message; negative for one completed out of order
  ts       when the packet that completed the message arrived, UTC; to the millisecond
           from an exported log. The server sends in bursts, about four a second, so many
           messages share one; Tick's clock is finer. The readable lines write clocks in
           local time, as a2k stats -at takes them.
  type     the message type, two bytes in wire order
  flags    server or client, then lz4, bundled, resynced. Only with -stream can a message
           have neither: a2k had too few to be sure the stream is the game's
  name     what a2k calls the type, if anything
  event    the fields of the type, when decoded
  payload  the message's bytes in hex, when not decoded or failed
  error    why it failed: "game: ...", or "json: ..." for a position JSON cannot hold

These keys stay. The fields in event are game's types, and change as a2k learns the game;
each type and field is documented at pkg.go.dev/github.com/nuriland/a2kit/game. The log a2k
export writes is another format, a2log/v0.1, whose key for the type is opcode.

With jq:

  a2k show -json fight.pcap | jq -c 'select(.event and .name != "Tick" and .name != "Move")'
  a2k show -json fight.pcap | jq -c 'select(.name == "Hit") | .event'

`

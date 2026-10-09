package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nuriland/a2kit"
	"github.com/nuriland/a2kit/capture"
)

var connsCommand = command{
	name:  "conns",
	args:  "[flags] FILE",
	short: "the game's TCP connections in a recording, and any that failed",
	long: `Conns reads FILE, a recording, and lists the game's TCP connections in it, and any that failed. It
prints when each began and for how long it lasted, its two ends, how the handshake went, how it closed,
how many bytes each way, and a status. Useful for debugging a session when a2k show doesn't print
anything. A "silent" server took the handshake and the client's bytes and never sent any, which is
what a dead game server looks like behind its proxy.

  a2k conns down.pcap
  a2k conns -all down.pcap               every connection the computer made, not only the game's
  a2k conns -o conns.txt down.pcap`,
	define: func(fs *flag.FlagSet, o *options) func([]string) error {
		var all bool
		fs.BoolVar(&all, "all", false, "list every connection, not only the game's and the failed ones")

		o.verboseFlag(fs)
		o.outputFlag(fs)
		return func(args []string) error {
			name, err := one(args, "FILE")
			if err != nil {
				return err
			}
			return conns(o, name, all)
		}
	},
}

func conns(o *options, name string, all bool) error {
	if name == "-" {
		return usagef("conns reads a recording by its name, not stdin")
	}

	cs, err := a2kit.Connections(name, o.config())
	switch {
	case errors.Is(err, capture.ErrNotCapture):
		return usagef("%s is not a recording, and a log keeps the game's messages, not the packets", name)
	case err != nil:
		return err
	}

	out, err := o.openOutput(false)
	if err != nil {
		return err
	}
	var (
		n, game = len(cs), 0
		t0      time.Time
	)
	for _, c := range cs {
		if c.Game {
			game++
		}
	}
	if n > 0 {
		t0 = cs[0].Start
	}
	if !all {
		cs = slices.DeleteFunc(cs, func(c a2kit.Connection) bool { return !c.Game && !c.Failed() })
	}
	writeConns(out, cs, t0)
	err = errors.Join(out.Close(), o.close())
	fmt.Fprintf(o.stderr, "a2k: done connections=%d shown=%d game=%d\n", n, len(cs), game)
	return err
}

// writeConns prints the connections as a table, their start counted from t0, the recording's first.
func writeConns(w io.Writer, cs []a2kit.Connection, t0 time.Time) {
	var tw *tabwriter.Writer = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "start\tfor\tclient\tserver\tsyn\tsyn-ack\tclose\tsent\treceived\tstatus\tnote")
	for _, c := range cs {
		note := "-"
		if c.Game {
			note = "game"
		}
		fmt.Fprintf(tw, "%.3f\t%.1fs\t%v\t%v\t%d\t%d\t%s\t%d\t%d\t%s\t%s\n", c.Start.Sub(t0).Seconds(), c.End.Sub(c.Start).Seconds(),
			c.Client, c.Server, c.SYN, c.SYNACK, closing(c), c.Sent, c.Received, c.Status, note)
	}
	tw.Flush()
}

// closing is how the connection closed, "fin", "rst", "fin rst", or "-" for not yet.
func closing(c a2kit.Connection) string {
	var how []string
	if c.FIN {
		how = append(how, "fin")
	}
	if c.RST {
		how = append(how, "rst")
	}
	if len(how) == 0 {
		return "-"
	}
	return strings.Join(how, " ")
}

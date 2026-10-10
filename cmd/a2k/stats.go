package main

import (
	"cmp"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nuriland/a2kit"
	"github.com/nuriland/a2kit/a2log"
	"github.com/nuriland/a2kit/game"
	"github.com/nuriland/a2kit/wire"
)

var statsCommand = command{
	name:  "stats",
	args:  "[flags] FILE",
	short: "which message types came, how often, and which a2k decodes",
	long: `Stats reads FILE, a recording, and lists the message types the game server sent. How many of
each, their sizes, and how many a2k decodes. It is the first thing to run on a new recording,
and how new types get decoded. Act in the game at noted moments, then see what answered.

  a2k stats fight.pcap
  a2k stats -at 21.05s,1m13s fight.pcap     how the types followed the moments you acted
  a2k stats -actions fight.pcap             when you acted, as your client's packets show it
  a2k stats -type "01 38" fight.pcap        one type, byte by byte

-at takes offsets from the first message, as a2k show counts them, or clock times like
10:53:41, in this computer's local time, as a2k show writes clocks. A note of "known" means a2k
uses the type to find the game's connection. "background" means the server sends it whether the
player acts or not.`,
	define: func(fs *flag.FlagSet, o *options) func([]string) error {
		var v views
		fs.StringVar(&v.at, "at", "", "the `moments` you acted, comma-separated: offsets like 21.05s, or clock times like 10:53:41")
		fs.DurationVar(&v.window, "window", time.Second, "how long after a moment the server's messages count as its answer")
		fs.BoolVar(&v.actions, "actions", false, "list when your client sent something unusual, and what the server answered")
		fs.StringVar(&v.typ, "type", "", "show one message `type` byte by byte, in wire order: \"01 38\" or 0138")
		o.verboseFlag(fs)
		o.outputFlag(fs)
		return func(args []string) error {
			name, err := one(args, "FILE")
			if err != nil {
				return err
			}
			if err := v.check(); err != nil {
				return err
			}
			return stats(o, name, v)
		}
	},
}

func clock(t time.Time) string { return t.Local().Format("15:04:05 MST") }

// views are the flags that choose what stats shows.
type views struct {
	at      string
	actions bool
	typ     string
	window  time.Duration
	op      wire.Opcode
}

// check takes one view, -at only with the table, a window to look into, and a type to show.
func (v *views) check() (err error) {
	switch {
	case v.window <= 0:
		return usagef("-window %v: the window must be positive", v.window)
	case v.typ != "" && v.actions:
		return usagef("-type and -actions are different views; take one")
	case v.at != "" && (v.typ != "" || v.actions):
		return usagef("-at marks the table; drop -type or -actions")
	case v.at != "":
		if _, err := parseMarks(v.at, time.Now()); err != nil {
			return usageError{err}
		}
	case v.typ != "":
		if v.op, err = parseOpcode(v.typ); err != nil {
			return usageError{err}
		}
	}
	return nil
}

// stats reads a recording, and writes the view v chooses.
func stats(o *options, name string, v views) error {
	if name == "-" {
		return usagef("stats reads a recording by its name, not stdin")
	}

	a, err := a2kit.Analyze(name, o.config())
	if err != nil {
		return err
	}
	out, err := o.openOutput(false)
	if err != nil {
		return err
	}
	if a.Pairs > 1 {
		fmt.Fprintf(o.stderr, "a2k: the game used %d connections; showing %v to %v, the one with the most messages\n", a.Pairs, a.Server, a.Client)
	}
	err = func() error {
		switch {
		case v.typ != "":
			writeType(out, a, v.op)
		case v.actions:
			writeActions(out, a, v.window)
		default:
			marks, err := parseMarks(v.at, a.Start)
			if err != nil {
				return err
			}
			for _, m := range marks {
				if m.Before(a.First) || m.After(a.Last) {
					fmt.Fprintf(o.stderr, "a2k: the mark at %s, %s, is outside the session, %s to %s, %s to %s\n",
						since(a, m), clock(m), since(a, a.First), since(a, a.Last), clock(a.First), clock(a.Last))
				}
			}
			writeTable(out, a, marks, v.window)
		}
		return nil
	}()
	err = errors.Join(err, out.Close(), o.close())
	summarize(o.stderr, a2log.Source{Kind: "pcap", Path: name}, false, a.Summary, err)
	return err
}

// since is how far into the session t is, the way -at takes it.
func since(a *a2kit.Analysis, t time.Time) string {
	return fmt.Sprintf("%.2fs", t.Sub(a.Start).Seconds())
}

// session is the analysis in a line. The endpoints, the span, the messages, and what the client sends all the time.
func session(a *a2kit.Analysis) string {
	types := make(map[wire.Opcode]bool)
	for _, m := range a.Messages {
		types[m.Opcode] = true
	}
	line := fmt.Sprintf("%v to %v: %.1fs, %s of %s; the client sent %s",
		a.Server, a.Client, a.Last.Sub(a.First).Seconds(), plural(len(a.Messages), "message"), plural(len(types), "type"), plural(a.Packets, "packet"))
	if len(a.Usual) > 0 {
		line += fmt.Sprintf(", of %s bytes all the time", listed(a.Usual))
	}
	return line
}

// writeTable prints every message type the server sent, and with marks, how each followed them.
func writeTable(w io.Writer, a *a2kit.Analysis, marks []time.Time, window time.Duration) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, session(a))
	fmt.Fprint(tw, "type\tname\tcount\tshare\tsize\tdecoded\tfailed\tnote")
	if len(marks) > 0 {
		fmt.Fprint(tw, "\tmarks\twithin\tidle/s")
	}
	fmt.Fprintln(tw)
	for _, st := range a.Types(marks, window) {
		fmt.Fprintf(tw, "%v\t%s\t%d\t%.1f%%\t%s\t%d\t%d\t%s", st.Type, cmp.Or(game.Name(st.Type), "-"), st.Count,
			100*float64(st.Count)/float64(len(a.Messages)), sizes(st.Sizes), st.Decoded, st.Failed, note(st.Type, st.Background))
		if len(marks) > 0 {
			rate := "-" // no idle time to rate against
			if !math.IsNaN(st.Idle) {
				rate = fmt.Sprintf("%.2f", st.Idle)
			}
			fmt.Fprintf(tw, "\t%d/%d\t%d\t%s", st.Marks, len(marks), st.Within, rate)
		}
		fmt.Fprintln(tw)
	}
	tw.Flush()
}

// note says what is known of a type.
// The lock counts it, and it comes whether the player acts or not. A type that is guessed is read, but the lock does not count it.
func note(op wire.Opcode, background bool) string {
	var notes []string
	if op.Known() {
		notes = append(notes, "known")
	} else if op.Guessed() {
		notes = append(notes, "guessed")
	}
	if background {
		notes = append(notes, "background")
	}
	if len(notes) == 0 {
		return "-"
	}
	return strings.Join(notes, ", ")
}

// listedMost is how many types a line names of the server's answer.
const listedMost = 12

// writeActions prints when the client sent packets of a size it does not send all the time,
// and the server's types that followed, leaving out those it sends whether the player acts or not.
func writeActions(w io.Writer, a *a2kit.Analysis, window time.Duration) {
	fmt.Fprintf(w, "%s; %s come whether the player acts or not, and are left out\n", session(a), listed(a.Background))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "at\tclient sent\tserver answered")
	for _, act := range a.Actions(window) {
		var sent, answered []string
		for _, n := range act.Sent {
			sent = append(sent, fmt.Sprint(n))
		}
		for _, c := range act.Answered[:min(len(act.Answered), listedMost)] {
			if c.N > 1 {
				answered = append(answered, fmt.Sprintf("%v x%d", c.Type, c.N))
			} else {
				answered = append(answered, c.Type.String())
			}
		}
		if len(act.Answered) > listedMost {
			answered = append(answered, fmt.Sprintf("%d more", len(act.Answered)-listedMost))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", since(a, act.At), strings.Join(sent, " "), cmp.Or(strings.Join(answered, ", "), "-"))
	}
	tw.Flush()
}

const (
	samples    = 8  // how many messages writeType prints whole
	sharedMost = 8  // how many other types it names that share the first varint's values
	shown      = 32 // how many bytes of a payload it prints
)

// writeType prints one message type's payloads, position by position.
func writeType(w io.Writer, a *a2kit.Analysis, op wire.Opcode) {
	d := a.Type(op)
	if len(d.Messages) == 0 {
		fmt.Fprintf(w, "%v: no messages\n", op)
		return
	}

	fmt.Fprintf(w, "%v: %d messages of %s bytes\n", op, len(d.Messages), sizes(d.Sizes))
	for p, counts := range d.Bytes {
		fmt.Fprintf(w, "  byte %2d: %s\n", p, values(counts))
	}
	if d.Longest > len(d.Bytes) {
		fmt.Fprintf(w, "  and %d more\n", d.Longest-len(d.Bytes))
	}

	first := "none"
	if d.Values > 0 {
		first = plural(d.Values, "value") + ", shared with no other type"
	}
	if len(d.Shared) > 0 {
		var parts []string
		for _, c := range d.Shared[:min(len(d.Shared), sharedMost)] {
			parts = append(parts, fmt.Sprintf("%v (%d)", c.Type, c.N))
		}
		if len(d.Shared) > sharedMost {
			parts = append(parts, "...")
		}
		first = fmt.Sprintf("%s, shared with %s", plural(d.Values, "value"), strings.Join(parts, ", "))
	}
	fmt.Fprintf(w, "first varint: %s\n", first)
	fmt.Fprintln(w, "first messages:")
	for _, m := range d.Messages[:min(len(d.Messages), samples)] {
		fmt.Fprintf(w, "  %s  %s\n", since(a, m.Time), payload(m.Payload))
	}
}

// values is the three values a position took most, "05 x2, 13 x1".
func values(counts map[byte]int) string {
	var (
		bs    = slices.SortedFunc(maps.Keys(counts), func(x, y byte) int { return cmp.Or(cmp.Compare(counts[y], counts[x]), cmp.Compare(x, y)) })
		plen  = min(len(bs), 3)
		parts = make([]string, 0, plen)
	)
	for _, b := range bs[:plen] {
		parts = append(parts, fmt.Sprintf("%02x x%d", b, counts[b]))
	}
	if len(bs) > plen {
		return fmt.Sprintf("%d values: %s, ...", len(bs), strings.Join(parts, ", "))
	}
	return strings.Join(parts, ", ")
}

// payload is the first bytes of p in hex, "00 00 00 e0 26 a8 00".
func payload(p []byte) string {
	s := fmt.Sprintf("% x", p[:min(len(p), shown)])
	if len(p) > shown {
		s += " ..."
	}
	return s
}

// listed is the values in order, or "none".
func listed[T any](vs []T) string {
	if len(vs) == 0 {
		return "none"
	}

	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		parts = append(parts, fmt.Sprint(v))
	}
	return strings.Join(parts, ", ")
}

// sizes describes payload sizes, messages by size: "7", or "9..12 (4 sizes)".
func sizes(m map[int]int) string {
	all := slices.Sorted(maps.Keys(m))
	if len(all) == 1 {
		return fmt.Sprint(all[0])
	}
	return fmt.Sprintf("%d..%d (%d sizes)", all[0], all[len(all)-1], len(all))
}

// parseMarks reads -at moments as offsets from start, "21.05s" or "1m13s", or as local clock
// times on the day of start, "10:53:41", or the day after if that puts them before it.
func parseMarks(list string, start time.Time) ([]time.Time, error) {
	if list == "" {
		return nil, nil
	}

	var marks []time.Time
	for m := range strings.SplitSeq(list, ",") {
		m = strings.TrimSpace(m)
		if d, err := time.ParseDuration(m); err == nil {
			marks = append(marks, start.Add(d))
			continue
		}
		clock, err := time.Parse("15:04:05", m)
		if err != nil {
			return nil, fmt.Errorf("-at %q: not an offset like 21.05s, or a clock time like 10:53:41", m)
		}
		y, mo, d := start.Local().Date()
		at := time.Date(y, mo, d, clock.Hour(), clock.Minute(), clock.Second(), clock.Nanosecond(), time.Local)
		if at.Before(start) {
			at = at.Add(24 * time.Hour)
		}
		marks = append(marks, at)
	}
	slices.SortFunc(marks, time.Time.Compare)
	return marks, nil
}

// parseOpcode reads a message type in wire order, "01 38" or "0138".
func parseOpcode(s string) (wire.Opcode, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil || len(b) != 2 {
		return 0, fmt.Errorf("-type %q: not two hex bytes like \"01 38\"", s)
	}
	return wire.Opcode(uint16(b[0]) | uint16(b[1])<<8), nil
}

package main

import (
	"cmp"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nuriland/a2kit/game"
	"github.com/nuriland/a2kit/wire"
)

// stat is what the table shows of an opcode
type stat struct {
	op     wire.Opcode
	n      int
	sizes  map[int]int // payload size -> frames
	marks  int         // marks it followed within a window
	within int         // frames within a mark's window
}

// table prints every opcode the server sent, and with marks, how each followed them
func (s *session) table(w io.Writer, marks []time.Time, window time.Duration) {
	stats := make(map[wire.Opcode]*stat)
	for _, f := range s.frames {
		st := stats[f.Opcode]
		if st == nil {
			st = &stat{op: f.Opcode, sizes: make(map[int]int)}
			stats[f.Opcode] = st
		}
		st.n++
		st.sizes[len(f.Payload)]++
	}

	for _, m := range marks {
		followed := make(map[wire.Opcode]bool)
		for _, f := range s.between(m, m.Add(window)) {
			followed[f.Opcode] = true
		}
		for op := range followed {
			stats[op].marks++
		}
	}

	var covered time.Duration
	for _, iv := range windows(marks, window) {
		for _, f := range s.between(iv[0], iv[1]) {
			stats[f.Opcode].within++
		}
		// Only what the window covers of the session is time that was not idle
		lo, hi := iv[0], iv[1]
		if lo.Before(s.first) {
			lo = s.first
		}
		if hi.After(s.last) {
			hi = s.last
		}
		if hi.After(lo) {
			covered += hi.Sub(lo)
		}
	}

	rows := slices.SortedFunc(maps.Values(stats), func(a, b *stat) int {
		if len(marks) > 0 {
			return cmp.Or(cmp.Compare(b.marks, a.marks), cmp.Compare(a.n-a.within, b.n-b.within),
				cmp.Compare(b.n, a.n), cmp.Compare(a.op, b.op))
		}
		return cmp.Or(cmp.Compare(b.n, a.n), cmp.Compare(a.op, b.op))
	})

	var (
		tw   = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		idle = s.last.Sub(s.first) - covered
	)

	fmt.Fprintln(w, s.summary())
	fmt.Fprint(tw, "opcode\tname\tframes\tshare\tpayload\tnote")
	if len(marks) > 0 {
		fmt.Fprint(tw, "\tmarks\twithin\tidle/s")
	}
	fmt.Fprintln(tw)

	for _, st := range rows {
		fmt.Fprintf(tw, "%v\t%s\t%d\t%.1f%%\t%s\t%s", st.op, cmp.Or(game.Name(st.op), "-"), st.n, 100*float64(st.n)/float64(len(s.frames)), sizes(st.sizes), note(st.op, s.background[st.op]))
		if len(marks) > 0 {
			rate := "-" // no idle time to rate against
			if idle > 0 {
				rate = fmt.Sprintf("%.2f", float64(st.n-st.within)/idle.Seconds())
			}
			fmt.Fprintf(tw, "\t%d/%d\t%d\t%s", st.marks, len(marks), st.within, rate)
		}
		fmt.Fprintln(tw)
	}
	tw.Flush()
}

// note says what is known of an opcode: the lock counts it, and it comes whether the player acts or not
func note(op wire.Opcode, background bool) string {
	var notes []string
	if op.Known() {
		notes = append(notes, "known")
	}
	if background {
		notes = append(notes, "background")
	}
	if len(notes) == 0 {
		return "-"
	}
	return strings.Join(notes, ", ")
}

// windows merges the marks' windows where they overlap, so that a frame counts once
func windows(marks []time.Time, window time.Duration) [][2]time.Time {
	var out [][2]time.Time
	for _, m := range marks {
		if n := len(out); n > 0 && !m.After(out[n-1][1]) {
			out[n-1][1] = m.Add(window)
			continue
		}
		out = append(out, [2]time.Time{m, m.Add(window)})
	}
	return out
}

// parseMarks reads -at moments as offsets from start, "21.05s" or "1m13s",
// or as local clock times on the day of start, "10:53:41", or the day after if that puts them before it
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

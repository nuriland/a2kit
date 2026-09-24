package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nuriland/a2kit/wire"
)

const (
	listedMost = 12                     // listedMost is how many opcodes a line names of the server's answer.
	burstGap   = 250 * time.Millisecond // burstGap is the silence that separates one of the player's actions from the next
)

// anchors prints when the client sent segments of a size it does not send all the time,
// and the server's opcodes that followed within window, or until the next such moment, leaving out those it sends whether the player acts or not.
func (s *session) anchors(w io.Writer, window time.Duration) {
	fmt.Fprintf(w, "%s; %s come whether the player acts or not, and are left out\n", s.summary(), listed(s.background))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "at\tclient sent\tserver answered")

	all := bursts(s.sent, s.usual)
	for i, burst := range all {
		var sent []string
		for _, g := range burst {
			sent = append(sent, strconv.Itoa(g.size))
		}
		from, to := burst[0].t, burst[0].t.Add(window)
		if i+1 < len(all) && all[i+1][0].t.Before(to) { // what follows the next burst is its answer
			to = all[i+1][0].t
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", s.since(from), strings.Join(sent, " "), answered(s.between(from, to), s.background))
	}
	tw.Flush()
}

// bursts groups the segments of unusual sizes, one within burstGap of the last joins its burst.
func bursts(sent []segment, usual map[int]bool) [][]segment {
	var out [][]segment
	for _, g := range sent {
		if usual[g.size] {
			continue
		}
		if n := len(out); n > 0 && g.t.Sub(out[n-1][len(out[n-1])-1].t) <= burstGap {
			out[n-1] = append(out[n-1], g)
			continue
		}
		out = append(out, []segment{g})
	}
	return out
}

// answered lists the opcodes of frames outside background, in order of first appearance and
// with counts, "01 38, 02 38 x2", up to listedMost of them
func answered(frames []wire.Frame, background map[wire.Opcode]bool) string {
	var (
		counts = make(map[wire.Opcode]int)
		order  = make([]wire.Opcode, 0, len(frames))
	)
	for _, f := range frames {
		if background[f.Opcode] {
			continue
		}
		if counts[f.Opcode] == 0 {
			order = append(order, f.Opcode)
		}
		counts[f.Opcode]++
	}
	if len(order) == 0 {
		return "-"
	}

	var parts []string
	for _, op := range order[:min(len(order), listedMost)] {
		if n := counts[op]; n > 1 {
			parts = append(parts, fmt.Sprintf("%v x%d", op, n))
		} else {
			parts = append(parts, op.String())
		}
	}
	if len(order) > listedMost {
		parts = append(parts, fmt.Sprintf("%d more", len(order)-listedMost))
	}
	return strings.Join(parts, ", ")
}

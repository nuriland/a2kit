// Score measures the decoder on synthesized captures whose frames are known: how many of them
// it finds, and how many it makes up. A heuristic in package wire changes only with these
// numbers, before and after.
//
//	go run ./internal/score [-n 200] [-noise 30]
//
// Each corpus is captures of one server stream: small frames, bundles, padding, and a share of
// big frames, with random payloads. A capture may start mid-stream, and loses one to three of
// its segments and reorders others. Each is read twice: as a pcap, the way dump -pcap reads it,
// and given to Feed in pieces, some sent the other way and so lost. The output is deterministic.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"slices"
	"sync"
	"text/tabwriter"

	"github.com/nuriland/a2kit/capture"
	"github.com/nuriland/a2kit/wire"
)

var (
	captures = flag.Int("n", 200, "`captures` in each corpus")
	noiseRun = flag.Int("noise", 0, "also feed this many `runs` of 64 MB of noise to a hunting decoder, and count the locks")
)

var corpora = []corpus{
	{name: "big 10%", big: 0.10, seed: 11},
	{name: "big 2%", big: 0.02, seed: 23},
}

// tally counts frames sent, found, and made up, and by payload size: under 1 KiB, to 16 KiB, past it.
type tally struct {
	sent, found, bogus int
	sentBy, foundBy    [3]int
}

func (t *tally) add(u tally) {
	t.sent += u.sent
	t.found += u.found
	t.bogus += u.bogus
	for i := range t.sentBy {
		t.sentBy[i] += u.sentBy[i]
		t.foundBy[i] += u.foundBy[i]
	}
}

func class(n int) int {
	switch {
	case n < 1<<10:
		return 0
	case n <= 1<<14:
		return 1
	}
	return 2
}

// count matches the frames the server's stream gave against those it was sent, as a multiset.
func count(want []frame, got []wire.Frame) (t tally) {
	left := make(map[frame]int, len(want))
	for _, w := range want {
		left[w]++
		t.sent++
		t.sentBy[class(len(w.payload))]++
	}
	for _, f := range got {
		if f.Src != srv {
			continue
		}
		k := frame{f.Opcode, string(f.Payload)}
		if left[k] == 0 {
			t.bogus++
			continue
		}
		left[k]--
		t.found++
		t.foundBy[class(len(f.Payload))]++
	}
	return t
}

// run scores n captures of c, both ways, in parallel.
func (c corpus) run(n int) (pcap, feed tally) {
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, runtime.GOMAXPROCS(0))
	)
	for i := range uint64(n) {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			p, f := c.score(i)
			mu.Lock()
			pcap.add(p)
			feed.add(f)
			mu.Unlock()
		})
	}
	wg.Wait()
	return pcap, feed
}

func (c corpus) score(i uint64) (pcap, feed tally) {
	s := c.sampler(i, false)
	b, want := s.stream()
	r, err := capture.NewReader(bytes.NewReader(s.capture(b)))
	if err != nil {
		log.Fatal(err)
	}
	var got []wire.Frame
	for f, err := range wire.NewDecoder(wire.Config{EmitClient: true}).Decode(r) {
		if err != nil {
			log.Fatal(err)
		}
		got = append(got, f)
	}
	pcap = count(want, got)

	s = c.sampler(i, true)
	b, want = s.stream()
	d := wire.NewDecoder(wire.Config{EmitClient: true})
	s.feed(d, b)
	feed = count(want, slices.Collect(d.Frames()))
	return pcap, feed
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("score: ")
	flag.Parse()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "corpus\tread\tfound\t\tbogus\tunder 1 KiB\tto 16 KiB\tpast 16 KiB")
	for _, c := range corpora {
		pcap, feed := c.run(*captures)
		row(w, c.name, "pcap", pcap)
		row(w, c.name, "feed", feed)
	}
	w.Flush()

	if *noiseRun > 0 {
		noise(*noiseRun, 64)
	}
}

func row(w io.Writer, name, how string, t tally) {
	fmt.Fprintf(w, "%s\t%s\t%d of %d\t%.2f%%\t%d\t%.1f%%\t%.1f%%\t%.1f%%\n", name, how, t.found, t.sent,
		percent(t.found, t.sent), t.bogus, percent(t.foundBy[0], t.sentBy[0]),
		percent(t.foundBy[1], t.sentBy[1]), percent(t.foundBy[2], t.sentBy[2]))
}

func percent(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

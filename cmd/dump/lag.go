package main

import (
	"log/slog"
	"slices"
	"time"

	"github.com/nuriland/a2kit/wire"
)

// lagEvery is how often lag logs, when frames keep coming.
const lagEvery = 5 * time.Second

// lag logs how far the frames run behind the wire, which is the time from a frame's packet to the frame coming out.
// For a live capture that is the capture's own delay, since decoding takes microseconds.
type lag struct {
	log   *slog.Logger
	now   func() time.Time
	seen  []time.Duration
	since time.Time // when it last logged
}

func newLag(log *slog.Logger, now func() time.Time) *lag {
	return &lag{log: log, now: now, since: now()}
}

// note counts f, and logs the frames counted so far once lagEvery has passed.
func (l *lag) note(f wire.Frame) {
	now := l.now()
	l.seen = append(l.seen, now.Sub(f.Time))
	if now.Sub(l.since) >= lagEvery {
		l.report()
		l.since = now
	}
}

// report logs the frames counted since the last report, and starts counting again.
func (l *lag) report() {
	n := len(l.seen)
	if n == 0 {
		return
	}
	slices.Sort(l.seen)
	round := func(d time.Duration) time.Duration { return d.Round(time.Millisecond) }
	l.log.Info("capture lag", "frames", n,
		"min", round(l.seen[0]), "p50", round(l.seen[n/2]), "p90", round(l.seen[n*9/10]), "max", round(l.seen[n-1]))
	l.seen = l.seen[:0]
}

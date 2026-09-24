package main

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nuriland/a2kit/wire"
)

func TestLag(t *testing.T) {
	var (
		out strings.Builder
		now = time.Unix(1000, 0)

		log  = slog.New(slog.NewTextHandler(&out, &slog.HandlerOptions{ReplaceAttr: untimed}))
		l    = newLag(log, func() time.Time { return now })
		note = func(behind time.Duration) { l.note(wire.Frame{Time: now.Add(-behind)}) }
	)

	note(1500 * time.Millisecond)
	now = now.Add(2 * time.Second)
	note(1200 * time.Millisecond)
	if out.Len() != 0 {
		t.Fatalf("logged before %v: %s", lagEvery, out.String())
	}

	now = now.Add(3 * time.Second)
	note(1900 * time.Millisecond)
	want := `level=INFO msg="capture lag" frames=3 min=1.2s p50=1.5s p90=1.9s max=1.9s` + "\n"
	if out.String() != want {
		t.Errorf("log:\n%swant:\n%s", out.String(), want)
	}

	out.Reset()
	l.report() // nothing counted since
	if out.Len() != 0 {
		t.Errorf("logged an empty window: %s", out.String())
	}

	note(300 * time.Millisecond)
	l.report()
	want = `level=INFO msg="capture lag" frames=1 min=300ms p50=300ms p90=300ms max=300ms` + "\n"
	if out.String() != want {
		t.Errorf("log:\n%swant:\n%s", out.String(), want)
	}
}

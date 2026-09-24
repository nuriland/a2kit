// Opdiff helps name opcodes.
//
//	go run ./internal/opdiff -anchors FILE                       when the client sent something unusual
//	go run ./internal/opdiff [-at 21.05s,1m13s,10:53:41] FILE    the opcodes, and how they followed the marks
//	go run ./internal/opdiff -op "01 38" FILE                    one opcode, position by position
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nuriland/a2kit/capture"
)

var (
	at      = flag.String("at", "", "the `moments` the player acted, comma-separated: offsets from the start like 21.05s, or local clock times like 10:53:41")
	op      = flag.String("op", "", "show one `opcode` position by position, in wire order: \"01 38\"")
	window  = flag.Duration("window", time.Second, "how long after a moment the server's frames count as its answer")
	anchors = flag.Bool("anchors", false, "list when the client sent something unusual")
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("opdiff: ")
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(flag.Arg(0)); err != nil {
		log.Fatal(err)
	}
}

func run(name string) error {
	if err := validateFlags(); err != nil {
		return err
	}
	f, err := capture.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	s, err := read(f)
	if err != nil {
		return err
	}
	if s.locks > 1 {
		log.Printf("the decoder locked on %d game streams; showing %v to %v, the one with the most frames", s.locks, s.server, s.client)
	}
	switch {
	case *op != "":
		o, err := parseOpcode(*op)
		if err != nil {
			return err
		}
		s.bytes(os.Stdout, o)
	case *anchors:
		s.anchors(os.Stdout, *window)
	default:
		marks, err := parseMarks(*at, s.start)
		if err != nil {
			return err
		}
		for _, m := range marks {
			if m.Before(s.first) || m.After(s.last) {
				log.Printf("the mark at %s is outside the session, %s to %s", s.since(m), s.since(s.first), s.since(s.last))
			}
		}
		s.table(os.Stdout, marks, *window)
	}
	return nil
}

// validateFlags takes one view, -at only with the table, and a window to look into.
func validateFlags() error {
	switch {
	case *window <= 0:
		return fmt.Errorf("-window %v: the window must be positive", *window)
	case *op != "" && *anchors:
		return errors.New("-op and -anchors are different views; take one")
	case *at != "" && (*op != "" || *anchors):
		return errors.New("-at marks the table; drop -op or -anchors")
	}
	return nil
}

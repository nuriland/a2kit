package main

import (
	"encoding/json"
	"runtime/debug"
	"strings"
	"time"

	"github.com/nuriland/a2kit/a2log"
	"github.com/nuriland/a2kit/wire"
)

type log struct {
	enc   *json.Encoder
	hdr   a2log.Header
	begun bool // whether the header has been written
}

// write writes f, after the header if f is the first frame.
func (l *log) write(f wire.Frame) error {
	if !l.begun {
		l.hdr.T0 = f.Time.UTC()
		if err := l.enc.Encode(l.hdr); err != nil {
			return err
		}
		l.begun = true
	}
	return l.enc.Encode(frame(f, l.hdr.T0))
}

// end writes the header if no frame has.
func (l *log) end() error {
	if l.begun {
		return nil
	}
	return l.enc.Encode(l.hdr)
}

// frame is f as the log writes it, its time as milliseconds after t0.
func frame(f wire.Frame, t0 time.Time) a2log.Frame {
	return a2log.Frame{
		T:       f.Time.Sub(t0).Milliseconds(),
		Opcode:  f.Opcode.String(),
		Flags:   flags(f.Flags),
		Src:     f.Src.String(),
		Dst:     f.Dst.String(),
		Payload: f.Payload,
	}
}

// flags lists the names Flags.String joins, [] for none.
func flags(f wire.Flags) []string {
	s := f.String()
	if s == "-" {
		return []string{}
	}
	return strings.Split(s, ",")
}

// header describes this run: the source decoded, and the build that wrote it.
func header() a2log.Header {
	var src a2log.Source
	switch {
	case *pcapFile != "":
		src = a2log.Source{Kind: "pcap", Path: *pcapFile}
	case *live:
		src = a2log.Source{Kind: "live", Path: *dev}
	default:
		src = a2log.Source{Kind: "feed", Path: *feedFile}
	}
	hdr := a2log.Header{Schema: a2log.Schema, Source: src}
	if bi, ok := debug.ReadBuildInfo(); ok {
		hdr.Decoder = bi.Main.Path + "@" + bi.Main.Version
	}
	return hdr
}

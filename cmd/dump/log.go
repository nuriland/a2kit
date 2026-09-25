package main

import (
	"encoding/json"
	"runtime/debug"

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
	return l.enc.Encode(a2log.NewFrame(f, l.hdr.T0))
}

// end writes the header if no frame has.
func (l *log) end() error {
	if l.begun {
		return nil
	}
	return l.enc.Encode(l.hdr)
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

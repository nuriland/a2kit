// Package a2log is the fight log that dump -log writes: a Header line, then one Frame a line, each a JSON object.
package a2log

import (
	"net/netip"
	"time"

	"github.com/nuriland/a2kit/wire"
)

// Schema names the layout: a Header line, then a Frame a line.
// A reader ignores keys it does not know.
const Schema = "a2log/v0.1"

// Header is the first line of a log.
type Header struct {
	Schema  string    `json:"schema"`
	Decoder string    `json:"decoder"` // the module and version that wrote it
	Source  Source    `json:"source"`
	T0      time.Time `json:"t0,omitzero"` // the first frame's time, UTC; absent with no frames
}

// Source is where the frames came from.
type Source struct {
	Kind string `json:"kind"`           // pcap, feed or live
	Path string `json:"path,omitempty"` // the file, or the device; empty for the default device
}

// Frame is one line after the header.
type Frame struct {
	T       int64          `json:"t"`       // milliseconds after Header.T0; negative when a capture is out of order
	Opcode  wire.Opcode    `json:"opcode"`  // in wire order, "04 38"
	Flags   wire.Flags     `json:"flags"`   // ["server","lz4"], [] for none
	Src     netip.AddrPort `json:"src"`     // "10.0.0.2:13328"
	Dst     netip.AddrPort `json:"dst"`     // "10.0.0.3:13328"
	Payload []byte         `json:"payload"` // the bytes after the opcode, base64; "" when empty, never null
}

// NewFrame is f as a line of a log that begins at t0.
func NewFrame(f wire.Frame, t0 time.Time) Frame {
	p := f.Payload
	if p == nil {
		p = []byte{}
	}
	return Frame{f.Time.Sub(t0).Milliseconds(), f.Opcode, f.Flags, f.Src, f.Dst, p}
}

// Wire is the frame of a line of a log that begins at t0, for game.Parse. Its time is to the millisecond.
func (f Frame) Wire(t0 time.Time) wire.Frame {
	return wire.Frame{
		Time:    t0.Add(time.Duration(f.T) * time.Millisecond),
		Src:     f.Src,
		Dst:     f.Dst,
		Opcode:  f.Opcode,
		Flags:   f.Flags,
		Payload: f.Payload,
	}
}

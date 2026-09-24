// Package a2log is the fight log that dump -log writes: a Header line, then one Frame a line, each a JSON object.
package a2log

import "time"

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
	T       int64    `json:"t"`       // milliseconds after Header.T0; negative when a capture is out of order
	Opcode  string   `json:"opcode"`  // the two bytes in wire order, "04 38"
	Flags   []string `json:"flags"`   // server, client, lz4, bundled, resynced; [] for none, never null
	Src     string   `json:"src"`     // "10.0.0.2:13328"
	Dst     string   `json:"dst"`     // "10.0.0.3:13328"
	Payload []byte   `json:"payload"` // the bytes after the opcode, base64; "" when empty, never null
}

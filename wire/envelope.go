package wire

import (
	"bytes"
	"encoding/binary"
)

// The lengths an envelope header may give.
const (
	minEnvelope = 8
	maxEnvelope = 1000000
)

// envelopes strips the u32le length headers from a stream whose frames come in envelopes.
type envelopes struct {
	on   bool    // the stream is in envelopes
	lost bool    // a gap took a header, and nothing is stripped until the next is found
	left int     // body bytes left in the current envelope
	have int     // header bytes received so far
	head [4]byte // a header split across writes

	search scan // for the headers in the raw bytes since the gap, while lost
}

// believable reports whether n is a length an envelope header may give.
func believable(n uint32) bool { return n >= minEnvelope && n <= maxEnvelope }

// skip accounts for n lost bytes. Within the current body the position is still known; past it,
// a header was lost.
func (e *envelopes) skip(n int) {
	if !e.lost && n <= e.left {
		e.left -= n
		return
	}
	e.lost, e.left, e.have = true, 0, 0
	e.search.reset()
}

// strip removes the headers from p in place. A header with a length that is not believable ends
// the envelopes: its bytes are kept with the rest, and over is true. The result may be longer
// than p when that header began in an earlier write.
func (e *envelopes) strip(p []byte) (out []byte, over bool) {
	out = p[:0]
	for len(p) > 0 {
		if e.left > 0 {
			n := min(len(p), e.left)
			out = append(out, p[:n]...)
			p = p[n:]
			e.left -= n
			continue
		}

		e.head[e.have] = p[0]
		e.have++
		p = p[1:]
		if e.have < len(e.head) {
			continue
		}
		e.have = 0
		if n := binary.LittleEndian.Uint32(e.head[:]); believable(n) {
			e.left = int(n)
			continue
		}

		e.on = false
		tail := append(e.head[:], p...) // a copy: e.head has no spare capacity
		return append(out, tail...), true
	}
	return out, false
}

// envelope reports whether an envelope begins at p: a believable length followed by a plausible
// frame, in bytes that do not begin a plausible frame themselves. Unless afterFrame, two more
// believable headers must follow, one envelope apart, within stallLimit bytes. Missing bytes can
// only raise a little-endian length, so a partial header that is already too long is none.
func (f *framer) envelope(p []byte, afterFrame bool) verdict {
	var h [4]byte
	n := copy(h[:], p)
	switch l := binary.LittleEndian.Uint32(h[:]); {
	case l > maxEnvelope, n == 4 && l < minEnvelope:
		return no
	case n < 4:
		return maybe
	}
	if f.begins(bytes.TrimLeft(p, "\x00")) == yes {
		return no
	}
	if v := f.accepts(p[4:]); v != yes || afterFrame {
		return v
	}
	return chain(p, 0, stallLimit)
}

// strip removes the headers from f.buf[from:].
func (f *framer) strip(from int) {
	out, over := f.env.strip(f.buf[from:])
	f.buf = append(f.buf[:from], out...)
	if over {
		f.log.Warn("envelopes ended")
		f.aligned = false
	}
}

// refind searches the raw bytes since a lost header for three believable headers in a row, one
// envelope apart. The bytes before the first end the envelope the gap cut into and are kept as
// body. It reports whether f.buf is ready to parse: the headers were found, or maxBuf bytes
// arrived without them and the envelopes are over.
func (f *framer) refind() bool {
	e := &f.env
	h, found := e.search.find(0, len(f.buf)-3, func(h int) verdict {
		if !believable(binary.LittleEndian.Uint32(f.buf[h:])) {
			return no
		}
		return chain(f.buf, h, maxBuf)
	})
	switch {
	case found:
		f.log.Info("envelopes found again", "at", h)
		e.lost, e.left = false, h
		e.search.reset()
		f.strip(0)
		return true
	case len(f.buf) < maxBuf:
		return false
	}
	f.log.Warn("envelopes given up")
	*e = envelopes{}
	return true
}

// chain reports whether the header at h is followed by two more believable headers, one envelope
// apart, reading no further than far.
func chain(p []byte, h, far int) verdict {
	for range 2 {
		h += 4 + int(binary.LittleEndian.Uint32(p[h:]))
		switch {
		case h+4 > far:
			return no
		case h+4 > len(p):
			return maybe
		case !believable(binary.LittleEndian.Uint32(p[h:])):
			return no
		}
	}
	return yes
}

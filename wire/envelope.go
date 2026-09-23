package wire

import (
	"bytes"
	"encoding/binary"
	"slices"
)

// The lengths an envelope header may give.
const (
	minEnvelope = 8
	maxEnvelope = 1000000
)

// envelopes strips the u32le length headers from a stream whose frames come in envelopes.
type envelopes struct {
	on   bool    // headers are being stripped
	lost bool    // a gap took a header, and the next must be found again
	left int     // body bytes left in the current envelope
	have int     // header bytes received so far
	head [4]byte // a header split across writes

	// The search for headers in the raw bytes since the gap, while lost
	scanned int   // offsets checked
	pending []int // believable headers whose successors have not arrived
}

// believable reports whether n is a length an envelope header may give.
func believable(n uint32) bool { return n >= minEnvelope && n <= maxEnvelope }

// skip accounts for n lost bytes. Within the current body the position is still known; past it,
// a header was lost.
func (e *envelopes) skip(n int) {
	if !e.lost && e.have == 0 && n <= e.left {
		e.left -= n
		return
	}
	e.lost, e.left, e.have = true, 0, 0
	e.scanned, e.pending = 0, e.pending[:0]
}

// strip removes the headers from p in place. A header with a length that is not believable ends
// the envelopes: its bytes are kept with the rest, and lost is true. The result may be longer
// than p when that header began in an earlier write.
func (e *envelopes) strip(p []byte) (out []byte, lost bool) {
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
	if v := f.starts(p[4:]); v != yes || afterFrame {
		return v
	}
	return chain(p, 0, stallLimit)
}

// strip removes the headers from f.buf[from:].
func (f *framer) strip(from int) {
	out, lost := f.env.strip(f.buf[from:])
	f.buf = append(f.buf[:from], out...)
	if lost {
		f.log.Warn("envelopes lost")
		f.aligned = false
	}
}

// refind searches the raw bytes since a lost header for three believable headers in a row, one
// envelope apart. The bytes before the first end the envelope the gap cut into and are kept as
// body. It reports whether f.buf is ready to parse: the headers were found, or maxBuf bytes
// arrived without them and the envelopes are over.
func (f *framer) refind() bool {
	e := &f.env
	for ; e.scanned+4 <= len(f.buf); e.scanned++ {
		if believable(binary.LittleEndian.Uint32(f.buf[e.scanned:])) {
			e.pending = append(e.pending, e.scanned)
		}
	}
	for i := 0; i < len(e.pending); {
		switch h := e.pending[i]; chain(f.buf, h, maxBuf) {
		case maybe:
			i++
		case yes:
			f.log.Info("envelopes found again", "at", h)
			*e = envelopes{on: true, left: h, pending: e.pending[:0]}
			f.strip(0)
			return true
		default:
			e.pending = slices.Delete(e.pending, i, i+1)
		}
	}
	if len(f.buf) < maxBuf {
		return false
	}
	f.log.Warn("envelopes lost")
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

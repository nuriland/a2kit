package wire

import (
	"encoding/binary"
	"slices"
)

const (
	minEnvelope = 8
	maxEnvelope = 1000000
)

// envelopes strips the u32le length | body envelopes some streams wrap their frames in.
type envelopes struct {
	on   bool    // whether envelopes are on
	lost bool    // on, but a gap took a header with it, so the next must be found again
	left int     // body bytes left in the current envelope
	have int     // bytes in the current header
	head [4]byte // a header split across writes

	// While lost, over the raw bytes since the gap.
	scanned int   // offsets looked at
	pending []int // believable headers whose successor has not come yet
}

func envelopeLen(n uint32) bool { return n >= minEnvelope && n <= maxEnvelope }

// skip passes over n lost bytes. Within the current body they are counted off, and past it a header went with them.
func (e *envelopes) skip(n int) {
	if !e.lost && e.have == 0 && n <= e.left {
		e.left -= n
		return
	}
	e.lost, e.left, e.have = true, 0, 0
	e.scanned, e.pending = 0, e.pending[:0]
}

// strip removes the headers from p, in place. A header without a believable length means the
// envelopes have ended, or never were: they turn off, and the header goes back in with the rest.
// It may have begun in an earlier write, so out can be longer than p.
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
		if n := binary.LittleEndian.Uint32(e.head[:]); envelopeLen(n) {
			e.left = int(n)
			continue
		}

		e.on = false
		tail := append(e.head[:], p...) // a copy, since e.head has no spare room
		return append(out, tail...), true
	}
	return out, false
}

// envelope is whether p starts an envelope around a frame.
func (f *framer) envelope(p []byte) verdict {
	if len(p) < 4 {
		return maybe
	}
	if !envelopeLen(binary.LittleEndian.Uint32(p)) {
		return no
	}
	return f.starts(p[4:])
}

func (f *framer) strip(from int) {
	out, lost := f.env.strip(f.buf[from:])
	f.buf = append(f.buf[:from], out...)
	if lost {
		f.log.Warn("envelopes lost")
		f.aligned = false
	}
}

// refind looks for the headers again in the raw bytes since a gap: three believable ones in a row,
// each one envelope on from the last. Two would do for random bytes about once in 4,000 believable
// candidates, and a megabyte has a few hundred. The bytes before them end the body the gap cut
// into, and are parsed as such. It reports whether f.buf is ready to parse: the headers found, or
// not found in maxBuf bytes, so that the envelopes are over.
func (f *framer) refind() bool {
	e := &f.env
	for ; e.scanned+4 <= len(f.buf); e.scanned++ {
		if envelopeLen(binary.LittleEndian.Uint32(f.buf[e.scanned:])) {
			e.pending = append(e.pending, e.scanned)
		}
	}
	for i := 0; i < len(e.pending); {
		switch h := e.pending[i]; chain(f.buf, h) {
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

// chain is whether the believable header at h has two more behind it, each one envelope on.
func chain(p []byte, h int) verdict {
	for range 2 {
		h += 4 + int(binary.LittleEndian.Uint32(p[h:]))
		if h+4 > len(p) {
			return maybe
		}
		if !envelopeLen(binary.LittleEndian.Uint32(p[h:])) {
			return no
		}
	}
	return yes
}

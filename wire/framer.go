package wire

import (
	"log/slog"
	"slices"
)

const (
	maxFrame        = 1 << 20 // a frame on the wire, varint and all
	maxBuf          = 1 << 20 // what a stream holds while it looks for frames
	probationFrames = 2       // frames after a resync still held to the untrusted rules

	// stallLimit is the biggest frame an untrusted stream waits for. Below it, garbage
	// read as a length is common and cheap to wait on. Above it, where a length takes a
	// third varint byte, garbage is rare but can hold the stream for a megabyte.
	stallLimit = 1 << 14
)

// verdict is what the bytes so far say
type verdict int

const (
	no    verdict = -1
	maybe verdict = 0 // need more bytes
	yes   verdict = 1
)

// framer cuts one stream's bytes into frame bodies, and hands each to emit.
type framer struct {
	knownOnly bool
	log       *slog.Logger
	emit      func(body []byte, flags Flags)

	buf       []byte    // not parsed yet
	aligned   bool      // the last bytes parsed were a frame
	probation int       // frames left before the stream is trusted again
	skipped   int       // bytes passed over since the last frame
	resync    bool      // flag the next frame Resynced
	plain     []byte    // bundle plaintext, a stack for nesting
	env       envelopes // envelopes around frames

	// resume's work on the frame buf[0] waits on, kept from one write to the next
	waiting bool  // the last pump stopped on it
	scanned int   // offsets looked at
	pending []int // those that more bytes may yet make two frames of
}

func (f *framer) write(p []byte) {
	for len(p) > 0 {
		if len(f.buf) >= maxBuf {
			f.log.Warn("stream buffer full", "dropped", len(f.buf))
			f.lose(0)
		}

		var (
			n    = min(len(p), maxBuf-len(f.buf))
			from = len(f.buf)
		)
		f.buf = append(f.buf, p[:n]...)
		p = p[n:]
		switch {
		case f.env.lost:
			if !f.refind() {
				continue
			}
		case f.env.on:
			f.strip(from)
		}
		f.pump()
	}
}

// lose says n bytes of the stream will never come. What the framer holds no longer lines up
// with what does, so it goes too.
func (f *framer) lose(n int) {
	f.skipped += len(f.buf) + n
	f.buf = f.buf[:0]
	f.aligned, f.waiting = false, false
	if f.env.on {
		f.env.skip(n)
	}
}

// trusted is whether the stream is aligned and probation is over.
func (f *framer) trusted() bool { return f.aligned && f.probation == 0 }

// pump parses what it can, and keeps the rest for later bytes to finish.
func (f *framer) pump() {
	var (
		off  = 0
		kept = f.waiting // resume's work stands while the frame at 0 is the one it waited on
	)
	f.waiting = false

loop:
	for off < len(f.buf) {
		p := f.buf[off:]
		if p[0] == 0 && (f.aligned || f.env.on || f.envelope(p) == no) {
			off++ // padding, unless it starts a header: a length of 1024 is 00 04 00 00
			continue
		}

		n, head := f.frameLen(p, f.trusted())
		switch {
		case n > 0:
			if f.skipped > 0 {
				f.log.Info("resynced", "skipped", f.skipped)
				f.skipped, f.resync, f.probation = 0, true, probationFrames
			} else if f.probation > 0 {
				f.probation--
			}
			f.aligned = true
			f.parse(p[head:n], 0, 0)
			off += n

		case n == 0:
			var skip = 0
			if !f.aligned {
				skip = f.resume(p, kept && off == 0)
			}
			if skip == 0 {
				f.waiting = !f.aligned
				break loop // wait for the rest
			}
			f.skipped += skip
			off += skip

		default:
			if !f.aligned && !f.env.on {
				switch f.envelope(p) {
				case maybe:
					break loop
				case yes:
					f.log.Info("envelopes found")
					f.env.on = true
					f.strip(off)
					kept = false // the bytes at off are not what they were
					continue
				}
			}
			f.aligned = false // garbage
			f.skipped++
			off++
		}
	}
	f.buf = f.buf[:copy(f.buf, f.buf[off:])]
}

// frameLen returns the length of the frame at p, varint and all, and the varint's width.
// The length is 0 to wait for more bytes, and -1 if p is not a frame.
// Untrusted, it wants a plausible opcode, and won't wait on a frame over stallLimit bytes.
func (f *framer) frameLen(p []byte, trust bool) (n, head int) {
	v, head := uvarint(p)
	switch {
	case head == 0:
		return 0, 0
	case head < 0, v < 6:
		return -1, 0 // no varint, or no room for an opcode
	}

	n = int(v) + head - 4
	if n > maxFrame {
		return -1, 0
	}

	if !trust {
		if len(p) < head+2 {
			return 0, head // the opcode is not here yet
		}
		if !f.plausible(p[head:], n-head) {
			return -1, 0
		}
		if n > len(p) && n > stallLimit {
			return -1, 0 // too big to wait for on a guess
		}
	}
	if n > len(p) {
		return 0, head
	}
	return n, head
}

// plausible judges a body by its first two or three bytes, and the size its frame gives it.
func (f *framer) plausible(b []byte, size int) bool {
	switch {
	case b[0] == 0xFF && b[1] == 0xFF:
		return size >= minBundle // a bundle
	case b[0] >= 0xF0 && b[0] < 0xFF && b[1] == 0xFF:
		return size > minBundle && (len(b) < 3 || b[2] == 0xFF) // a flagged bundle
	}
	if f.knownOnly {
		return (Opcode(b[0]) | Opcode(b[1])<<8).Known()
	}
	return inFamily(b[1])
}

// starts is whether an untrusted stream would take a frame at p, whole or not.
func (f *framer) starts(p []byte) verdict {
	n, head := f.frameLen(p, false)
	switch {
	case n < 0:
		return no
	case head == 0, len(p) < head+2:
		return maybe
	}
	return yes
}

// resume serves an unaligned stream waiting on a frame that may be garbage. It looks ahead for
// two whole frames in a row, and returns the offset of the first, or 0 to keep waiting. A whole
// frame and the start of another turn up every few thousand offsets of random bytes, often
// inside the frame waited on, so the second must be whole too.
//
// The wait is on nothing past stallLimit, so an offset that fails now fails until the wait ends.
// With kept, the offsets looked at before are not looked at again, only those still pending.
func (f *framer) resume(p []byte, kept bool) int {
	if !kept {
		f.scanned, f.pending = 0, f.pending[:0]
	}
	for j := 0; j < len(f.pending); {
		switch i := f.pending[j]; f.pair(p, i) {
		case yes:
			return i
		case no:
			f.pending = slices.Delete(f.pending, j, j+1)
		default:
			j++
		}
	}
	for f.scanned = max(f.scanned, 1); f.scanned < len(p); f.scanned++ {
		switch f.pair(p, f.scanned) {
		case yes:
			return f.scanned
		case maybe:
			f.pending = append(f.pending, f.scanned)
		}
	}
	return 0
}

// pair is whether p holds two whole frames in a row at i, by the untrusted rules.
func (f *framer) pair(p []byte, i int) verdict {
	n, _ := f.frameLen(p[i:], false)
	switch {
	case n < 0:
		return no
	case n == 0:
		return maybe
	}
	next := i + n
	for next < len(p) && p[next] == 0 {
		next++
	}
	switch m, _ := f.frameLen(p[next:], false); {
	case m < 0:
		return no
	case m == 0:
		return maybe
	}
	return yes
}

// parse opens bundles and emits everything else. A flagged bundle that won't open is emitted as it is
func (f *framer) parse(body []byte, depth int, flags Flags) {
	switch {
	case body[0] == 0xFF && body[1] == 0xFF:
		f.unwrap(body, depth, flags) // dropped if it will not open
		return
	case len(body) > minBundle && body[0] >= 0xF0 && body[0] < 0xFF && body[1] == 0xFF && body[2] == 0xFF:
		if f.unwrap(body[1:], depth, flags) {
			return
		}
	}
	if f.resync {
		flags |= Resynced
		f.resync = false
	}
	f.emit(body, flags)
}

// walk parses a bundle's plaintext. Nothing more will come, so it stops at the first bytes that are not a whole frame.
func (f *framer) walk(p []byte, depth int, flags Flags) {
	for len(p) > 0 {
		if p[0] == 0 {
			p = p[1:]
			continue
		}
		n, head := f.frameLen(p, true)
		if n <= 0 {
			return
		}
		f.parse(p[head:n], depth, flags)
		p = p[n:]
	}
}

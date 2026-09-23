package wire

import "log/slog"

const (
	maxFrame        = 1 << 20 // the longest frame, varint included
	maxBuf          = 1 << 20 // the most a stream buffers
	probationFrames = 2       // frames after a resync that still get the untrusted rules
	stallLimit      = 1 << 14 // the longest incomplete frame an untrusted stream waits for
)

// verdict answers a question that the bytes so far may not settle.
type verdict int

const (
	no    verdict = -1
	maybe verdict = 0 // more bytes are needed
	yes   verdict = 1
)

// framer splits one stream's bytes into frame bodies and passes each to emit.
type framer struct {
	knownOnly bool
	log       *slog.Logger
	emit      func(body []byte, flags Flags)

	buf       []byte    // bytes not parsed yet
	begun     bool      // a frame has been taken or bytes skipped
	over      bool      // no more bytes will arrive
	aligned   bool      // the last bytes parsed were a frame
	probation int       // frames left before the stream is trusted again
	skipped   int       // bytes skipped since the last frame
	resync    bool      // the next frame is flagged Resynced
	plain     []byte    // bundle plaintext, a stack shared by nesting levels
	env       envelopes // envelope state

	waiting bool // the last pump stopped waiting on the frame at buf[0]
	ahead   scan // resume's search past that frame, kept between writes
}

// write appends p to the stream and parses what it can.
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

// lose records that the next n bytes of the stream will never arrive. The buffered bytes no
// longer line up with what follows and are dropped, after any bytes held for the envelope check
// at the start are parsed.
func (f *framer) lose(n int) {
	f.settle()
	f.skipped += len(f.buf) + n
	f.buf = f.buf[:0]
	f.begun, f.aligned, f.waiting = true, false, false
	if f.env.on {
		f.env.skip(n)
	}
}

// settle decides that no envelopes begin at the start of the stream, and parses the bytes held
// while that was undecided.
func (f *framer) settle() {
	if !f.begun {
		f.begun = true
		f.pump()
	}
}

// end records that no more bytes will arrive. Undecided envelope checks resolve to no, a search
// for lost envelope headers is abandoned, and what the framer holds is parsed.
func (f *framer) end() {
	f.over, f.begun = true, true
	if f.env.lost {
		f.log.Warn("envelopes given up")
		f.env = envelopes{}
	}
	f.pump()
}

// trusted reports whether the stream is aligned and off probation.
func (f *framer) trusted() bool { return f.aligned && f.probation == 0 }

// pump parses every frame the buffer holds and keeps the remainder for later writes.
func (f *framer) pump() {
	var (
		off  = 0
		kept = f.waiting // resume's progress holds while buf[0] is the frame it waited on
	)
	f.waiting = false

loop:
	for off < len(f.buf) {
		p := f.buf[off:]
		// Envelopes can begin only where a frame could: after a frame, or at the start.
		if !f.env.on && (f.aligned || !f.begun) {
			switch f.envelope(p, f.aligned) {
			case yes:
				f.log.Info("envelopes found")
				f.env.on = true
				f.strip(off)
				kept = false // the bytes at off have changed
				continue
			case maybe:
				if !f.over {
					break loop // wait for the bytes that decide it
				}
			}
		}
		if p[0] == 0 {
			off++ // padding
			continue
		}

		n, head := f.frameLen(p, f.trusted())
		if n > 0 && !f.aligned && f.follows(p[n:]) == no {
			n = -1 // nothing follows it
		}
		switch {
		case n > 0:
			if f.skipped > 0 {
				f.log.Info("resynced", "skipped", f.skipped)
				f.skipped, f.resync, f.probation = 0, true, probationFrames
			} else if f.probation > 0 {
				f.probation--
			}
			f.begun, f.aligned = true, true
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
			f.begun = true
			f.skipped += skip
			off += skip

		default:
			f.begun, f.aligned = true, false // garbage
			f.skipped++
			off++
		}
	}
	f.buf = f.buf[:copy(f.buf, f.buf[off:])]
}

// frameLen returns the length of the frame at p, varint included, and the varint's width. The
// length is 0 if more bytes are needed and -1 if p does not start a frame. Without trust, the
// opcode must be plausible, and an incomplete frame longer than stallLimit is rejected.
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
			return 0, head // the opcode has not arrived
		}
		if !f.plausible(p[head:], n-head) {
			return -1, 0
		}
		if n > len(p) && n > stallLimit {
			return -1, 0 // too long to wait for
		}
	}
	if n > len(p) {
		return 0, head
	}
	return n, head
}

// plausible reports whether b, the start of a body of the given size, could begin a real frame:
// a bundle, a known opcode, or, unless knownOnly, an opcode in a family.
func (f *framer) plausible(b []byte, size int) bool {
	switch {
	case b[0] == 0xFF && b[1] == 0xFF:
		return size >= minBundle // a bundle
	case b[0] >= 0xF0 && b[0] < 0xFF && b[1] == 0xFF:
		return size > minBundle && (len(b) < 3 || b[2] == 0xFF) // a flagged bundle
	}
	if f.knownOnly {
		return opcode(b).Known()
	}
	return inFamily(b[1])
}

// accepts reports whether an untrusted stream would take a frame at p, complete or not. Unlike
// begins, it refuses an incomplete frame longer than stallLimit.
func (f *framer) accepts(p []byte) verdict {
	n, head := f.frameLen(p, false)
	switch {
	case n < 0:
		return no
	case head == 0, len(p) < head+2:
		return maybe
	}
	return yes
}

// resume is called while an unaligned stream waits for an incomplete frame that may be garbage.
// It returns the first offset further on where two complete frames follow each other, or 0 to
// keep waiting. An offset that fails cannot pass later in the same wait, since p stays shorter
// than stallLimit, so with kept only the pending offsets and the new bytes are checked.
func (f *framer) resume(p []byte, kept bool) int {
	if !kept {
		f.ahead.reset()
	}
	i, _ := f.ahead.find(1, len(p), func(i int) verdict { return f.pair(p, i) })
	return i
}

// pair reports whether p holds two complete frames in a row at i, under the untrusted rules.
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

// follows reports whether a plausible frame or an envelope begins at p, after any padding. An
// unaligned stream accepts a frame only if one does.
func (f *framer) follows(p []byte) verdict {
	if !f.env.on {
		if v := f.envelope(p, true); v != no {
			return v
		}
	}
	for len(p) > 0 && p[0] == 0 {
		p = p[1:]
	}
	return f.begins(p)
}

// begins reports whether a plausible frame begins at p, however long it is.
func (f *framer) begins(p []byte) verdict {
	v, head := uvarint(p)
	switch {
	case head == 0:
		return maybe
	case head < 0, v < 6, int(v)+head-4 > maxFrame:
		return no
	case len(p) < head+2:
		return maybe
	case f.plausible(p[head:], int(v)-4):
		return yes
	}
	return no
}

// parse unwraps bundles and emits every other body. A flagged bundle that fails to unwrap is
// emitted as a frame.
func (f *framer) parse(body []byte, depth int, flags Flags) {
	switch {
	case body[0] == 0xFF && body[1] == 0xFF:
		f.unwrap(body, depth, flags) // dropped if it fails
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

// walk parses a bundle's plaintext, stopping at the first bytes that are not a complete frame.
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

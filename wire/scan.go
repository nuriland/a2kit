package wire

// scan is a search over a buffer that grows between writes. It keeps how far it has looked, and
// the offsets that more bytes may still decide, so that each write checks only those and the new
// offsets.
type scan struct {
	done    int   // offsets below this have been looked at
	pending []int // offsets whose answer was maybe, in order
}

func (s *scan) reset() { s.done, s.pending = 0, s.pending[:0] }

// find checks the pending offsets again, then each offset in [from, to) not looked at before, and
// returns the first that at answers yes to. Offsets that answer no are forgotten. After a yes the
// scan must be reset before it is used again.
func (s *scan) find(from, to int, at func(int) verdict) (int, bool) {
	kept := s.pending[:0]
	for _, i := range s.pending {
		switch at(i) {
		case yes:
			return i, true
		case maybe:
			kept = append(kept, i)
		}
	}
	s.pending = kept
	for s.done = max(s.done, from); s.done < to; s.done++ {
		switch at(s.done) {
		case yes:
			return s.done, true
		case maybe:
			s.pending = append(s.pending, s.done)
		}
	}
	return 0, false
}

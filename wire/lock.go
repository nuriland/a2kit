package wire

import "time"

// admit reports whether bytes on k are parsed. While locked, only the pair is admitted, and its
// traffic keeps the lock alive. The lock ends when the server's stream closes, or after LockIdle
// of silence.
func (d *Decoder) admit(k key, t time.Time) bool {
	d.sweep(t)
	if d.srv == nil {
		return true
	}
	if d.srv.key == k || d.srv.key == k.reverse() {
		if t.After(d.lockAt) {
			d.lockAt = t
		}
		return true
	}

	if t.Sub(d.lockAt) > d.config.LockIdle {
		d.log.Info("flow idle, hunting")
		d.unlock()
		return true
	}
	return false
}

// hunt counts a frame toward the lock, and locks on its stream once it has earned it. Only known
// opcodes count, on a stream off probation, and a resync resets the count. Three lock, as does a
// combat opcode after one. Nothing counts once locked, so a lock never turns around: the
// client's bodies are encrypted, and a known opcode on its side is chance.
func (d *Decoder) hunt(st *stream, op Opcode, flags Flags) {
	if flags&Resynced != 0 {
		st.frames = 0
	}
	if !op.Known() || !st.fr.trusted() {
		return
	}
	st.frames++
	switch {
	case combat(op) && st.frames >= 2:
		d.lock(st, "combat opcode")
	case st.frames >= 3:
		d.lock(st, "3 known frames")
	}
}

// lock makes st the server side and its reverse the client, and drops every other stream.
func (d *Decoder) lock(st *stream, why string) {
	peer := d.streams[st.key.reverse()]
	d.srv, d.lockAt = st, st.last
	st.dir = FromServer
	if peer != nil {
		peer.dir = FromClient
	}
	for _, o := range d.streams {
		if o != st && o != peer {
			d.drop(o)
		}
	}
	d.log.Info("flow locked", "src", st.key.src, "dst", st.key.dst, "why", why)
}

// unlock returns the decoder to hunting.
func (d *Decoder) unlock() {
	d.srv = nil
	for _, st := range d.streams {
		st.dir, st.frames = 0, 0
	}
}

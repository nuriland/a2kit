package wire

import "time"

// admit is whether bytes on k get parsed. While locked, only the pair's do, and they keep the lock alive.
// The lock ends when its server's stream closes, or when it has been quiet for LockIdle.
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

	if t.Sub(d.lockAt) > d.c.LockIdle {
		d.l.Info("flow idle, hunting")
		d.unlock()
		return true
	}
	return false
}

// lockFrame counts a frame toward the lock, and returns its direction.
//
// Any busy stream throws up frames that parse, so only known opcodes count, only once the
// stream is past probation, and a resync starts the count over. Three lock, or a combat
// opcode after one. Combat from the client side means the pair was taken backwards.
func (d *Decoder) lockFrame(st *stream, op Opcode, flags Flags) Flags {
	if flags&Resynced != 0 {
		st.frames = 0
	}
	if !op.Known() || !st.fr.trusted() {
		return st.dir
	}
	st.frames++
	switch {
	case d.srv == nil && combat(op) && st.frames >= 2:
		d.lock(st, "combat opcode")
	case d.srv == nil && st.frames >= 3:
		d.lock(st, "3 known frames")
	case st.dir == FromClient && combat(op) && st.frames >= 2:
		d.lock(st, "combat from other side")
	}
	return st.dir
}

// lock drops every stream outside the pair, as they are ignored from now on.
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
	d.l.Info("flow locked", "src", st.key.src, "dst", st.key.dst, "why", why)
}

func (d *Decoder) unlock() {
	d.srv = nil
	for _, st := range d.streams {
		st.dir, st.frames = 0, 0
	}
}

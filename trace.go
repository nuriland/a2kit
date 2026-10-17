package a2kit

import (
	"bufio"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/nuriland/a2kit/game"
	"github.com/nuriland/a2kit/wire"
)

// WriteTrace writes msgs to w as a Chrome trace, to open in ui.perfetto.dev
func WriteTrace(w io.Writer, msgs iter.Seq2[Message, error]) error {
	var (
		bw  = bufio.NewWriter(w)
		t   = trace{w: bw, ops: map[uint32]bool{}, entities: map[game.Entity]*entity{}, casts: map[cast]traceEvent{}}
		err error
	)
	bw.WriteString(`{"displayTimeUnit":"ms","traceEvents":[` + "\n")
	for m, e := range msgs {
		if e != nil {
			err = e
			break
		}
		t.add(m)
	}
	t.end()
	bw.WriteString("\n]}\n")
	return errors.Join(err, bw.Flush())
}

// traceEvent is one entry of a Chrome trace.
//
// @REVIEW: maybe write our own tracer lib, who knows?
type traceEvent struct {
	Name string `json:"name"`
	Ph   string `json:"ph"`  // i an instant, X a slice, M a track's name or order
	TS   int64  `json:"ts"`  // µs after the first frame
	Dur  int64  `json:"dur"` // a slice's, in µs
	PID  int    `json:"pid"`
	TID  uint32 `json:"tid"`
	S    string `json:"s,omitempty"` // t: an instant drawn on its track only
	Args any    `json:"args,omitempty"`
}

const (
	byOpcode = 1 // track an opcode, the client's apart
	byEntity = 2 // track an entity
)

type cast struct {
	actor game.Entity
	skill game.Skill
}

type entity struct {
	sort int
	name string
	npc  game.NPC
}

// label names id's track, either the player's name, or the NPC's, or the number
func (en *entity) label(id game.Entity) string {
	switch {
	case en.name != "":
		return en.name
	case en.npc != 0:
		return fmt.Sprint("npc ", en.npc)
	}
	return fmt.Sprint("entity ", id)
}

type trace struct {
	ops      map[uint32]bool
	entities map[game.Entity]*entity
	casts    map[cast]traceEvent

	w  *bufio.Writer
	t0 time.Time
	n  int
}

// clientTrack sets a track apart for the client's messages, whose bodies are encrypted.
const clientTrack = 1 << 16

// add puts m on its type's track, and the event game reads on its entities' tracks.
func (t *trace) add(m Message) {
	f := m.Frame
	if t.t0.IsZero() {
		t.t0 = f.Time
	}

	tid, name := uint32(f.Opcode), cmp.Or(game.Name(f.Opcode), f.Opcode.String())
	if f.Flags&wire.FromClient != 0 {
		tid, name = tid|clientTrack, f.Opcode.String()
	}
	t.ops[tid] = true

	e, err := m.Event, m.Err
	var args json.RawMessage
	if err == nil {
		if args, err = json.Marshal(e); err != nil {
			e = nil // a position that is NaN or infinite, which JSON cannot hold
		}
	}
	if err != nil {
		unread := map[string]string{"payload": fmt.Sprintf("% x", f.Payload)}
		if !errors.Is(err, game.ErrUnread) {
			unread["error"] = err.Error()
		}
		args, _ = json.Marshal(unread)
	}

	ts := f.Time.Sub(t.t0).Microseconds()
	t.emit(traceEvent{Name: name, Ph: "i", TS: ts, PID: byOpcode, TID: tid, S: "t", Args: args})

	// @TODO: cleanup
	switch e := e.(type) {
	case game.Hit:
		t.on(e.Actor, "Hit", ts, args)
		t.on(e.Target, "Hit taken", ts, args)
	case game.Cast:
		k := cast{e.Actor, e.Skill}
		if c, ok := t.casts[k]; ok {
			t.emit(c) // cast again before it ended
		}
		t.casts[k] = t.instant(e.Actor, "Cast", ts, args)
	case game.CastEnd:
		k := cast{e.Actor, e.Skill}
		c, ok := t.casts[k]
		if !ok {
			t.on(e.Actor, "CastEnd", ts, args)
			break
		}
		delete(t.casts, k)
		c.Ph, c.S, c.Dur = "X", "", ts-c.TS
		t.emit(c)
	case game.Spawn:
		t.on(e.Entity, "Spawn", ts, args)
		t.entity(e.Entity).npc = e.NPC
	case game.Player:
		t.on(e.Entity, "Player", ts, args)
		if e.Name != "" {
			t.entity(e.Entity).name = e.Name
		}
	case game.Kill:
		t.on(e.Entity, "Kill", ts, args)
		t.entity(e.Actor).name = e.Name
	case game.Death:
		t.on(e.Entity, "Death", ts, args)
	case game.Move:
		t.on(e.Entity, "Move", ts, args)
	}
}

// on writes an instant on id's track.
func (t *trace) on(id game.Entity, name string, ts int64, args json.RawMessage) {
	t.emit(t.instant(id, name, ts, args))
}

// instant is an instant on id's track, which it opens.
func (t *trace) instant(id game.Entity, name string, ts int64, args json.RawMessage) traceEvent {
	t.entity(id)
	return traceEvent{Name: name, Ph: "i", TS: ts, PID: byEntity, TID: uint32(id), S: "t", Args: args}
}

func (t *trace) emit(e traceEvent) {
	b, _ := json.Marshal(e) // args are JSON already, or maps of strings and numbers
	if t.n > 0 {
		t.w.WriteString(",\n")
	}
	t.w.Write(b)
	t.n++
}

// entity is id's track, opened the first time.
func (t *trace) entity(id game.Entity) *entity {
	en, ok := t.entities[id]
	if !ok {
		en = &entity{sort: len(t.entities)}
		t.entities[id] = en
	}
	return en
}

// end writes the Casts that never ended, as instants, and the tracks' names and order.
//
// @REVIEW: works for now but a bit unmaintainable.
func (t *trace) end() {
	for _, c := range slices.SortedFunc(maps.Values(t.casts), func(a, b traceEvent) int { return cmp.Compare(a.TS, b.TS) }) {
		t.emit(c)
	}
	meta := func(pid int, tid uint32, name string, args any) {
		t.emit(traceEvent{Name: name, Ph: "M", PID: pid, TID: tid, Args: args})
	}
	meta(byOpcode, 0, "process_name", map[string]string{"name": "by opcode"})
	meta(byEntity, 0, "process_name", map[string]string{"name": "by entity"})
	for _, tid := range slices.Sorted(maps.Keys(t.ops)) {
		op, name := wire.Opcode(tid), ""
		if tid&clientTrack != 0 {
			name = "client " + op.String()
		} else {
			name = strings.TrimSpace(op.String() + " " + game.Name(op))
		}
		meta(byOpcode, tid, "thread_name", map[string]string{"name": name})
		meta(byOpcode, tid, "thread_sort_index", map[string]uint32{"sort_index": tid})
	}
	for _, id := range slices.Sorted(maps.Keys(t.entities)) {
		en := t.entities[id]
		meta(byEntity, uint32(id), "thread_name", map[string]string{"name": en.label(id)})
		meta(byEntity, uint32(id), "thread_sort_index", map[string]int{"sort_index": en.sort})
	}
}

package main

import (
	"bufio"
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/nuriland/a2kit"
	"github.com/nuriland/a2kit/a2log"
	"github.com/nuriland/a2kit/game"
	"github.com/nuriland/a2kit/wire"
)

// output is where a command writes, either -o's file, or stdout
type output struct {
	*bufio.Writer
	f    *os.File
	live bool
}

func (w *output) flushLive() error {
	if w.live {
		return w.Flush()
	}
	return nil
}

func (w *output) Close() error {
	err := w.Flush()
	if w.f != nil {
		err = errors.Join(err, w.f.Close())
	}
	return err
}

type printer struct {
	json, wire bool
	hideTicks  bool
	w          *output
	t0         time.Time
}

func printing(fs *flag.FlagSet) *printer {
	p := new(printer)
	fs.BoolVar(&p.json, "json", false, "write a JSON line a message, for scripts; a2k help types says what is in it")
	fs.BoolVar(&p.wire, "wire", false, "write the protocol's view of each message: its type, size, flags and endpoints")
	return p
}

func (p *printer) check() error {
	if p.json && p.wire {
		return usagef("-json and -wire are two ways to write a line; take one")
	}
	return nil
}

func (p *printer) print(m a2kit.Message) error {
	if p.t0.IsZero() {
		p.t0 = m.Time
	}
	if p.hideTicks && typeName(m) == "Tick" {
		return nil
	}
	switch {
	case p.json:
		p.w.Write(marshal(m, p.t0))
		p.w.WriteByte('\n')
	case p.wire:
		fmt.Fprintf(p.w, "t=%d ts=%s type=%q name=%s len=%d flags=%v src=%v dst=%v\n",
			m.Time.Sub(p.t0).Milliseconds(), m.Time.UTC().Format(time.RFC3339Nano), m.Opcode.String(),
			cmp.Or(typeName(m), "-"), len(m.Payload), m.Flags, m.Src, m.Dst)
	default:
		label := cmp.Or(typeName(m), m.Opcode.String())
		if m.Flags&wire.FromClient != 0 {
			label = "client"
		}
		fmt.Fprintf(p.w, "%9.3f  %-9s  %s\n", float64(m.Time.Sub(p.t0).Milliseconds())/1000, label, readable(m))
	}
	return p.w.flushLive()
}

// typeName is what game calls m's type, nothing for the client's messages, whose types are obfuscated (?)
func typeName(m a2kit.Message) string {
	if m.Flags&wire.FromClient != 0 {
		return ""
	}
	return game.Name(m.Opcode)
}

// readable is what a line says of m after its name.
func readable(m a2kit.Message) string {
	switch {
	case m.Flags&wire.FromClient != 0:
		return fmt.Sprintf("(encrypted, %s)", plural(len(m.Payload), "byte"))
	case m.Err == nil:
		return fields(m.Event)
	case m.Failed():
		return fmt.Sprintf("(failed: %s; %s)", strings.TrimPrefix(m.Err.Error(), "game: "), plural(len(m.Payload), "byte"))
	case game.Name(m.Opcode) == "":
		return fmt.Sprintf("(unknown type, %s)", plural(len(m.Payload), "byte"))
	}
	return fmt.Sprintf("(not decoded, %s)", plural(len(m.Payload), "byte"))
}

// plural is n of what, "1 packet" or "3382 packets".
func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

// fields writes e's fields as key=value, the keys in lower case, leaving out those that are zero. Clocks are in local time, as -at takes them.
func fields(e game.Event) string {
	var b strings.Builder
	var add func(v reflect.Value)
	add = func(v reflect.Value) {
		for i := range v.NumField() {
			f, sf := v.Field(i), v.Type().Field(i)
			if sf.Anonymous {
				add(f) // Pos, as x, y and z
				continue
			}
			if f.IsZero() {
				continue
			}
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(strings.ToLower(sf.Name) + "=")
			switch x := f.Interface().(type) {
			case float32:
				fmt.Fprintf(&b, "%.1f", x)
			case time.Time:
				b.WriteString(x.Local().Format("15:04:05.000"))
			case []byte:
				fmt.Fprintf(&b, "%x", x)
			case string:
				if strings.ContainsAny(x, " \"=") {
					x = fmt.Sprintf("%q", x)
				}
				b.WriteString(x)
			default:
				fmt.Fprint(&b, x)
			}
		}
	}
	add(reflect.ValueOf(e))
	return b.String()
}

type jsonLine struct {
	T       int64       `json:"t"`                 // milliseconds after the first message
	TS      time.Time   `json:"ts"`                // when the packet that completed the message came, UTC
	Type    wire.Opcode `json:"type"`              // the message type, two bytes in wire order
	Flags   wire.Flags  `json:"flags"`             // server or client, then lz4, bundled, resynced. Only with -stream can a message have neither
	Name    string      `json:"name,omitempty"`    // what a2k calls the type, if anything
	Event   game.Event  `json:"event,omitempty"`   // the fields of the type, when decoded
	Payload string      `json:"payload,omitempty"` // the message's bytes in hex, when not decoded or failed
	Error   string      `json:"error,omitempty"`   // why it failed: "game: ...", or "json: ..." for a position JSON cannot hold
}

func marshal(m a2kit.Message, t0 time.Time) []byte {
	l := jsonLine{T: m.Time.Sub(t0).Milliseconds(), TS: m.Time.UTC(), Type: m.Opcode, Flags: m.Flags, Name: typeName(m)}
	err := m.Err
	if err == nil {
		l.Event = m.Event
		b, jerr := json.Marshal(l)
		if jerr == nil {
			return b
		}
		l.Event, err = nil, jerr // a position that is NaN or infinite
	}
	l.Payload = fmt.Sprintf("% x", m.Payload)
	if !errors.Is(err, game.ErrUnread) {
		l.Error = err.Error()
	}
	b, _ := json.Marshal(l) // numbers and strings only
	return b
}

func finish(o *options, r *a2kit.Reader, out *output, err error) error {
	err = errors.Join(err, r.Close())
	if out != nil {
		err = errors.Join(err, out.Close())
	}

	err = errors.Join(err, o.close())
	sum := r.Summary()
	if sum.Lost != nil {
		fmt.Fprintln(o.stderr, "a2k:", strings.ReplaceAll(sum.Lost.Error(), "\n", "\na2k: "))
	}

	src := r.Source
	if o.file != "" {
		src.Path = o.file // the file read, not where a log says its frames came from
	}
	summarize(o.stderr, src, r.Log, sum, err)
	return err
}

// summarize prints what a command read, in a line of key=value
func summarize(w io.Writer, src a2log.Source, log bool, sum a2kit.Summary, err error) {
	if sum.CutShort > 0 {
		fmt.Fprintf(w, "a2k: the recording cut %d packets short, and the bytes cut are lost; pktmon needs --pkt-size 0\n", sum.CutShort)
	}
	if sum.Messages == 0 && err == nil {
		if src.Kind == "live" && !log {
			fmt.Fprintln(w, "a2k: no game messages; is the game running, on the adapter captured? a2k adapters lists them")
		} else {
			fmt.Fprintln(w, "a2k: no game messages in", src.Path)
		}
	}

	state := "done"
	if err != nil {
		state = "stopped"
	}
	fmt.Fprintf(w, "a2k: %s messages=%d decoded=%d not_decoded=%d failed=%d", state, sum.Messages, sum.Decoded, sum.Unread, sum.Failed)
	if !log { // a log has no decoder to count
		fmt.Fprintf(w, " sessions=%d", sum.Locks)
		if sum.Locks > 0 {
			fmt.Fprintf(w, " server=%v client=%v", sum.Server, sum.Client)
		}
		fmt.Fprintf(w, " resyncs=%d client_resyncs=%d", sum.Resyncs, sum.ClientResyncs)
	}
	if !log && src.Kind == "pcap" {
		fmt.Fprintf(w, " cut_short=%d", sum.CutShort)
	}
	fmt.Fprintln(w)
}

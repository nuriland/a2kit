package main

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"io"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nuriland/a2kit/capture"
	"github.com/nuriland/a2kit/internal/wiretest"
	"github.com/nuriland/a2kit/wire"
)

var (
	server = netip.MustParseAddrPort("10.0.0.2:13328")
	client = netip.MustParseAddrPort("10.0.0.1:10000")
	start  = time.Unix(1000, 0)
)

const summaryLine = "10.0.0.2:13328 to 10.0.0.1:10000: 29.8s, 135 frames of 5 opcodes; the client sent 64 segments, of 11 bytes all the time"

// A sending is one side's payload at a moment.
type sending struct {
	at       time.Duration
	src, dst netip.AddrPort
	payload  []byte
	delay    time.Duration
	again    bool
}

// packet is a segment ready for the file.
type packet struct {
	t    time.Time
	data []byte
}

// pcapng writes the script as a pcapng file, every packet on each of ifaces interfaces.
func pcapng(t *testing.T, script []sending, ifaces int) *capture.Reader {
	slices.SortStableFunc(script, func(a, b sending) int { return cmp.Compare(a.at, b.at) })
	seq := make(map[netip.AddrPort]uint32)
	var pk []packet
	for _, s := range script {
		if s.again {
			seq[s.src] -= uint32(len(s.payload))
		}
		pk = append(pk, packet{start.Add(s.at + s.delay), wiretest.TCP(s.src, s.dst, seq[s.src], 0, 0x18, s.payload)})
		seq[s.src] += uint32(len(s.payload))
	}
	slices.SortStableFunc(pk, func(a, b packet) int { return a.t.Compare(b.t) })
	p := wiretest.NewPcapng(binary.LittleEndian)
	for range ifaces {
		p.Interface(101, 9, 0)
	}
	for _, k := range pk {
		for id := range ifaces {
			p.Packet(id, k.t, k.data)
		}
	}
	r, err := capture.NewReader(bytes.NewReader(p.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func record(t *testing.T, script []sending, ifaces int) *session {
	s, err := read(pcapng(t, script, ifaces))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// frame is a frame of op0 op1 and payload, as wiretest.AppendFrame counts it.
func frame(op0, op1 byte, payload ...byte) []byte {
	b := binary.AppendUvarint(nil, uint64(2+len(payload)+4))
	return append(append(b, op0, op1), payload...)
}

// tick is the server's 00 36 with an 8-byte clock.
func tick(ms uint64) []byte { return frame(0x00, 0x36, binary.LittleEndian.AppendUint64(nil, ms)...) }

// play is thirty seconds of a session
//   - a tick a second and a movement frame every 300 ms from the server,
//   - an 11-byte segment every 500 ms from the client,
//   - the player acting at 10 s and 20 s, answered by 01 38 and 3B 38, and once by 35 38.
//   - the second answer arrives out of order: 01 38, sent at 20.15 s, is captured at 20.25 s, after the 3B 38 that the decoder holds until then.
//   - At 25 s the client sends 7 bytes that nothing answers.
func play() []sending {
	var s []sending
	srv := func(at time.Duration, p []byte) { s = append(s, sending{at: at, src: server, dst: client, payload: p}) }
	cli := func(at time.Duration, size int) {
		s = append(s, sending{at: at, src: client, dst: server, payload: wiretest.AppendFrame(nil, 0xAA, 0xBB, size-3)})
	}
	for i := range 30 {
		srv(time.Duration(i)*time.Second, tick(uint64(1000000+i*1000)))
	}
	for i := range 100 {
		srv(100*time.Millisecond+time.Duration(i)*300*time.Millisecond, frame(0x1D, 0x37, 0xAC, 0x02, 1, 2, 3, 4, 5, 6, 7, 8, byte(i)))
	}
	for i := range 60 {
		cli(50*time.Millisecond+time.Duration(i)*500*time.Millisecond, 11)
	}
	cli(10*time.Second, 38)
	srv(10150*time.Millisecond, frame(0x01, 0x38, 0x05, 0x00, 0x00, 0xE0, 0x26, 0xA8, 0x00))
	srv(10200*time.Millisecond, frame(0x3B, 0x38, 0x05, 0x00))
	cli(20*time.Second, 45)
	cli(20100*time.Millisecond, 7)
	s = append(s, sending{at: 20150 * time.Millisecond, delay: 100 * time.Millisecond, src: server, dst: client,
		payload: frame(0x01, 0x38, 0x05, 0x13, 0x18, 0xD0, 0xFF, 0xA7, 0x00)})
	srv(20200*time.Millisecond, frame(0x3B, 0x38, 0x05, 0x00))
	srv(20300*time.Millisecond, frame(0x35, 0x38, 1, 2, 3, 4, 5))
	cli(25*time.Second, 7)
	return s
}

func TestViews(t *testing.T) {
	s := record(t, play(), 1)
	marks := func(list string) []time.Time {
		m, err := parseMarks(list, s.start)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	tests := []struct {
		name string
		view func(io.Writer)
		want string
	}{
		{"table", func(w io.Writer) { s.table(w, nil, time.Second) }, summaryLine + `
opcode  frames  share  payload  note
1D 37   100     74.1%  11       background
00 36   30      22.2%  8        known, background
01 38   2       1.5%   7        -
3B 38   2       1.5%   2        -
35 38   1       0.7%   5        known
`},
		{"marks", func(w io.Writer) { s.table(w, marks("10s,20s"), time.Second) }, summaryLine + `
opcode  frames  share  payload  note               marks  within  idle/s
01 38   2       1.5%   7        -                  2/2    2       0.00
3B 38   2       1.5%   2        -                  2/2    2       0.00
00 36   30      22.2%  8        known, background  2/2    2       1.01
1D 37   100     74.1%  11       background         2/2    7       3.35
35 38   1       0.7%   5        known              1/2    1       0.00
`},
		// The windows overlap by half a second, so their frames count once and the idle time
		// loses 1.5 s.
		{"overlapping marks", func(w io.Writer) { s.table(w, marks("10s,10.5s"), time.Second) }, summaryLine + `
opcode  frames  share  payload  note               marks  within  idle/s
00 36   30      22.2%  8        known, background  2/2    2       0.99
1D 37   100     74.1%  11       background         2/2    5       3.36
01 38   2       1.5%   7        -                  1/2    1       0.04
3B 38   2       1.5%   2        -                  1/2    1       0.04
35 38   1       0.7%   5        known              0/2    0       0.04
`},
		// The window runs 29.2 s past the session, and covers only 0.8 s of it.
		{"a mark near the end", func(w io.Writer) { s.table(w, marks("29s"), 30*time.Second) }, summaryLine + `
opcode  frames  share  payload  note               marks  within  idle/s
00 36   30      22.2%  8        known, background  1/1    1       1.00
1D 37   100     74.1%  11       background         1/1    3       3.34
35 38   1       0.7%   5        known              0/1    0       0.03
01 38   2       1.5%   7        -                  0/1    0       0.07
3B 38   2       1.5%   2        -                  0/1    0       0.07
`},
		{"a window over the whole session", func(w io.Writer) { s.table(w, marks("0s"), time.Minute) }, summaryLine + `
opcode  frames  share  payload  note               marks  within  idle/s
1D 37   100     74.1%  11       background         1/1    100     -
00 36   30      22.2%  8        known, background  1/1    30      -
01 38   2       1.5%   7        -                  1/1    2       -
3B 38   2       1.5%   2        -                  1/1    2       -
35 38   1       0.7%   5        known              1/1    1       -
`},
		{"anchors", func(w io.Writer) { s.anchors(w, time.Second) }, summaryLine + `; 00 36, 1D 37 come whether the player acts or not, and are left out
at      client sent  server answered
10.00s  38           01 38, 3B 38
20.00s  45 7         3B 38, 01 38, 35 38
25.00s  7            -
`},
		// A window of ten seconds reaches from one burst into the next, and stops there.
		{"anchors close together", func(w io.Writer) { s.anchors(w, 10*time.Second) }, summaryLine + `; 00 36, 1D 37 come whether the player acts or not, and are left out
at      client sent  server answered
10.00s  38           01 38, 3B 38
20.00s  45 7         3B 38, 01 38, 35 38
25.00s  7            -
`},
		{"bytes", func(w io.Writer) { s.bytes(w, 0x3801) }, `01 38: 2 frames, payload 7
  byte  0: 05 x2
  byte  1: 00 x1, 13 x1
  byte  2: 00 x1, 18 x1
  byte  3: d0 x1, e0 x1
  byte  4: 26 x1, ff x1
  byte  5: a7 x1, a8 x1
  byte  6: 00 x2
first varint: 1 value, shared with 3B 38 (1)
first frames:
  10.15s  05 00 00 e0 26 a8 00
  20.25s  05 13 18 d0 ff a7 00
`},
		{"bytes of an opcode never sent", func(w io.Writer) { s.bytes(w, 0x3899) }, "99 38: no frames\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			tt.view(&out)
			if got := out.String(); got != tt.want {
				t.Errorf("got:\n%swant:\n%s", got, tt.want)
			}
		})
	}
}

func TestDuplicateInterface(t *testing.T) {
	one, two := record(t, play(), 1), record(t, play(), 2)
	if len(two.frames) != len(one.frames) || len(two.sent) != len(one.sent) {
		t.Errorf("two interfaces gave %d frames and %d segments, one gave %d and %d",
			len(two.frames), len(two.sent), len(one.frames), len(one.sent))
	}
}

func TestRetransmit(t *testing.T) {
	odd := wiretest.AppendFrame(nil, 0xAA, 0xBB, 35)
	script := []sending{
		{at: 0, src: server, dst: client, payload: tick(0)},
		{at: time.Second, src: server, dst: client, payload: tick(1)},
		{at: 2 * time.Second, src: server, dst: client, payload: tick(2)},
		{at: 10 * time.Second, src: client, dst: server, payload: odd},
		{at: 10300 * time.Millisecond, src: client, dst: server, payload: odd, again: true},
	}
	if s := record(t, script, 1); len(s.sent) != 1 {
		t.Errorf("%d segments sent, want 1: a retransmit is not a send", len(s.sent))
	}
}

func TestNoLock(t *testing.T) {
	var script []sending
	for i := range 3 {
		script = append(script, sending{at: time.Duration(i) * time.Second, src: client, dst: server, payload: wiretest.AppendFrame(nil, 0xAA, 0xBB, 8)})
	}
	if _, err := read(pcapng(t, script, 1)); err == nil {
		t.Error("no error for a capture with no server")
	}
}

func TestSecondLock(t *testing.T) {
	var (
		other  = netip.MustParseAddrPort("10.0.0.3:13328")
		script = make([]sending, 0, 13)
	)
	for i := range 5 {
		script = append(script, sending{at: time.Duration(i) * time.Second, src: server, dst: client, payload: tick(uint64(i))})
	}
	for i := range 8 {
		script = append(script, sending{at: 70*time.Second + time.Duration(i)*time.Second, src: other, dst: client, payload: tick(uint64(i))})
	}
	s := record(t, script, 1)
	if s.locks != 2 || s.server != other || len(s.frames) != 8 {
		t.Errorf("locks %d, server %v, %d frames; want 2, %v, 8", s.locks, s.server, len(s.frames), other)
	}
}

func TestParseMarks(t *testing.T) {
	var (
		clock      = start.Local().Add(10 * time.Second).Format("15:04:05")
		marks, err = parseMarks("20s, "+clock, start)
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := []time.Time{start.Add(10 * time.Second), start.Add(20 * time.Second)}; !slices.EqualFunc(marks, want, time.Time.Equal) {
		t.Errorf("marks %v, want %v", marks, want)
	}
	late := time.Date(2026, 1, 1, 23, 59, 30, 0, time.Local) // a capture over midnight
	if marks, err := parseMarks("00:00:40", late); err != nil || !marks[0].Equal(late.Add(70*time.Second)) {
		t.Errorf("past midnight: %v, %v; want %v", marks, err, late.Add(70*time.Second))
	}
	if _, err := parseMarks("10s,soon", start); err == nil {
		t.Error("no error for a mark that is neither an offset nor a clock time")
	}
	if marks, err := parseMarks("", start); err != nil || marks != nil {
		t.Errorf("no marks gave %v, %v", marks, err)
	}
}

func TestParseOpcode(t *testing.T) {
	for _, in := range []string{"01 38", "0138"} {
		if op, err := parseOpcode(in); err != nil || op != wire.Opcode(0x3801) {
			t.Errorf("parseOpcode(%q) = %v, %v", in, op, err)
		}
	}
	for _, in := range []string{"", "01", "01 38 00", "zz 38"} {
		if _, err := parseOpcode(in); err == nil {
			t.Errorf("parseOpcode(%q): no error", in)
		}
	}
}

func TestValidateFlags(t *testing.T) {
	defer func() { *window, *op, *at, *anchors = time.Second, "", "", false }()
	tests := []struct {
		window  time.Duration
		op, at  string
		anchors bool
		ok      bool
	}{
		{time.Second, "", "", false, true},
		{time.Second, "01 38", "", false, true},
		{time.Second, "", "10s", false, true},
		{time.Second, "", "", true, true},
		{0, "", "", false, false},
		{-time.Second, "", "", false, false},
		{time.Second, "01 38", "", true, false},
		{time.Second, "01 38", "10s", false, false},
		{time.Second, "", "10s", true, false},
	}
	for _, tt := range tests {
		*window, *op, *at, *anchors = tt.window, tt.op, tt.at, tt.anchors
		if err := validateFlags(); (err == nil) != tt.ok {
			t.Errorf("-window %v -op %q -at %q -anchors=%v: %v", tt.window, tt.op, tt.at, tt.anchors, err)
		}
	}
}

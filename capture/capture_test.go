package capture

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/nuriland/a2kit/internal/wiretest"
	"github.com/nuriland/a2kit/wire"
)

// decode reads a whole capture through a fresh decoder.
func decode(r wire.SegmentReader) ([]wire.Frame, error) {
	var fs []wire.Frame
	for f, err := range wire.NewDecoder(wire.Config{}).Decode(r) {
		if err != nil {
			return fs, err
		}
		fs = append(fs, f)
	}
	return fs, nil
}

// lines prints frames as a2kit dump does, a line each, and without their
// timestamps if timeless is set.
func lines(fs []wire.Frame, timeless bool) string {
	var b strings.Builder
	for _, f := range fs {
		line := f.String()
		if timeless {
			_, line, _ = strings.Cut(line, " ")
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// The server's stream arrives out of order, with a retransmit, among noise.
func TestSample(t *testing.T) {
	f, err := Open("testdata/sample.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fs, err := decode(f)
	if err != nil {
		t.Fatal(err)
	}
	got := lines(fs, true)

	// The segment sent third, at 6 ms, fills the gap and completes the first two frames. The last
	// two came wholly in the segment sent second, and keep its time.
	var times []int64
	for _, f := range fs {
		times = append(times, f.Time.UnixNano()-1700000000000000000)
	}
	if want := []int64{6e6, 6e6, 5e6, 5e6}; !slices.Equal(times, want) {
		t.Errorf("stamped %v ns past the start, want %v", times, want)
	}

	b, err := os.ReadFile("testdata/sample.expect.json")
	if err != nil {
		t.Fatal(err)
	}
	var wants []struct {
		Opcode     string `json:"opcode"`
		PayloadLen int    `json:"payload_len"`
		Flags      string `json:"flags"`
	}
	if err := json.Unmarshal(b, &wants); err != nil {
		t.Fatal(err)
	}
	var want strings.Builder
	for _, w := range wants {
		fmt.Fprintf(&want, "opcode=%s len=%d flags=%s src=10.0.0.2:13328 dst=10.0.0.1:10000\n",
			w.Opcode, w.PayloadLen, w.Flags)
	}
	if got != want.String() {
		t.Errorf("frames:\n%swant:\n%s", got, want.String())
	}
}

// packets returns every packet in a capture, TCP or not.
func packets(t *testing.T, file []byte) []packet {
	t.Helper()
	c, err := newContainer(bytes.NewReader(file))
	if err != nil {
		t.Fatal(err)
	}
	var ps []packet
	for {
		p, err := c.next()
		if err == io.EOF {
			return ps
		}
		if err != nil {
			t.Fatal(err)
		}
		p.data = bytes.Clone(p.data)
		ps = append(ps, p)
	}
}

// Every way of writing the sample capture down reads back the same.
func TestFormats(t *testing.T) {
	sample, err := os.ReadFile("testdata/sample.pcap")
	if err != nil {
		t.Fatal(err)
	}
	ps := packets(t, sample)
	r, err := NewReader(bytes.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	want, err := decode(r)
	if err != nil {
		t.Fatal(err)
	}

	pcap := func(order binary.AppendByteOrder, nano bool) []byte {
		w := wiretest.NewPcap(order, nano, linkEthernet)
		for _, p := range ps {
			w.Add(p.time, p.data)
		}
		return w.Bytes()
	}
	pcapng := func(order binary.AppendByteOrder, res byte, offset int64) []byte {
		w := wiretest.NewPcapng(order)
		w.Interface(linkEthernet, res, offset)
		for _, p := range ps {
			w.Packet(0, p.time, p.data)
		}
		return w.Bytes()
	}
	// The noise, sent as raw IP on an interface of its own, around blocks
	// a reader has no use for.
	mixed := func() []byte {
		w := wiretest.NewPcapng(binary.LittleEndian)
		w.Block(0x0000_0BAD, []byte("custom"))
		w.Interface(linkEthernet, 6, 0)
		w.Interface(101, 9, 0) // raw IP
		for i, p := range ps {
			w.Block(0x0000_0005, make([]byte, 20)) // interface statistics
			if i == 0 || i == len(ps)-1 {
				w.Packet(1, p.time, p.data[14:])
				continue
			}
			w.Packet(0, p.time, p.data)
		}
		return w.Bytes()
	}
	simple := func() []byte {
		w := wiretest.NewPcapng(binary.BigEndian)
		w.Interface(linkEthernet, 6, 0)
		for _, p := range ps {
			w.Simple(p.data)
		}
		return w.Bytes()
	}
	sections := func() []byte {
		a := wiretest.NewPcapng(binary.LittleEndian)
		a.Interface(linkEthernet, 6, 0)
		b := wiretest.NewPcapng(binary.BigEndian)
		b.Interface(linkEthernet, 9, 0)
		for i, p := range ps {
			if i < len(ps)/2 {
				a.Packet(0, p.time, p.data)
			} else {
				b.Packet(0, p.time, p.data)
			}
		}
		return append(a.Bytes(), b.Bytes()...)
	}

	tests := []struct {
		name     string
		file     []byte
		timeless bool // the format cannot keep every timestamp
	}{
		{"pcap big-endian", pcap(binary.BigEndian, false), false},
		{"pcap nanoseconds", pcap(binary.LittleEndian, true), false},
		{"pcapng", pcapng(binary.LittleEndian, 6, 0), false},
		{"pcapng big-endian", pcapng(binary.BigEndian, 6, 0), false},
		{"pcapng nanoseconds", pcapng(binary.LittleEndian, 9, 0), false},
		{"pcapng offset", pcapng(binary.LittleEndian, 9, 1700000000), false},
		{"pcapng milliseconds", pcapng(binary.LittleEndian, 3, 0), false},
		{"pcapng binary ticks", pcapng(binary.LittleEndian, 0x80|20, 0), true},
		{"pcapng mixed", mixed(), false},
		{"pcapng simple blocks", simple(), true},
		{"pcapng two sections", sections(), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := NewReader(bytes.NewReader(tt.file))
			if err != nil {
				t.Fatal(err)
			}
			got, err := decode(r)
			if err != nil {
				t.Fatal(err)
			}
			if g, w := lines(got, tt.timeless), lines(want, tt.timeless); g != w {
				t.Errorf("frames:\n%swant:\n%s", g, w)
			}
		})
	}
}

// A capture cut short yields what it holds, then says it was cut.
func TestTruncated(t *testing.T) {
	sample, err := os.ReadFile("testdata/sample.pcap")
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewReader(bytes.NewReader(sample[:len(sample)-40]))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := decode(r)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("err = %v, want io.ErrUnexpectedEOF", err)
	}
	if len(fs) != 4 {
		t.Errorf("%d frames before the cut, want 4:\n%s", len(fs), lines(fs, false))
	}
}

func TestNotACapture(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("GIF89a, not a capture at all")} {
		if _, err := NewReader(bytes.NewReader(b)); err == nil {
			t.Errorf("NewReader(%q) took it", b)
		}
	}
}

func TestOpenLiveNoDevice(t *testing.T) {
	if _, err := OpenLive("a2kit-no-such-device"); err == nil {
		t.Error("opened a device that is not there")
	}
}

func FuzzReader(f *testing.F) {
	sample, err := os.ReadFile("testdata/sample.pcap")
	if err != nil {
		f.Fatal(err)
	}
	ng := wiretest.NewPcapng(binary.LittleEndian)
	ng.Interface(linkEthernet, 9, 0)
	ng.Packet(0, packetTime, wiretest.Ethernet(wiretest.TCP(src4, dst4, 1, 0x18, []byte("frame"))))
	f.Add(sample)
	f.Add(ng.Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := NewReader(bytes.NewReader(b))
		if err != nil {
			return
		}
		for range 1000 {
			if _, err := r.ReadSegment(); err != nil {
				return
			}
		}
	})
}

//go:build cgo

package capture

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gopacket/gopacket/pcap"

	"github.com/nuriland/a2kit/wire"
)

func TestRecord(t *testing.T) {
	h, err := pcap.OpenOffline("testdata/sample.pcap")
	if err != nil {
		t.Fatal(err)
	}
	l := &Live{h: h, link: int(h.LinkType())}
	defer l.Close()
	name := filepath.Join(t.TempDir(), "rec.pcap")
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Record(f); err != nil {
		t.Fatal(err)
	}
	live, err := decode(l)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	want := lines(decodeFile(t, "testdata/sample.pcap"), false)
	if got := lines(live, false); got != want {
		t.Errorf("live:\n%swant:\n%s", got, want)
	}
	if got := lines(decodeFile(t, name), false); got != want {
		t.Errorf("replayed recording:\n%swant:\n%s", got, want)
	}
	if got, w := libpcap(t, name), libpcap(t, "testdata/sample.pcap"); !slices.Equal(got, w) {
		t.Errorf("libpcap reads %d packets from the recording, not the sample's %d as they were", len(got), len(w))
	}
}

func decodeFile(t *testing.T, name string) []wire.Frame {
	t.Helper()
	f, err := Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fs, err := decode(f)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

type captured struct {
	time    int64 // ns
	capLen  int
	origLen int
	data    string
}

func libpcap(t *testing.T, name string) []captured {
	t.Helper()
	h, err := pcap.OpenOffline(name)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	var ps []captured
	for {
		data, ci, err := h.ReadPacketData()
		if err == io.EOF {
			return ps
		}
		if err != nil {
			t.Fatal(err)
		}
		ps = append(ps, captured{ci.Timestamp.UnixNano(), ci.CaptureLength, ci.Length, string(data)})
	}
}

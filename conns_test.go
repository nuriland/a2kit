package a2kit

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nuriland/a2kit/capture"
	"github.com/nuriland/a2kit/internal/wiretest"
	"github.com/nuriland/a2kit/wire"
)

// A packet a conns test sends: who to whom, with what flags, how many bytes.
type hop struct {
	src, dst netip.AddrPort
	seq      uint32
	flags    wire.TCPFlags
	n        int
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func wrap(h hop) []byte {
	return wiretest.Ethernet(wiretest.TCP(h.src, h.dst, h.seq, 0, byte(h.flags), make([]byte, h.n)))
}

func talked(t *testing.T, p []byte) []Connection {
	t.Helper()
	r, err := capture.NewReader(bytes.NewReader(p))
	if err != nil {
		t.Fatal(err)
	}
	cs, err := connections(r, wire.NewDecoder(wire.Config{}))
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func line(c Connection) string {
	return fmt.Sprintf("%v>%v syn=%d synack=%d fin=%t rst=%t sent=%d recv=%d %s", c.Client, c.Server, c.SYN, c.SYNACK, c.FIN, c.RST, c.Sent, c.Received, c.Status)
}

var t0 = time.Unix(1_700_000_000, 0)

func TestConnections(t *testing.T) {
	var (
		a1, a2, a3, a4, a5, a6 = ap("10.0.0.1:50001"), ap("10.0.0.1:50002"), ap("10.0.0.1:50003"), ap("10.0.0.1:50004"), ap("10.0.0.1:50005"), ap("10.0.0.1:50006")
		web, none, world       = ap("10.0.0.2:443"), ap("10.0.0.3:80"), ap("10.0.0.4:13700")
		db, half, ssh          = ap("10.0.0.5:3306"), ap("10.0.0.6:9000"), ap("10.0.0.7:22")
	)
	hops := []hop{
		{a1, web, 100, wire.SYN, 0}, {web, a1, 0, wire.RST | wire.ACK, 0}, // refused
		{a2, none, 100, wire.SYN, 0}, {a2, none, 100, wire.SYN, 0}, {a2, none, 100, wire.SYN, 0}, // no answer, three tries
		{a3, world, 100, wire.SYN, 0}, {world, a3, 500, wire.SYN | wire.ACK, 0}, {a3, world, 101, wire.ACK, 0}, // the handshake
		{a3, world, 101, wire.PSH | wire.ACK, 10}, {a3, world, 101, wire.PSH | wire.ACK, 10}, // ten bytes, then again
		{world, a3, 501, wire.PSH | wire.ACK, 5},
		{a3, world, 111, wire.FIN | wire.ACK, 0}, {world, a3, 506, wire.FIN | wire.ACK, 0}, {a3, world, 112, wire.RST, 0}, // the client's close
		{a3, world, 2000, wire.SYN, 0}, {world, a3, 3000, wire.SYN | wire.ACK, 0}, {a3, world, 2001, wire.ACK, 0}, // the port again
		{db, a4, 900, wire.PSH | wire.ACK, 7},                                 // begun before the recording
		{a5, half, 100, wire.SYN, 0}, {half, a5, 500, wire.SYN | wire.ACK, 0}, // never acked
		{ssh, a6, 500, wire.SYN | wire.ACK, 0}, {a6, ssh, 101, wire.ACK, 0}, {a6, ssh, 101, wire.PSH | wire.ACK, 3}, // caught from the SYN-ACK
	}
	want := strings.Join([]string{
		"10.0.0.1:50001>10.0.0.2:443 syn=1 synack=0 fin=false rst=true sent=0 recv=0 refused",
		"10.0.0.1:50002>10.0.0.3:80 syn=3 synack=0 fin=false rst=false sent=0 recv=0 no answer",
		"10.0.0.1:50003>10.0.0.4:13700 syn=1 synack=1 fin=true rst=true sent=10 recv=5 closed",
		"10.0.0.1:50003>10.0.0.4:13700 syn=1 synack=1 fin=false rst=false sent=0 recv=0 open",
		"10.0.0.1:50004>10.0.0.5:3306 syn=0 synack=0 fin=false rst=false sent=0 recv=7 already open",
		"10.0.0.1:50005>10.0.0.6:9000 syn=1 synack=1 fin=false rst=false sent=0 recv=0 half open",
		"10.0.0.1:50006>10.0.0.7:22 syn=0 synack=1 fin=false rst=false sent=3 recv=0 silent",
	}, "\n")

	p := wiretest.NewPcap(binary.LittleEndian, true, 1) // Ethernet
	for i, h := range hops {
		p.Add(t0.Add(time.Duration(i)*100*time.Millisecond), wrap(h)) // a tenth of a second apart, well past copyGap
	}
	cs := talked(t, p.Bytes())
	var got []string
	for _, c := range cs {
		got = append(got, line(c))
	}
	if g := strings.Join(got, "\n"); g != want {
		t.Fatalf("got\n%s\nwant\n%s", g, want)
	}
	if c := cs[2]; c.End.Sub(c.Start) != 800*time.Millisecond || c.Game || c.IfIndex != 0 {
		t.Errorf("the closed one: %+v", c)
	}
	if c := cs[3]; c.Start.Sub(cs[2].Start) != 900*time.Millisecond {
		t.Errorf("the reused port begins at %v after the first, want 900ms", c.Start.Sub(cs[2].Start))
	}
}

func TestConnectionsCopies(t *testing.T) {
	var (
		a, w  = ap("10.0.0.1:50001"), ap("10.0.0.4:13700")
		p     = wiretest.NewPcap(binary.LittleEndian, true, 1)
		twice = func(at time.Duration, h hop) {
			p.Add(t0.Add(at), wrap(h))
			p.Add(t0.Add(at+20*time.Microsecond), wrap(h))
		}
	)
	twice(0, hop{a, w, 100, wire.SYN, 0})
	twice(time.Second, hop{a, w, 100, wire.SYN, 0})
	twice(1100*time.Millisecond, hop{w, a, 500, wire.SYN | wire.ACK, 0})
	twice(1200*time.Millisecond, hop{a, w, 101, wire.ACK, 0})
	twice(1300*time.Millisecond, hop{a, w, 101, wire.PSH | wire.ACK, 10})

	cs := talked(t, p.Bytes())
	if len(cs) != 1 || cs[0].SYN != 2 || cs[0].SYNACK != 1 || cs[0].Sent != 10 || cs[0].Status != "silent" { // @TODO: some test helpers would be nice for these things
		t.Fatalf("%+v", cs)
	}
}

func TestConnectionsTwoAdapters(t *testing.T) {
	var (
		p    = wiretest.NewPcapng(binary.LittleEndian)
		syn  = wrap(hop{ap("10.0.0.1:50001"), ap("10.0.0.2:443"), 100, wire.SYN, 0})
		each = []int{p.Interface(1, 9, 0), p.Interface(1, 9, 0)}
	)
	for _, id := range each {
		p.Packet(id, t0, syn)
	}
	cs := talked(t, p.Bytes())
	if len(cs) != 2 || cs[0].SYN != 1 || cs[1].SYN != 1 || cs[0].IfIndex == cs[1].IfIndex {
		t.Fatalf("%+v", cs)
	}
}

func TestConnectionsRedirect(t *testing.T) {
	read := func(name string) []byte {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var (
		stream          = slices.Concat(read("game/testdata/redirect.bin"), read("game/testdata/lobbyping.bin"))
		a, lobby, world = ap("10.0.0.1:50001"), ap("10.0.0.9:13700"), ap("193.202.112.97:13328")
		b               = ap("10.0.0.1:50002")
		p               = wiretest.NewPcap(binary.LittleEndian, true, 1)
		at              = func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	)
	p.Add(at(0), wrap(hop{a, lobby, 100, wire.SYN, 0}))
	p.Add(at(1), wrap(hop{lobby, a, 500, wire.SYN | wire.ACK, 0}))
	p.Add(at(2), wrap(hop{a, lobby, 101, wire.ACK, 0}))
	p.Add(at(3), wiretest.Ethernet(wiretest.TCP(lobby, a, 501, 101, byte(wire.PSH|wire.ACK), stream)))
	p.Add(at(4), wrap(hop{b, world, 100, wire.SYN, 0}))
	p.Add(at(5), wrap(hop{world, b, 500, wire.SYN | wire.ACK, 0}))
	p.Add(at(6), wrap(hop{b, world, 101, wire.ACK, 0}))
	p.Add(at(7), wrap(hop{b, world, 101, wire.PSH | wire.ACK, 276}))

	cs := talked(t, p.Bytes())
	if len(cs) != 2 {
		t.Fatalf("%d connections: %+v", len(cs), cs)
	}
	if c := cs[0]; !c.Game || c.Status != "open" || c.Received != len(stream) || c.Failed() {
		t.Errorf("the lobby: %+v", c)
	}
	if c := cs[1]; !c.Game || c.Status != "silent" || c.Sent != 276 || !c.Failed() {
		t.Errorf("the world: %+v", c)
	}
}

func TestConnectionsGame(t *testing.T) {
	cs, err := Connections("capture/testdata/sample.pcap", Config{})
	if err != nil {
		t.Fatal(err)
	}
	game := 0
	for _, c := range cs {
		if c.Game {
			game++
		}
	}
	if len(cs) == 0 || game != 1 {
		t.Fatalf("%d connections, %d the game's: %+v", len(cs), game, cs)
	}
}

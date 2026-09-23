// Genfixtures writes the synthesized test fixtures: TCP payload streams for
// package wire, and a pcap for package capture, each with the frames it
// holds. The output is deterministic: run it again, and nothing changes.
//
//	go run ./internal/genfixtures [-root DIR]
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/nuriland/a2kit/internal/wiretest"
	"github.com/nuriland/a2kit/wire"
)

var root = flag.String("root", ".", "the module's root `directory`")

// What the decoder says of each frame.
const (
	server   = wire.FromServer
	bundled  = wire.FromServer | wire.WasLZ4 | wire.WasBundled
	resynced = wire.Resynced // on probation, so not toward the lock
	unlocked = wire.Flags(0) // a frame before the lock has no direction yet
)

// A fixture is what a server sends, and the frames a decoder must find in it.
type fixture struct {
	wire  []byte
	wants []want
}

type want struct {
	Opcode     string `json:"opcode"`
	PayloadLen int    `json:"payload_len"`
	Flags      string `json:"flags"`
}

// frame appends a frame to b, and expects it.
func (fx *fixture) frame(b []byte, op0, op1 byte, size int, flags wire.Flags) []byte {
	op := wire.Opcode(op0) | wire.Opcode(op1)<<8
	fx.wants = append(fx.wants, want{op.String(), size, flags.String()})
	return wiretest.AppendFrame(b, op0, op1, size)
}

func (fx *fixture) save(dir, name string) {
	write(filepath.Join(dir, name+".bin"), fx.wire)
	fx.saveWants(filepath.Join(dir, name+".expect.json"))
}

// saveWants writes the JSON an editor's formatter leaves as it is, so opening
// a fixture and saving it changes nothing.
func (fx *fixture) saveWants(path string) {
	wants := fx.wants
	if wants == nil {
		wants = []want{} // [], not null
	}
	b, err := json.MarshalIndent(wants, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	write(path, b)
}

func write(path string, b []byte) {
	if err := os.WriteFile(path, b, 0o644); err != nil {
		log.Fatal(err)
	}
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("genfixtures: ")
	flag.Parse()
	dir := filepath.Join(*root, "wire", "testdata")

	var fx fixture
	fx.wire = fx.frame(fx.wire, 0x04, 0x38, 41, unlocked) // combat locks with a known frame before it
	fx.wire = fx.frame(fx.wire, 0x04, 0x38, 41, server)
	fx.wire = fx.frame(fx.wire, 0x05, 0x38, 20, server)
	fx.wire = fx.frame(fx.wire, 0x33, 0x36, 12, server)
	fx.save(dir, "hit")

	fx = fixture{}
	fx.wire = fx.frame(fx.wire, 0x00, 0x36, 8, unlocked)
	var plain []byte
	plain = fx.frame(plain, 0x04, 0x38, 41, bundled)
	plain = fx.frame(plain, 0x2A, 0x38, 16, bundled)
	plain = fx.frame(plain, 0x1B, 0x92, 200, bundled)
	fx.wire = wiretest.AppendBundle(fx.wire, plain)
	fx.wire = fx.frame(fx.wire, 0x05, 0x38, 20, server)
	fx.save(dir, "bundle")

	fx = fixture{}
	fx.wire = fx.frame(fx.wire, 0x00, 0x36, 8, unlocked)
	plain = fx.frame(nil, 0x04, 0x38, 30, bundled)
	inner := fx.frame(nil, 0x05, 0x38, 20, bundled)
	inner = fx.frame(inner, 0x44, 0x36, 12, bundled)
	plain = wiretest.AppendBundle(plain, inner)
	fx.wire = wiretest.AppendBundle(fx.wire, plain)
	fx.save(dir, "nested")

	fx = fixture{wire: []byte{0xAA, 0xAA}}
	fx.wire = fx.frame(fx.wire, 0x04, 0x38, 41, resynced)
	fx.wire = fx.frame(fx.wire, 0x05, 0x38, 20, unlocked)
	fx.save(dir, "resync")

	fx = fixture{wire: []byte{0x16, 0x03, 0x01, 0x00, 0x2F}} // a TLS handshake record header
	fx.wire = wiretest.AppendFrame(fx.wire, 0x04, 0x38, 41)
	fx.save(dir, "tls")

	// Frames in 30-byte envelopes, straddling the envelope edges.
	fx = fixture{}
	plain = fx.frame(nil, 0x04, 0x38, 41, unlocked)
	plain = fx.frame(plain, 0x05, 0x38, 20, server)
	plain = fx.frame(plain, 0x33, 0x36, 12, server)
	for p := plain; len(p) > 0; {
		n := min(len(p), 30)
		fx.wire = binary.LittleEndian.AppendUint32(fx.wire, uint32(n))
		fx.wire = append(fx.wire, p[:n]...)
		p = p[n:]
	}
	fx.save(dir, "envelope")

	sample(filepath.Join(*root, "capture", "testdata"))
	fmt.Println("fixtures written under", *root)
}

// sample writes sample.pcap: HTTP noise on :8080, TLS on :443, the server's
// frames cut in three and sent first, third, second and second again, and a
// client frame, which a decoder drops by default.
func sample(dir string) {
	var fx fixture
	fx.wire = fx.frame(fx.wire, 0x04, 0x38, 41, unlocked)
	fx.wire = fx.frame(fx.wire, 0x2A, 0x38, 16, unlocked)
	fx.wire = fx.frame(fx.wire, 0x05, 0x38, 20, server)
	fx.wire = fx.frame(fx.wire, 0x33, 0x36, 12, server)
	fx.saveWants(filepath.Join(dir, "sample.expect.json"))

	var (
		srv   = netip.MustParseAddrPort("10.0.0.2:13328")
		cli   = netip.MustParseAddrPort("10.0.0.1:10000")
		web   = netip.MustParseAddrPort("10.0.0.3:8080")
		https = netip.MustParseAddrPort("10.0.0.4:443")
		lan   = netip.MustParseAddrPort("10.0.0.1:50000")
	)
	const data = byte(wire.PSH | wire.ACK)
	http := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello world")
	tls := slices.Concat([]byte{0x17, 0x03, 0x03, 0x00, 0x10, 0x06, 0x00, 0x36, 0x06, 0x00, 0x36}, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	isn := uint32(5000)
	a, b := 30, 70 // the server's segments are [0,a) [a,b) [b,end)
	w := fx.wire

	pc := wiretest.NewPcap(binary.LittleEndian, false, 1)
	at := func(ms int) time.Time { return time.Unix(1700000000, int64(ms)*int64(time.Millisecond)) }
	add := func(ms int, src, dst netip.AddrPort, seq uint32, flags byte, p []byte) {
		pc.Add(at(ms), wiretest.Ethernet(wiretest.TCP(src, dst, seq, 0, flags, p)))
	}
	add(0, web, lan, 1, data, http)
	add(2, https, lan, 1, data, tls)
	add(3, srv, cli, isn-1, byte(wire.SYN|wire.ACK), nil)
	add(4, srv, cli, isn, data, w[:a])
	add(5, srv, cli, isn+uint32(b), data, w[b:])
	add(6, srv, cli, isn+uint32(a), data, w[a:b])
	add(7, srv, cli, isn+uint32(a), data, w[a:b]) // a retransmit
	add(8, cli, srv, 900, data, wiretest.AppendFrame(nil, 0x33, 0x36, 5))
	add(9, web, lan, 1+uint32(len(http)), data, http)
	write(filepath.Join(dir, "sample.pcap"), pc.Bytes())
}

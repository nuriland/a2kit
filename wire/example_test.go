package wire_test

import (
	"fmt"
	"log"
	"net/netip"
	"os"
	"time"

	"github.com/nuriland/a2kit/capture"
	"github.com/nuriland/a2kit/wire"
)

func ExampleDecoder_Decode() {
	f, err := capture.Open("../capture/testdata/sample.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	d := wire.NewDecoder(wire.Config{})
	for fr, err := range d.Decode(f) {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(fr.Opcode, len(fr.Payload), fr.Flags)
	}
	// Output:
	// 04 38 41 -
	// 2A 38 16 -
	// 05 38 20 server
	// 33 36 12 server
}

func ExampleDecoder_Feed() {
	b, err := os.ReadFile("testdata/hit.bin") // the server's bytes, no TCP
	if err != nil {
		log.Fatal(err)
	}
	server := netip.MustParseAddrPort("10.0.0.2:13328")
	client := netip.MustParseAddrPort("10.0.0.1:10000")

	d := wire.NewDecoder(wire.Config{})
	d.Feed(time.Time{}, server, client, b)
	d.Flush()
	for f := range d.Frames() {
		fmt.Println(f.Opcode, len(f.Payload), f.Flags)
	}
	// Output:
	// 04 38 41 -
	// 04 38 41 server
	// 05 38 20 server
	// 33 36 12 server
}

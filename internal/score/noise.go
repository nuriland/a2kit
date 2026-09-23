package main

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"time"

	"github.com/nuriland/a2kit/wire"
)

// noise feeds runs of mb megabytes of random bytes to a hunting decoder, and runs of TLS records
// of 16 KiB, of which only the segment that starts one looks like TLS. It counts the runs that
// lock, which a stream of noise never should, and the rate the decoder parses noise at.
func noise(runs, mb int) {
	for _, tls := range []bool{false, true} {
		locked, fed, start := 0, 0, time.Now()
		for run := range runs {
			var (
				r   = rand.NewChaCha8([32]byte{byte(run), byte(run >> 8), 1})
				d   = wire.NewDecoder(wire.Config{EmitClient: true})
				src = netip.AddrPortFrom(netip.MustParseAddr("10.9.0.1"), uint16(2000+run))
				seg = make([]byte, 1400)
				hit = false
			)
			for i := 0; i < mb<<20/len(seg) && !hit; i++ {
				r.Read(seg)
				if tls && i%12 == 0 {
					copy(seg, []byte{0x17, 0x03, 0x03, 0x40, 0x00})
				}
				d.Feed(time.Unix(0, 0), src, cli, seg)
				fed += len(seg)
				for f := range d.Frames() {
					hit = hit || f.Flags&(wire.FromServer|wire.FromClient) != 0
				}
			}
			if hit {
				locked++
			}
		}
		kind := "random bytes"
		if tls {
			kind = "TLS records"
		}
		fmt.Printf("%s: %d of %d runs of %d MB locked; noise parsed at %.0f MB/s\n",
			kind, locked, runs, mb, float64(fed)/1e6/time.Since(start).Seconds())
	}
}

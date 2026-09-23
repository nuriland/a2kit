package wire

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

type Flags uint32

const (
	FromServer Flags = 1 << iota // sent by the locked server
	FromClient                   // sent by its client
	WasLZ4                       // the body was compressed with LZ4
	WasBundled                   // the body was bundled
	Resynced                     // the first frame after skipped or lost bytes
)

var flagNames = [...]string{"server", "client", "lz4", "bundled", "resynced"}

// Frame is one game frame. Its Payload is a copy the caller owns.
type Frame struct {
	Time     time.Time
	Src, Dst netip.AddrPort
	Opcode   Opcode
	Flags    Flags
	IfIndex  int
	Payload  []byte // after the opcode
}

// String is the line a2kit dump prints:
//
//	ts=1700000000006000000 opcode=04 38 len=41 flags=server src=10.0.0.2:13328 dst=10.0.0.1:10000
func (f Frame) String() string {
	return fmt.Sprintf("ts=%d opcode=%v len=%d flags=%v src=%v dst=%v",
		f.Time.UnixNano(), f.Opcode, len(f.Payload), f.Flags, f.Src, f.Dst)
}

// String is "server,lz4,bundled", or "-" for none.
func (f Flags) String() string {
	var b strings.Builder
	for i, name := range flagNames {
		if f&(1<<i) == 0 {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(name)
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

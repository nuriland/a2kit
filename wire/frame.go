package wire

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Flags describe a frame: its direction, and how it was found.
type Flags uint32

const (
	FromServer Flags = 1 << iota // sent by the locked server
	FromClient                   // sent by its client
	WasLZ4                       // it was compressed with LZ4
	WasBundled                   // it came out of a bundle
	Resynced                     // it is the first frame after skipped or lost bytes
)

var flagNames = [...]string{"server", "client", "lz4", "bundled", "resynced"}

// Frame is one game frame. Its Payload is a copy that the caller owns.
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
	if names := f.names(); len(names) > 0 {
		return strings.Join(names, ",")
	}
	return "-"
}

// MarshalJSON is the list of names, ["server","lz4"], and [] for none.
func (f Flags) MarshalJSON() ([]byte, error) { return json.Marshal(f.names()) }

// UnmarshalJSON reads the list MarshalJSON writes. It drops a name it does not know.
func (f *Flags) UnmarshalJSON(b []byte) error {
	var names []string
	if err := json.Unmarshal(b, &names); err != nil {
		return err
	}
	*f = 0
	for _, name := range names {
		if i := slices.Index(flagNames[:], name); i >= 0 {
			*f |= 1 << i
		}
	}
	return nil
}

func (f Flags) names() []string {
	names := []string{}
	for i, name := range flagNames {
		if f&(1<<i) != 0 {
			names = append(names, name)
		}
	}
	return names
}

package capture

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/nuriland/a2kit/internal/wiretest"
	"github.com/nuriland/a2kit/wire"
)

var (
	src4       = netip.MustParseAddrPort("10.0.0.2:13328")
	dst4       = netip.MustParseAddrPort("10.0.0.1:10000")
	src6       = netip.MustParseAddrPort("[2001:db8::2]:13328")
	dst6       = netip.MustParseAddrPort("[2001:db8::1]:10000")
	packetTime = time.Unix(1700000000, 0)
)

// vlan tags an Ethernet frame, once per id.
func vlan(eth []byte, ids ...uint16) []byte {
	for _, id := range ids {
		tag := binary.BigEndian.AppendUint16([]byte{0x81, 0x00}, id)
		eth = slices.Concat(eth[:12], tag, eth[12:])
	}
	return eth
}

func TestPeel(t *testing.T) {
	var (
		payload  = []byte("frame")
		ip4      = wiretest.TCP(src4, dst4, 7, byte(wire.ACK), payload)
		ip6      = wiretest.TCP(src6, dst6, 7, byte(wire.ACK), payload)
		sll      = slices.Concat(make([]byte, 14), []byte{0x08, 0x00}, ip4)
		sll2     = slices.Concat([]byte{0x86, 0xDD}, make([]byte, 18), ip6)
		fragment = slices.Clone(ip4)
		udp      = slices.Clone(ip4)
		arp      = wiretest.Ethernet(ip4)
	)

	fragment[6] = 0x20 // more fragments
	udp[9] = 17
	arp[12], arp[13] = 0x08, 0x06

	tests := []struct {
		name     string
		linkType int
		packet   []byte
		src      netip.AddrPort // the zero AddrPort for no segment
		payload  string
	}{
		{"ethernet", linkEthernet, wiretest.Ethernet(ip4), src4, "frame"},
		{"ethernet ipv6", linkEthernet, wiretest.Ethernet(ip6), src6, "frame"},
		{"vlan", linkEthernet, vlan(wiretest.Ethernet(ip4), 5), src4, "frame"},
		{"q-in-q", linkEthernet, vlan(wiretest.Ethernet(ip4), 5, 6), src4, "frame"},
		{"null", linkNull, slices.Concat([]byte{2, 0, 0, 0}, ip4), src4, "frame"},
		{"null ipv6", linkNull, slices.Concat([]byte{30, 0, 0, 0}, ip6), src6, "frame"},
		{"null big-endian", linkNull, slices.Concat([]byte{0, 0, 0, 2}, ip4), src4, "frame"},
		{"loop", linkLoop, slices.Concat([]byte{0, 0, 0, 2}, ip4), src4, "frame"},
		{"linux sll", linkLinuxSLL, sll, src4, "frame"},
		{"linux sll2", linkLinuxSLL2, sll2, src6, "frame"},
		{"raw", 101, ip4, src4, "frame"},
		{"raw ipv6", 229, ip6, src6, "frame"},
		{"cut by snaplen", linkEthernet, wiretest.Ethernet(ip4)[:14+40+3], src4, "fra"},
		{"fragment", linkEthernet, wiretest.Ethernet(fragment), netip.AddrPort{}, ""},
		{"udp", linkEthernet, wiretest.Ethernet(udp), netip.AddrPort{}, ""},
		{"arp", linkEthernet, arp, netip.AddrPort{}, ""},
		{"no tcp header", linkEthernet, wiretest.Ethernet(ip4)[:14+30], netip.AddrPort{}, ""},
		{"runt", linkEthernet, []byte{1, 2, 3}, netip.AddrPort{}, ""},
		{"empty", 101, nil, netip.AddrPort{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, ok := peel(tt.linkType, tt.packet)
			if ok != tt.src.IsValid() {
				t.Fatalf("ok = %v", ok)
			}
			if !ok {
				return
			}
			dst := dst4
			if tt.src.Addr().Is6() {
				dst = dst6
			}
			if s.Src != tt.src || s.Dst != dst || s.Seq != 7 || s.Flags != wire.ACK || !bytes.Equal(s.Payload, []byte(tt.payload)) {
				t.Errorf("%v -> %v seq %d flags %#x payload %q", s.Src, s.Dst, s.Seq, s.Flags, s.Payload)
			}
		})
	}
}

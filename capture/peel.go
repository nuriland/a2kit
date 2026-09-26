package capture

import (
	"encoding/binary"
	"math/bits"
	"net/netip"

	"github.com/nuriland/a2kit/wire"
)

// Link types, as files number them. Any other is taken for raw IP.
const (
	linkNull      = 0   // BSD loopback: an address family, in the capturing host's byte order
	linkEthernet  = 1   // Ethernet
	linkLoop      = 108 // OpenBSD loopback: the same, big-endian
	linkLinuxSLL  = 113 // Linux cooked capture
	linkLinuxSLL2 = 276 // its second version, what tcpdump -i any writes
	linkRaw       = 101 // raw IP
	protoTCP      = 6   // TCP protocol number
)

// peel strips a packet down to TCP, and reports false for anything else.
//
// A file that says Ethernet may still hold bare IP.
//
// pktmon's etl2pcap writes every component under one Ethernet interface, including a VPN tunnel, whose packets have no link header.
// So an Ethernet packet that is not TCP is tried again as raw IP.
func peel(linkType int, p []byte) (wire.Segment, bool) {
	s, ok := segment(network(linkType, p))
	if !ok && linkType == linkEthernet {
		s, ok = segment(network(linkRaw, p))
	}
	return s, ok
}

// segment reads the TCP segment in an IP packet of the given version, and reports false for anything else.
func segment(ip []byte, version int) (wire.Segment, bool) {
	var tcp []byte
	var src, dst netip.Addr
	switch version {
	case 4:
		tcp, src, dst = ipv4(ip)
	case 6:
		tcp, src, dst = ipv6(ip)
	}
	if tcp == nil {
		return wire.Segment{}, false
	}

	n := int(tcp[12]>>4) * 4 // header length
	if n < 20 || n > len(tcp) {
		return wire.Segment{}, false
	}
	return wire.Segment{
		Src:     netip.AddrPortFrom(src, binary.BigEndian.Uint16(tcp[0:])),
		Dst:     netip.AddrPortFrom(dst, binary.BigEndian.Uint16(tcp[2:])),
		Seq:     binary.BigEndian.Uint32(tcp[4:]),
		Ack:     binary.BigEndian.Uint32(tcp[8:]),
		Flags:   wire.TCPFlags(tcp[13]),
		Payload: tcp[n:],
	}, true
}

// network skips the link layer. version is 0 if what follows is not IP.
func network(linkType int, p []byte) (ip []byte, version int) {
	switch linkType {
	case linkEthernet:
		if len(p) < 14 {
			return nil, 0
		}
		typ, off := binary.BigEndian.Uint16(p[12:]), 14
		for (typ == 0x8100 || typ == 0x88A8) && len(p) >= off+4 {
			typ = binary.BigEndian.Uint16(p[off+2:]) // past a VLAN tag
			off += 4
		}
		return p[off:], ethertype(typ)
	case linkNull, linkLoop:
		if len(p) < 4 {
			return nil, 0
		}
		// An address family is small, so a value past 16 bits is in the other byte order.
		af := binary.LittleEndian.Uint32(p)
		if af > 0xFFFF {
			af = bits.ReverseBytes32(af)
		}
		return p[4:], family(af)
	case linkLinuxSLL:
		if len(p) < 16 {
			return nil, 0
		}
		return p[16:], ethertype(binary.BigEndian.Uint16(p[14:]))
	case linkLinuxSLL2:
		if len(p) < 20 {
			return nil, 0
		}
		return p[20:], ethertype(binary.BigEndian.Uint16(p[0:]))
	}
	if len(p) == 0 {
		return nil, 0
	}
	if v := int(p[0] >> 4); v == 4 || v == 6 {
		return p, v
	}
	return nil, 0
}

// ethertype returns the IP version of an Ethernet type.
func ethertype(t uint16) int {
	switch t {
	case 0x0800:
		return 4
	case 0x86DD:
		return 6
	}
	return 0
}

// family returns the IP version of an address family.
func family(af uint32) int {
	switch af {
	case 2:
		return 4
	case 24, 28, 30:
		return 6
	}
	return 0
}

// ipv4 returns nil tcp for anything but unfragmented TCP.
func ipv4(p []byte) (tcp []byte, src, dst netip.Addr) {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != protoTCP {
		return nil, src, dst
	}
	if binary.BigEndian.Uint16(p[6:])&0x3FFF != 0 {
		return nil, src, dst // no IP reassembly here
	}
	n := int(p[0]&15) * 4                                     // header length
	total := min(int(binary.BigEndian.Uint16(p[2:])), len(p)) // cut short by the snaplen, maybe
	if n < 20 || total < n+20 {
		return nil, src, dst
	}
	return p[n:total], netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20]))
}

// ipv6 does not follow extension headers.
func ipv6(p []byte) (tcp []byte, src, dst netip.Addr) {
	if len(p) < 40 || p[6] != protoTCP {
		return nil, src, dst
	}
	total := min(40+int(binary.BigEndian.Uint16(p[4:])), len(p))
	if total < 40+20 {
		return nil, src, dst
	}
	return p[40:total], netip.AddrFrom16([16]byte(p[8:24])), netip.AddrFrom16([16]byte(p[24:40]))
}

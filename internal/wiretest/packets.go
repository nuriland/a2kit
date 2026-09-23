package wiretest

import (
	"encoding/binary"
	"net/netip"
)

// TCP returns an IP packet, IPv4 or IPv6 as src is, that carries one TCP
// segment. Checksums are left zero; nothing here checks them.
func TCP(src, dst netip.AddrPort, seq uint32, flags byte, payload []byte) []byte {
	tcp := make([]byte, 20, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:], src.Port())
	binary.BigEndian.PutUint16(tcp[2:], dst.Port())
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 5 << 4 // header length, in words
	tcp[13] = flags
	tcp = append(tcp, payload...)

	if src.Addr().Is4() {
		ip := make([]byte, 20, 20+len(tcp))
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
		ip[8] = 64 // TTL
		ip[9] = 6  // TCP
		s, d := src.Addr().As4(), dst.Addr().As4()
		copy(ip[12:], s[:])
		copy(ip[16:], d[:])
		return append(ip, tcp...)
	}
	ip := make([]byte, 40, 40+len(tcp))
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(tcp)))
	ip[6] = 6  // TCP
	ip[7] = 64 // hop limit
	s, d := src.Addr().As16(), dst.Addr().As16()
	copy(ip[8:], s[:])
	copy(ip[24:], d[:])
	return append(ip, tcp...)
}

// Ethernet wraps an IP packet in an Ethernet frame, zero addresses and all.
func Ethernet(ip []byte) []byte {
	typ := uint16(0x0800)
	if ip[0]>>4 == 6 {
		typ = 0x86DD
	}
	h := make([]byte, 14, 14+len(ip))
	binary.BigEndian.PutUint16(h[12:], typ)
	return append(h, ip...)
}

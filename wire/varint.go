package wire

// uvarint reads the LEB128 varint at the start of p. It is at most 5 bytes, 32 bits, minimally encoded.
// Like binary.Uvarint, width 0 means p ends inside it, and a negative width means p does not start with one.
func uvarint(p []byte) (v uint32, width int) {
	for i := range 5 {
		if i == len(p) {
			return 0, 0
		}
		b := p[i]
		v |= uint32(b&0x7F) << (7 * i)
		if b&0x80 != 0 {
			continue
		}
		if i == 4 && b > 0x0F {
			return 0, -1 // past 32 bits
		}
		if i > 0 && b == 0 {
			return 0, -1 // not minimal
		}
		return v, i + 1
	}
	return 0, -1 // longer than 5 bytes
}

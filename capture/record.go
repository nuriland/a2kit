package capture

import (
	"encoding/binary"
	"io"
	"time"
)

const snapLen = 65535

// recorder writes packets as a classic pcap file, timestamps in nanoseconds.
// Each packet is one Write, so the file is whole up to the last packet even if the process dies.
type recorder struct {
	w   io.Writer
	buf []byte
}

func newRecorder(w io.Writer, linkType int) (*recorder, error) {
	h := binary.LittleEndian.AppendUint32(nil, pcapNano)
	h = binary.LittleEndian.AppendUint16(h, 2)
	h = binary.LittleEndian.AppendUint16(h, 4)
	h = binary.LittleEndian.AppendUint64(h, 0) // time zone and accuracy, unused
	h = binary.LittleEndian.AppendUint32(h, snapLen)
	h = binary.LittleEndian.AppendUint32(h, uint32(linkType))
	if _, err := w.Write(h); err != nil {
		return nil, err
	}
	return &recorder{w: w}, nil
}

func (r *recorder) write(t time.Time, data []byte, origLen int) error {
	b := binary.LittleEndian.AppendUint32(r.buf[:0], uint32(t.Unix()))
	b = binary.LittleEndian.AppendUint32(b, uint32(t.Nanosecond()))
	b = binary.LittleEndian.AppendUint32(b, uint32(len(data)))
	b = binary.LittleEndian.AppendUint32(b, uint32(origLen))
	b = append(b, data...)
	r.buf = b
	_, err := r.w.Write(b)
	return err
}

// Package capture reads TCP segments from pcap and pcapng files, and from a live device.
//
//	libpcap on macOS and Linux, pktmon on Windows
package capture

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/nuriland/a2kit/wire"
)

var (
	errNotCapture = errors.New("not a pcap or pcapng file")                        // errNotCapture is returned by newContainer if the file is not a pcap or pcapng file.
	ErrNoLive     = errors.New("capture: live capture needs cgo on this platform") // ErrNoLive is returned by OpenLive and Devices in a build without cgo, outside Windows.
)

// Device is a device that can be captured live.
type Device struct {
	Name        string
	Description string
}

// Reader reads a pcap or pcapng capture.
type Reader struct {
	c   container
	cut int // segments cut short
}

// container is a file format: classic pcap, or pcapng.
type container interface {
	next() (packet, error) // io.EOF after the last
}

type packet struct {
	time     time.Time
	linkType int
	ifIndex  int
	orig     int    // its length on the wire, which data falls short of if the capture cut it
	data     []byte // the container's buffer, until the next call
}

// NewReader returns a Reader for the pcap or pcapng capture that r holds.
func NewReader(r io.Reader) (*Reader, error) {
	c, err := newContainer(r)
	if err != nil {
		return nil, fmt.Errorf("capture: %w", err)
	}
	return &Reader{c: c}, nil
}

func newContainer(r io.Reader) (container, error) {
	br := bufio.NewReaderSize(r, 1<<16)
	magic, err := br.Peek(4)
	if err != nil {
		return nil, errNotCapture
	}
	if binary.LittleEndian.Uint32(magic) == ngSection {
		return &pcapng{r: br}, nil
	}
	return newClassic(br)
}

// ReadSegment returns the next TCP segment in the capture, skipping other packets, or io.EOF at
// the end.
func (r *Reader) ReadSegment() (wire.Segment, error) {
	for {
		p, err := r.c.next()
		if err == io.EOF {
			return wire.Segment{}, io.EOF
		}
		if err != nil {
			return wire.Segment{}, fmt.Errorf("capture: %w", err)
		}
		if s, ok := peel(p.linkType, p.data); ok {
			if len(p.data) < p.orig {
				r.cut++
			}
			s.Time, s.IfIndex = p.time, p.ifIndex
			return s, nil
		}
	}
}

// CutShort returns how many of the segments read so far the capture cut short of their length on
// the wire, as a snap length does. The decoder takes the bytes cut for a gap in the stream.
func (r *Reader) CutShort() int { return r.cut }

// File is a Reader that closes its file.
type File struct {
	Reader
	f *os.File
}

// Open opens a pcap or pcapng file.
func Open(name string) (*File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	c, err := newContainer(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("capture: %s: %w", name, err)
	}
	return &File{Reader{c: c}, f}, nil
}

func (f *File) Close() error { return f.f.Close() }

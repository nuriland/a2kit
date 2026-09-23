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

// ErrNoLive is what OpenLive and Devices return in a build without cgo outside Windows
var (
	ErrNoLive     = errors.New("capture: live capture needs cgo on this platform")
	errNotCapture = errors.New("not a pcap or pcapng file")
)

type Device struct {
	Name        string
	Description string
}

// Reader reads a pcap or pcapng capture.
type Reader struct {
	c container
}

// container is a file format: classic pcap, or pcapng.
type container interface {
	next() (packet, error) // io.EOF after the last
}

type packet struct {
	time     time.Time
	linkType int
	ifIndex  int
	data     []byte // the container's buffer, until the next call
}

// NewReader takes pcap or pcapng, whichever r starts with.
func NewReader(r io.Reader) (*Reader, error) {
	c, err := newContainer(r)
	if err != nil {
		return nil, fmt.Errorf("capture: %w", err)
	}
	return &Reader{c}, nil
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
			s.Time, s.IfIndex = p.time, p.ifIndex
			return s, nil
		}
	}
}

// File is a Reader that closes its file.
type File struct {
	Reader
	f *os.File
}

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
	return &File{Reader{c}, f}, nil
}

func (f *File) Close() error { return f.f.Close() }

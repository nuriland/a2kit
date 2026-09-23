//go:build !cgo && !windows

package capture

import (
	"io"

	"github.com/nuriland/a2kit/wire"
)

// Live needs cgo here, for libpcap.
type Live struct{}

func OpenLive(name string) (*Live, error) { return nil, ErrNoLive }

func (*Live) ReadSegment() (wire.Segment, error) { return wire.Segment{}, io.EOF }

func (*Live) Close() error { return nil }

func (*Live) Record(w io.Writer) error { return ErrNoLive }

func Devices() ([]Device, error) { return nil, ErrNoLive }

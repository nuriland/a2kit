package game

import "errors"

var (
	// ErrUnread is the error for a frame Parse does not read. The client's frame,
	// or an opcode, or a form the table has no reader for.
	ErrUnread = errors.New("game: not read")

	// ErrLayout is the error for a frame whose bytes contradict the layout its reader reads.
	// Wrapped with the byte it stopped at.
	ErrLayout = errors.New("game: off the layout")
)

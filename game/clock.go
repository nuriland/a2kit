package game

import "time"

// Tick carries the server's clock, from 00 36, twenty times a second.
type Tick struct {
	Server time.Time
}

// Ping answers the client's ping, from 03 36, with the client's send time and the server's clock.
// The difference from arrival gives the round trip.
type Ping struct {
	Client, Server time.Time
}

func (Tick) event() {}
func (Ping) event() {}

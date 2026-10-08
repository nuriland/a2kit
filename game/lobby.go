package game

import (
	"fmt"
	"net/netip"
	"time"
)

// Servers is the lobby's list of game servers, sent before the client picks one
type Servers struct {
	List []Server
}

// Server is one game server in the lobby's list
//
// Players and Capacity are not labelled anywhere, but our theory is that:
//
//   - Players is likely how many play on the server right now, and Capacity how many the server currently supports at once.
//   - Players changes by a tiny margin, up and down, each time the lobby sends the list again, every 10 s.
//   - It has always been well below Capacity, at most 4636 of 8000 so far from what we've seen.
//   - Capacity differs from server to server, from 2000 to 8000, and the smallest is the newest server.
//   - Since the October 2026 patch, the list carries one byte, Load, in place of both.
//     It is close to the old ratio on the servers seen both ways, 43% then 40 on LIVE_Light_001, so likely a percentage.
type Server struct {
	ID       uint16
	Name     string // like LIVE_Light_001, @TODO: maybe offload server ID->name resolution to aion2-api (https://github.com/nuriland/aion2-api) for better UX
	Faction  byte   // 1 on the Light (Elyos) servers, 2 on the Dark (Asmodians) ones
	Mask     byte   // its two bits of the byte before every fourth server's Status, 1 on every server before October 2026, 0 or 1 since, unsure what it marks
	Status   byte   // the game's marks on it, bits of StatusNew, StatusRecommended and StatusRestricted
	Players  uint32 // likely how many play on it, always below Capacity so far, 0 since October 2026 @TODO: remove
	Capacity uint16 // total capacity available on the server, 0 since October 2026 @TODO: remove
	Load     byte   // percentage load in place of Players and Capacity, which it replaced since October 2026
}

// What a Server's Status marks it with in the game's server list.
const (
	StatusNew         = 0x01 // "New"
	StatusRecommended = 0x02 // "Recommended" as shown in the UI
	StatusRestricted  = 0x04 // "Creation Restricted" as shown in the UI
)

// String is "1310:LIVE_Light_010 10% new restricted": its ID, Name, load, and what the game marks it with.
func (s Server) String() string {
	str := fmt.Sprintf("%d:%s %d%%", s.ID, s.Name, s.Load)
	if s.Capacity != 0 { // the form before October 2026, @TODO: remove
		str = fmt.Sprintf("%d:%s %d/%d", s.ID, s.Name, s.Players, s.Capacity)
	}
	if s.Status&StatusNew != 0 {
		str += " new"
	}
	if s.Status&StatusRecommended != 0 {
		str += " recommended"
	}
	if s.Status&StatusRestricted != 0 {
		str += " restricted"
	}
	return str
}

// LobbyPing answers the client's ping in the lobby every 10 s.
type LobbyPing struct {
	Client uint64 // likely the client's clock, in 100 ns ticks from an unknown start, sent back
	Server time.Time
}

// Redirect hands the client from the lobby to the world server it picked
type Redirect struct {
	Server uint16 // the ID in Servers
	Host   string
	Port   uint16
}

// Addr is Host and Port, when Host is an IP.
func (d Redirect) Addr() (netip.AddrPort, bool) {
	ip, err := netip.ParseAddr(d.Host)
	return netip.AddrPortFrom(ip, d.Port), err == nil
}

// Account is who logged in to the lobby.
type Account struct {
	ID      string    // the account's number
	Server  uint16    // likely the one joined last, the ID in Servers
	Session [2]string // two GUIDs, new at every login (unsure which one is which, or what they are used for)
}

// Characters is the account's characters on every server.
type Characters struct {
	List []Character
}

// Character is one of the account's characters.
//
// Some characters seem to be sent as placeholders, for example if you start the tutorial,
// but never create a character afterwards, the server locks in a placeholder character named $ with random letters (hidden by the game's UI).
type Character struct {
	Server uint16    // the ID in Servers
	Name   string    // the character's name
	Level  uint32    // the character's level
	Exp    uint32    // @TODO: not sure what this is, but it's sent for every character
	Code   uint32    // 5 to 44 so far, not read
	Flags  byte      // 1, and 2 on one placeholder, not read
	Mask   byte      // its two bits of the byte after every fourth character, not read
	Time   time.Time // likely when it was last played
}

// String is "1303:Name/29": its server's ID, its name and its level.
func (c Character) String() string { return fmt.Sprintf("%d:%s/%d", c.Server, c.Name, c.Level) }

func (Servers) event()    {}
func (LobbyPing) event()  {}
func (Redirect) event()   {}
func (Account) event()    {}
func (Characters) event() {}

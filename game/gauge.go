package game

import "strconv"

// Gauges is what changed of an entity's HP, MP and flight time.
type Gauges struct {
	Entity Entity
	Rows   map[Gauge]uint64
}

// Gauge is a row's id in a gauge update.
type Gauge uint8

const (
	GaugeHP        Gauge = 0
	GaugeMP        Gauge = 1
	GaugeFlight    Gauge = 6
	GaugeMaxHP     Gauge = 7
	GaugeMaxMP     Gauge = 8
	GaugeMaxFlight Gauge = 13
)

var gaugeNames = map[Gauge]string{GaugeHP: "hp", GaugeMP: "mp", GaugeFlight: "flight", GaugeMaxHP: "max_hp", GaugeMaxMP: "max_mp", GaugeMaxFlight: "max_flight"}

func (g Gauge) String() string {
	if n, ok := gaugeNames[g]; ok {
		return n
	}
	return strconv.Itoa(int(g))
}

func (Stats) event()  {}
func (Gauges) event() {}

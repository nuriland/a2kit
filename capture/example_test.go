package capture_test

import (
	"fmt"
	"log"
	"time"

	"github.com/nuriland/a2kit/capture"
	"github.com/nuriland/a2kit/wire"
)

func ExampleOpenLive() {
	l, err := capture.OpenLive("") // the first device that is up. On Windows, every adapter
	if err != nil {
		log.Fatal(err)
	}
	time.AfterFunc(time.Minute, func() { l.Close() }) // Decode returns once closed

	d := wire.NewDecoder(wire.Config{})
	for f, err := range d.Decode(l) {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(f)
	}
}

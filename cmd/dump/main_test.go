package main

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/nuriland/a2kit/wire"
)

func TestValidateFlags(t *testing.T) {
	oldPcap, oldFeed, oldLive := *pcapFile, *feedFile, *live
	oldDev, oldIndex, oldWrite := *dev, *index, *writeFile
	t.Cleanup(func() {
		*pcapFile, *feedFile, *live = oldPcap, oldFeed, oldLive
		*dev, *index, *writeFile = oldDev, oldIndex, oldWrite
	})
	tests := []struct {
		name    string
		pcap    string
		feed    string
		live    bool
		dev     string
		index   int
		write   string
		wantErr bool
	}{
		{name: "none", index: -1, wantErr: true},
		{name: "pcap", pcap: "capture.pcap", index: -1},
		{name: "feed", feed: "payload.bin", index: -1},
		{name: "live", live: true, index: -1},
		{name: "live device", live: true, dev: "143", index: -1},
		{name: "live index", live: true, index: 2},
		{name: "live write", live: true, write: "capture.pcap", index: -1},
		{name: "pcap and live", pcap: "capture.pcap", live: true, index: -1, wantErr: true},
		{name: "feed and pcap", feed: "payload.bin", pcap: "capture.pcap", index: -1, wantErr: true},
		{name: "device without live", pcap: "capture.pcap", dev: "143", index: -1, wantErr: true},
		{name: "index without live", feed: "payload.bin", index: 0, wantErr: true},
		{name: "device and index", live: true, dev: "143", index: 0, wantErr: true},
		{name: "write without live", pcap: "capture.pcap", write: "capture.pcap", index: -1, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			*pcapFile, *feedFile, *live = test.pcap, test.feed, test.live
			*dev, *index, *writeFile = test.dev, test.index, test.write
			err := validateFlags()
			if (err != nil) != test.wantErr {
				t.Errorf("validateFlags() error = %v", err)
			}
		})
	}
}

type line struct {
	name    string
	op      wire.Opcode
	flags   wire.Flags
	payload string
	want    string
}

func TestMeaning(t *testing.T) {
	tests := []line{
		{"read", 0x3804, wire.FromServer, "c7 7c 04 00 f5 a3 02 e0 26 a8 00 00 02 4b ed 9f 41 01 00 00 00 90 4e 24 01 00",
			"ts=1700000000006000000 04 38 Hit {Actor:37365 Target:15943 Skill:11020000 Damage:36 Extra:[] Type:2 Scalar:10000 Mods:0 Direction:0}"},
		{"not read", 0x371D, wire.FromServer, "e4 72 05 03 2b d5 bc c6 01 6f 24 c7",
			"ts=1700000000006000000 1D 37 Move e4 72 05 03 2b d5 bc c6 01 6f 24 c7"},
		{"not met", 0x38E2, wire.FromServer, "01 02",
			"ts=1700000000006000000 E2 38 - 01 02"},
		{"off the layout", 0x3804, wire.FromServer, "c7 7c 04 00 f5 a3 02 e0 26 a8 00 00 02 4b",
			"ts=1700000000006000000 04 38 Hit c7 7c 04 00 f5 a3 02 e0 26 a8 00 00 02 4b game: off the layout at byte 13 of 14"},
		{"the client's", 0x3804, wire.FromClient, "c7 7c",
			"ts=1700000000006000000 04 38 - c7 7c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := hex.DecodeString(strings.ReplaceAll(tt.payload, " ", ""))
			if err != nil {
				t.Fatal(err)
			}
			f := wire.Frame{Time: time.Unix(0, 1700000000006000000), Opcode: tt.op, Flags: tt.flags, Payload: payload}
			if got := meaning(f); got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

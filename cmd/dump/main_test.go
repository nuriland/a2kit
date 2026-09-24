package main

import (
	"testing"
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

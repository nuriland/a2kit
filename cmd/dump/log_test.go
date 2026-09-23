package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/nuriland/a2kit/a2log"
	"github.com/nuriland/a2kit/capture"
	"github.com/nuriland/a2kit/wire"
)

var update = flag.Bool("update", false, "rewrite testdata/sample.jsonl")

func TestSample(t *testing.T) {
	r, err := capture.Open("../../capture/testdata/sample.pcap")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	var got bytes.Buffer
	lg := &log{enc: json.NewEncoder(&got), hdr: a2log.Header{
		Schema:  a2log.Schema,
		Decoder: "github.com/nuriland/a2kit@test",
		Source:  a2log.Source{Kind: "pcap", Path: "sample.pcap"},
	}}
	if err := decode(wire.NewDecoder(wire.Config{}), r, lg.write); err != nil {
		t.Fatal(err)
	}
	if err := lg.end(); err != nil {
		t.Fatal(err)
	}

	const golden = "testdata/sample.jsonl"
	if *update {
		if err := os.WriteFile(golden, got.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("log:\n%swant:\n%s", got.Bytes(), want)
	}
}

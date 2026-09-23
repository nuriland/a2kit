// Dump prints a line for each game frame it finds:
//
//	ts=1700000000006000000 opcode=04 38 len=41 flags=server src=10.0.0.2:13328 dst=10.0.0.1:10000
//
// Usage:
//
//	dump -pcap FILE                                  a pcap or pcapng file
//	dump -feed FILE                                  raw TCP payload, server 10.0.0.2:13328 to client 10.0.0.1:10000
//	dump -live [-dev NAME | -index N] [-write FILE]  a device, or the first one up
//	dump -list                                       the devices that can be captured
//
// With -client, it prints the client's frames too, and with -v it logs what
// the decoder does to stderr. -write records a live capture to a pcap, for
// -pcap to replay: all the TCP the device sees, not only the game's.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"github.com/nuriland/a2kit/capture"
	"github.com/nuriland/a2kit/wire"
)

var (
	pcapFile  = flag.String("pcap", "", "read a pcap or pcapng `file`")
	feedFile  = flag.String("feed", "", "read raw TCP payload from `file`, server to client")
	live      = flag.Bool("live", false, "capture live")
	dev       = flag.String("dev", "", "the live capture `device`")
	index     = flag.Int("index", -1, "the live capture device, by its `number` in -list")
	writeFile = flag.String("write", "", "record the live capture to a pcap `file`")
	list      = flag.Bool("list", false, "list the devices that can be captured")
	client    = flag.Bool("client", false, "print the client's frames too")
	verbose   = flag.Bool("v", false, "log what the decoder does")
)

// The endpoints a -feed file is taken to flow between.
var (
	srv = netip.MustParseAddrPort("10.0.0.2:13328")
	cli = netip.MustParseAddrPort("10.0.0.1:10000")
)

var errUsage = errors.New("usage")

func main() {
	flag.Parse()
	err := run()
	if err == errUsage {
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dump:", err)
		os.Exit(1)
	}
}

func run() error {
	if *list {
		return devices()
	}
	if *pcapFile == "" && *feedFile == "" && !*live {
		return errUsage
	}
	if *writeFile != "" && !*live {
		return errors.New("-write records a live capture; add -live")
	}

	cfg := wire.Config{EmitClient: *client}
	if *verbose {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{ReplaceAttr: untimed}))
	}
	d := wire.NewDecoder(cfg)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	if *feedFile != "" {
		if err := feed(d, *feedFile); err != nil {
			return err
		}
		d.Flush()
		for f := range d.Frames() {
			fmt.Fprintln(out, f)
		}
	}
	switch {
	case *pcapFile != "":
		f, err := capture.Open(*pcapFile)
		if err != nil {
			return err
		}
		defer f.Close()
		return decode(d, f, out)
	case *live:
		return runLive(d, os.Stdout) // unbuffered, so that a frame shows when it comes
	}
	return nil
}

// runLive decodes a device until Ctrl-C, and records it too with -write.
func runLive(d *wire.Decoder, out io.Writer) (err error) {
	l, err := openLive()
	if err != nil {
		return err
	}
	defer l.Close()
	if *writeFile != "" {
		f, err := os.Create(*writeFile)
		if err != nil {
			return err
		}
		defer func() {
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}()
		if err := l.Record(f); err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	context.AfterFunc(ctx, func() { l.Close() }) // ends the decode below
	return decode(d, l, out)
}

// untimed drops the time from log lines, since the frames carry their own.
func untimed(groups []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey && len(groups) == 0 {
		return slog.Attr{}
	}
	return a
}

func decode(d *wire.Decoder, r wire.SegmentReader, out io.Writer) error {
	for f, err := range d.Decode(r) {
		if err != nil {
			return err
		}
		fmt.Fprintln(out, f)
	}
	return nil
}

func feed(d *wire.Decoder, name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 1<<16)
	for {
		n, err := f.Read(buf)
		d.Feed(time.Unix(0, 0), srv, cli, buf[:n])
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func openLive() (*capture.Live, error) {
	name := *dev
	if *index >= 0 {
		devs, err := capture.Devices()
		if err != nil {
			return nil, err
		}
		if *index >= len(devs) {
			return nil, fmt.Errorf("no device %d; -list has %d", *index, len(devs))
		}
		name = devs[*index].Name
	}
	return capture.OpenLive(name)
}

func devices() error {
	devs, err := capture.Devices()
	if err != nil {
		return err
	}
	for i, d := range devs {
		if d.Description == "" {
			fmt.Printf("%d %s\n", i, d.Name)
			continue
		}
		fmt.Printf("%d %s (%s)\n", i, d.Name, d.Description)
	}
	return nil
}

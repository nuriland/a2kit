// Dump prints a line for each game frame it finds
//
//	ts=1700000000006000000 opcode=04 38 len=41 flags=server src=10.0.0.2:13328 dst=10.0.0.1:10000
//
// With -events, it prints what each frame means instead, as game reads it, and the
// payload of one game does not read, or reads off its layout:
//
//	ts=1700000000006000000 04 38 Hit {Actor:15943 Target:37365 Skill:11020000 Damage:41 Extra:[] Type:2 Scalar:10000 Mods:0 Direction:0}
//	ts=1700000000006000000 1D 37 Move e4 72 05 03 2b d5 bc c6 01 6f 24 c7
//	ts=1700000000006000000 04 38 Hit c7 7c 04 00 f5 a3 02 e0 26 a8 00 00 02 4b game: off the layout at byte 13 of 14
package main

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
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
	"github.com/nuriland/a2kit/game"
	"github.com/nuriland/a2kit/wire"
)

var (
	pcapFile  = flag.String("pcap", "", "read a pcap or pcapng `file`")
	feedFile  = flag.String("feed", "", "read raw TCP payload from `file`, server to client")
	live      = flag.Bool("live", false, "capture live")
	dev       = flag.String("dev", "", "the live capture `device`")
	index     = flag.Int("index", -1, "the live capture device, by its `number` in -list")
	writeFile = flag.String("write", "", "record the live capture to a pcap `file`")
	logFile   = flag.String("log", "", "write the frames to an a2log `file`")
	list      = flag.Bool("list", false, "list the devices that can be captured")
	client    = flag.Bool("client", false, "print the client's frames too")
	events    = flag.Bool("events", false, "print what the frames mean, as game reads them")
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

func run() (err error) {
	if *list {
		return devices()
	}
	if err := validateFlags(); err != nil {
		return err
	}

	cfg := wire.Config{EmitClient: *client}
	if *verbose {
		cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{ReplaceAttr: untimed}))
	}
	d := wire.NewDecoder(cfg)

	var out io.Writer = os.Stdout // unbuffered with -live, so that a frame shows when it comes
	if !*live {
		w := bufio.NewWriter(os.Stdout)
		defer w.Flush()
		out = w
	}
	var lg *log
	if *logFile != "" {
		var f *os.File
		if f, err = os.Create(*logFile); err != nil {
			return err
		}
		lg = &log{enc: json.NewEncoder(f), hdr: header()}
		defer func() {
			if cerr := errors.Join(lg.end(), f.Close()); err == nil {
				err = cerr
			}
		}()
	}
	var behind *lag
	if *verbose && *live {
		behind = newLag(cfg.Logger, time.Now)
		defer behind.report()
	}
	emit := func(f wire.Frame) error {
		if *events {
			fmt.Fprintln(out, meaning(f))
		} else {
			fmt.Fprintln(out, f)
		}
		if behind != nil {
			behind.note(f)
		}
		if lg == nil {
			return nil
		}
		return lg.write(f)
	}

	if *feedFile != "" {
		if err := feed(d, *feedFile); err != nil {
			return err
		}
		d.Flush()
		for f := range d.Frames() {
			if err := emit(f); err != nil {
				return err
			}
		}
	}
	switch {
	case *pcapFile != "":
		f, err := capture.Open(*pcapFile)
		if err != nil {
			return err
		}
		defer f.Close()
		return decode(d, f, emit)
	case *live:
		return runLive(d, emit)
	}
	return nil
}

// runLive decodes a device until Ctrl-C, and records it too with -write.
func runLive(d *wire.Decoder, emit func(wire.Frame) error) (err error) {
	l, err := openLive()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, l.Close()) }()
	if *writeFile != "" {
		var f *os.File
		if f, err = os.Create(*writeFile); err != nil {
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
	return decode(d, l, emit)
}

// validateFlags takes exactly one source, and the flags that belong to -live only with it.
func validateFlags() error {
	sources := 0
	for _, set := range []bool{*pcapFile != "", *feedFile != "", *live} {
		if set {
			sources++
		}
	}
	switch {
	case sources == 0:
		return errUsage
	case sources > 1:
		return errors.New("-pcap, -feed, and -live take one source")
	case !*live && (*dev != "" || *index >= 0):
		return errors.New("-dev and -index select a live capture; add -live")
	case *dev != "" && *index >= 0:
		return errors.New("-dev and -index select the same capture")
	case !*live && *writeFile != "":
		return errors.New("-write records a live capture; add -live")
	}
	return nil
}

// meaning is the -events line for f. It prints the event game reads, or the payload it does not read,
// with the error when the bytes are off the layout.
func meaning(f wire.Frame) string {
	name := "-"
	if f.Flags&wire.FromClient == 0 {
		name = cmp.Or(game.Name(f.Opcode), "-")
	}
	line := fmt.Sprintf("ts=%d %v %s", f.Time.UnixNano(), f.Opcode, name)
	e, err := game.Parse(f)
	switch {
	case err == nil:
		return fmt.Sprintf("%s %+v", line, e)
	case errors.Is(err, game.ErrUnread):
		return fmt.Sprintf("%s % x", line, f.Payload)
	default:
		return fmt.Sprintf("%s % x %v", line, f.Payload, err)
	}
}

// untimed drops the time from log lines, since the frames carry their own.
func untimed(groups []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey && len(groups) == 0 {
		return slog.Attr{}
	}
	return a
}

func decode(d *wire.Decoder, r wire.SegmentReader, emit func(wire.Frame) error) error {
	for f, err := range d.Decode(r) {
		if err != nil {
			return err
		}
		if err := emit(f); err != nil {
			return err
		}
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

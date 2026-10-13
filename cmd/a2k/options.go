package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/nuriland/a2kit"
	"github.com/nuriland/a2kit/a2log"
	"github.com/nuriland/a2kit/game"
	"github.com/nuriland/a2kit/wire"
)

// options are the flags the commands share, each defining those it takes, and where they write.
//
// @TODO: cleanup, maybe decide on a CLI lib
type options struct {
	stdout, stderr io.Writer

	out     string // -o
	client  bool
	verbose bool
	stream  bool          // the file is a bare server to client stream
	adapter string        // live
	pcap    string        // live: record all the adapter's traffic to this file
	log     string        // live: write the game's messages to this log, "-" for stdout
	dur     time.Duration // live: stop after this long
	account bool          // keep Login, Account and Characters in a file to share

	file    string         // the FILE read as given for the summary
	closers []func() error // what the command opened beside the Reader, in the order to close it
}

func (o *options) outputFlag(fs *flag.FlagSet) {
	fs.StringVar(&o.out, "o", "", "write to `file` instead of stdout; on Windows, use it rather than >, which writes UTF-16")
}

func (o *options) clientFlag(fs *flag.FlagSet) {
	fs.BoolVar(&o.client, "client", false, "include the game client's messages too, which are encrypted")
}

func (o *options) verboseFlag(fs *flag.FlagSet) {
	fs.BoolVar(&o.verbose, "v", false, "log what the decoder does to stderr")
}

func (o *options) accountFlag(fs *flag.FlagSet) {
	fs.BoolVar(&o.account, "account", false, "keep Login, Account and Characters, which name the account; left out by default, for a file to share")
}

func (o *options) streamFlag(fs *flag.FlagSet) {
	fs.BoolVar(&o.stream, "stream", false, "FILE is the bare stream the game server sends, not a recording")
}

func (o *options) liveFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.adapter, "adapter", "", "capture this `adapter`, a name a2k adapters lists; the one it marks if none")
	fs.DurationVar(&o.dur, "for", 0, "stop after this `long`, like 2m; until Ctrl-C if none")
}

// checkLive refuses a duration a live capture cannot stop after.
func (o *options) checkLive() error {
	if o.dur < 0 {
		return usagef("-for %v: how long to capture, like 2m", o.dur)
	}
	return nil
}

// config is the a2kit.Config the flags ask for.
func (o *options) config() a2kit.Config {
	cfg := a2kit.Config{Client: o.client}
	if o.verbose {
		cfg.Logger = slog.New(o.records())
	}
	return cfg
}

// records is where -v logs, without times, since the messages carry their own.
func (o *options) records() slog.Handler {
	untimed := func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey && len(groups) == 0 {
			return slog.Attr{}
		}
		return a
	}
	return slog.NewTextHandler(o.stderr, &slog.HandlerOptions{ReplaceAttr: untimed})
}

// open reads FILE: a recording or a log, stdin for "-", or with -stream the bare stream a server
// sends.
func (o *options) open(name string) (*a2kit.Reader, error) {
	o.file = name
	if name == "-" {
		o.file = "stdin"
	}
	switch {
	case o.stream:
		return openStream(o, name)
	case name == "-":
		r, err := a2kit.OpenReader(os.Stdin, o.config())
		if err != nil {
			return nil, fmt.Errorf("stdin: %w", err)
		}
		if !r.Log {
			r.Source.Path = "-"
		}
		return r, nil
	}
	return a2kit.Open(name, o.config())
}

// capture captures live until Ctrl-C, SIGTERM or -for, recording to -pcap if set.
func (o *options) capture() (*a2kit.Reader, error) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	cancel := context.CancelFunc(func() {})
	if o.dur > 0 {
		ctx, cancel = context.WithTimeout(ctx, o.dur)
	}

	var over atomic.Bool // the command ended on its own, not a stop
	context.AfterFunc(ctx, func() {
		stop()
		if !over.Load() {
			fmt.Fprintln(o.stderr, "a2k: stopping the capture")
		}
	})
	o.closers = append(o.closers, func() error { over.Store(true); cancel(); stop(); return nil })

	cfg := o.config()
	if o.pcap != "" {
		f, err := os.Create(o.pcap)
		if err != nil {
			return nil, errors.Join(err, o.close())
		}
		o.closers = append(o.closers, f.Close) // after the Reader's Close, which ends the writes
		cfg.Record = f
	}
	r, err := a2kit.Capture(ctx, o.adapter, cfg)
	if err != nil {
		err = errors.Join(err, o.close())
		if o.pcap != "" {
			os.Remove(o.pcap) // nothing of the session is in it
		}
		return nil, err
	}
	return r, nil
}

// openLog starts the log -log names, of the messages from src
func (o *options) openLog(src a2log.Source) (*a2log.Writer, error) {
	if o.log == "-" {
		lg := a2log.NewWriter(o.stdout, src)
		o.closers = append(o.closers, lg.Close)
		return lg, nil
	}
	f, err := os.Create(o.log)
	if err != nil {
		return nil, err
	}
	lg := a2log.NewWriter(f, src)
	o.closers = append(o.closers, lg.Close, f.Close) // an empty log's header, before the file closes
	return lg, nil
}

// private reports whether f names the account or its characters.
func (o *options) private(f wire.Frame) bool { return !o.account && game.Private(f.Opcode) }

// logWrite writes f to lg, unless it is private.
func (o *options) logWrite(lg *a2log.Writer, f wire.Frame) error {
	if o.private(f) {
		return nil
	}
	return lg.Write(f)
}

// shared is msgs without the private ones.
func (o *options) shared(msgs iter.Seq2[a2kit.Message, error]) iter.Seq2[a2kit.Message, error] {
	return func(yield func(a2kit.Message, error) bool) {
		for m, err := range msgs {
			if err == nil && o.private(m.Frame) {
				continue
			}
			if !yield(m, err) {
				return
			}
		}
	}
}

// openOutput is where the command writes: -o's file, or stdout.
func (o *options) openOutput(live bool) (*output, error) {
	if o.out == "" {
		return &output{Writer: bufio.NewWriter(o.stdout), live: live}, nil
	}
	if same(o.out, o.file) {
		return nil, usagef("-o %s is the FILE being read, and creating it would empty it", o.out)
	}
	f, err := os.Create(o.out)
	if err != nil {
		return nil, err
	}
	return &output{Writer: bufio.NewWriter(f), live: live, f: f}, nil
}

func same(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	return err == nil && os.SameFile(fa, fb)
}

// close closes what the command opened, in order.
func (o *options) close() error {
	var errs []error
	for _, c := range o.closers {
		errs = append(errs, c())
	}
	o.closers = nil
	return errors.Join(errs...)
}

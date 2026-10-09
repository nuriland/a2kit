package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type command struct {
	name  string
	args  string
	short string
	long  string

	define func(fs *flag.FlagSet, o *options) func(args []string) error
}

var commands = []command{watchCommand, recordCommand, showCommand, exportCommand, timelineCommand, statsCommand, connsCommand, adaptersCommand, versionCommand}

type usageError struct{ error }

func usagef(format string, a ...any) error { return usageError{fmt.Errorf(format, a...)} }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		list(stderr)
		return 2
	}

	switch args[0] {
	case "help", "-h", "-help", "--help":
		return help(args[1:], stdout, stderr)
	}

	i := slices.IndexFunc(commands, func(c command) bool { return c.name == args[0] })
	if i < 0 {
		fmt.Fprintf(stderr, "a2k: no command %q\n\n", args[0])
		list(stderr)
		return 2
	}

	c := commands[i]
	fs := flag.NewFlagSet("a2k "+c.name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {} // run says how to use it
	exec := c.define(fs, &options{stdout: stdout, stderr: stderr})
	short := func() { fmt.Fprintf(stderr, "usage: %s\nRun a2k help %s for more.\n", c.line(), c.name) }

	rest, err := parse(fs, args[1:])
	switch {
	case errors.Is(err, flag.ErrHelp):
		c.usage(stdout, fs)
		return 0
	case err != nil:
		short() // after the flag package's reason
		return 2
	}
	err = exec(rest)

	var u usageError
	switch {
	case errors.As(err, &u):
		fmt.Fprintf(stderr, "a2k %s: %v\n", c.name, u.error)
		short()
		return 2
	case err != nil:
		fmt.Fprintf(stderr, "a2k %s: %v\n", c.name, err)
		return 1
	}
	return 0
}

func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var rest []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if n := len(args) - fs.NArg(); n > 0 && args[n-1] == "--" {
			return append(rest, fs.Args()...), nil
		}
		if fs.NArg() == 0 {
			return rest, nil
		}
		rest = append(rest, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func one(args []string, what string) (string, error) {
	switch len(args) {
	case 0:
		return "", usagef("no %s", what)
	case 1:
		return args[0], nil
	}
	return "", usagef("one %s, not %d", what, len(args))
}

func none(args []string) error {
	if len(args) > 0 {
		return usagef("no arguments, not %q", args)
	}
	return nil
}

func (c command) usage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, "usage: %s\n\n%s\n", c.line(), c.long)
	flags := false
	fs.VisitAll(func(*flag.Flag) { flags = true })
	if flags {
		fmt.Fprint(w, "\nflags:\n")
		fs.SetOutput(w)
		fs.PrintDefaults()
	}
}

func (c command) line() string { return strings.TrimSpace("a2k " + c.name + " " + c.args) }

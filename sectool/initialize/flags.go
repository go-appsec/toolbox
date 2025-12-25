package initialize

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

func Parse(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	var reset bool
	fs.BoolVar(&reset, "reset", false, "clear all state and reinitialize")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool init <mode> [options]

Initialize working directory for agent work.

Modes:
  test-report  Create guide for validating a known issue or bug bounty report
  explore      Create guide for exploring a feature or web app for security flaws

Options:
`)
		fs.PrintDefaults()
	}

	// Find mode first (first non-flag argument)
	var mode string
	var flagArgs []string
	for _, arg := range args {
		if arg == "test-report" || arg == "explore" {
			mode = arg
		} else {
			flagArgs = append(flagArgs, arg)
		}
	}

	if mode == "" {
		fs.Usage()
		return errors.New("mode required: test-report or explore")
	}

	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	if len(fs.Args()) > 0 {
		return fmt.Errorf("unknown init mode: %s (expected test-report or explore)", fs.Args()[0])
	}

	return run(mode, reset)
}

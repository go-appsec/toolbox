package service

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/jentfoo/llm-security-toolbox/sectool/cli"
	"github.com/jentfoo/llm-security-toolbox/sectool/config"
)

type DaemonFlags struct {
	WorkDir    string
	BurpMCPURL string
}

func ParseDaemonFlags(args []string) (DaemonFlags, error) {
	fs := pflag.NewFlagSet("service", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	flags := DaemonFlags{BurpMCPURL: config.DefaultBurpMCPURL}

	fs.StringVar(&flags.WorkDir, "workdir", "", "working directory for service state")
	fs.StringVar(&flags.BurpMCPURL, "burp-mcp-url", flags.BurpMCPURL, "Burp MCP SSE endpoint URL")

	if err := fs.Parse(args); err != nil {
		return flags, err
	}

	return flags, nil
}

var serviceSubcommands = []string{"status", "stop", "logs", "help"}

func Parse(args []string) error {
	if len(args) < 1 {
		printUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case "status":
		return parseStatus(args[1:])
	case "stop":
		return parseStop(args[1:])
	case "logs":
		return parseLogs(args[1:])
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return cli.UnknownSubcommandError("service", args[0], serviceSubcommands)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: sectool service <command> [options]

Manage the sectool background service. The service auto-starts when needed;
these commands are for debugging and manual control.

Commands:
  status     Show service health and backend connection status
  stop       Gracefully stop the running service
  logs       View service logs (useful for debugging backend errors)

---

service logs [options]
  -n, --lines <num>      number of lines to show (default: 50)
  -f, --follow           follow log output continuously
`)
}

func parseStatus(args []string) error {
	fs := pflag.NewFlagSet("service status", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool service status [options]

Show service status and health.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return status(timeout)
}

func parseStop(args []string) error {
	fs := pflag.NewFlagSet("service stop", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool service stop [options]

Stop the running service.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return stop(timeout)
}

func parseLogs(args []string) error {
	fs := pflag.NewFlagSet("service logs", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var follow bool
	var lines int

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.BoolVarP(&follow, "follow", "f", false, "follow log output")
	fs.IntVarP(&lines, "lines", "n", 50, "number of lines to show")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool service logs [options]

View service logs.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return logs(timeout, follow, lines)
}

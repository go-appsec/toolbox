package oast

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/jentfoo/llm-security-toolbox/sectool/cli"
)

var oastSubcommands = []string{"create", "poll", "get", "list", "delete", "help"}

func Parse(args []string) error {
	if len(args) < 1 {
		printUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case "create":
		return parseCreate(args[1:])
	case "poll":
		return parsePoll(args[1:])
	case "get":
		return parseGet(args[1:])
	case "list":
		return parseList(args[1:])
	case "delete":
		return parseDelete(args[1:])
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return cli.UnknownSubcommandError("oast", args[0], oastSubcommands)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: sectool oast <command> [options]

Out-of-band Application Security Testing (OAST) for detecting blind
vulnerabilities (SSRF, XXE, blind SQLi, command injection, etc).

Workflow:
  1. Create a session to get a unique domain:
       sectool oast create
  2. Use the domain in payloads with subdomains for tagging:
       curl https://sqli-test.xyz123.oast.fun
       nslookup xxe-probe.xyz123.oast.fun
  3. Poll to see interactions:
       sectool oast poll <oast_id>
  4. Get full event details:
       sectool oast get <oast_id> <event_id>

---

oast create [options]

  Create a new OAST session with unique domain.

  Options:
    --label <str>      optional label for easier reference

  Output: oast_id and domain (e.g., xyz123.oast.fun)

---

oast poll <oast_id|label|domain> [options]

  Poll for out-of-band interactions (DNS, HTTP).

  Options:
    --since <id>       events after event_id, or 'last' for new events
    --wait <dur>       max wait time for events (default: 2m, max: 2m)
    --limit <n>        maximum number of events to return

  Examples:
    sectool oast poll abc123 --limit 10         # return at most 10 events
    sectool oast poll abc123 --since last       # only new events
    sectool oast poll abc123 --wait 30s         # all events, wait up to 30s for events (can be combined with restrictions above)

  Output: Markdown table with event_id, time, type, source_ip, subdomain

---

oast get <oast_id|label|domain> <event_id>

  Get full details for a specific event without truncation.

  Example:
    sectool oast poll abc123          # find event_id
    sectool oast get abc123 evt_xyz   # get full details

  Output: Complete raw request/response data

---

oast list [options]

  List all active OAST sessions (most recent first).

  Options:
    --limit <n>        maximum number of sessions to return

  Output: Markdown table with oast_id, domain, created_at

---

oast delete <oast_id|label|domain>

  Delete an OAST session.

  Output: Confirmation message
`)
}

func parseCreate(args []string) error {
	fs := pflag.NewFlagSet("oast create", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var label, name string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&label, "label", "", "optional label for easier reference")
	fs.StringVar(&name, "name", "", "alias for --label")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool oast create [options]

Create a new OAST session.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if label == "" {
		label = name
	}

	return create(timeout, label)
}

func parsePoll(args []string) error {
	fs := pflag.NewFlagSet("oast poll", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout, wait time.Duration
	var since string
	var limit int

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&since, "since", "", "filter events since event_id or 'last'")
	fs.DurationVar(&wait, "wait", 120*time.Second, "max wait time for events (max 120s)")
	fs.IntVar(&limit, "limit", 0, "maximum number of events to return")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool oast poll <oast_id> [options]

Poll for OAST interactions. Returns a summary table of events. Use
'sectool oast get' to view full details for a specific event.

Get oast_id from 'sectool oast create' or 'sectool oast list'.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("oast_id required (get from 'sectool oast create' or 'sectool oast list')")
	}

	return poll(timeout, fs.Args()[0], since, wait, limit)
}

func parseGet(args []string) error {
	fs := pflag.NewFlagSet("oast get", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool oast get <oast_id> <event_id> [options]

Get full details for a specific OAST event. Use 'sectool oast poll' to list
events and get their event_id values.

This shows the complete raw request/response without truncation, useful for
analyzing the exact payload that triggered an out-of-band interaction.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) < 2 {
		fs.Usage()
		return errors.New("oast_id and event_id required (get event_id from 'sectool oast poll')")
	}

	return get(timeout, fs.Args()[0], fs.Args()[1])
}

func parseList(args []string) error {
	fs := pflag.NewFlagSet("oast list", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var limit int

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.IntVar(&limit, "limit", 0, "maximum number of sessions to return (most recent first)")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool oast list [options]

List active OAST sessions (most recent first).

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return list(timeout, limit)
}

func parseDelete(args []string) error {
	fs := pflag.NewFlagSet("oast delete", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool oast delete <oast_id> [options]

Delete an OAST session.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("oast_id required (get from 'sectool oast list')")
	}

	return del(timeout, fs.Args()[0])
}

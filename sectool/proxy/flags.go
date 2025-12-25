package proxy

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
)

func Parse(args []string) error {
	if len(args) < 1 {
		printUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case "list":
		return parseList(args[1:])
	case "export":
		return parseExport(args[1:])
	case "intercept":
		return parseIntercept(args[1:])
	case "rule":
		return parseRule(args[1:])
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown proxy subcommand: %s", args[0])
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: sectool proxy <command> [options]

Query and manage proxy history.

Commands:
  list       List proxy history (aggregate or filtered)
  export     Export a flow to disk for editing
  intercept  Enable/disable proxy intercept mode (planned)
  rule       Manage intercept rules (planned)

Use "sectool proxy <command> --help" for more information.
`)
}

func parseList(args []string) error {
	fs := flag.NewFlagSet("proxy list", flag.ContinueOnError)
	var timeout time.Duration
	var host, path, method, status, contains, containsBody, since, excludeHost, excludePath string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&host, "host", "", "filter by host pattern (glob: *, ?)")
	fs.StringVar(&path, "path", "", "filter by path pattern (glob: *, ?)")
	fs.StringVar(&method, "method", "", "filter by HTTP method (comma-separated)")
	fs.StringVar(&status, "status", "", "filter by status code (comma-separated)")
	fs.StringVar(&contains, "contains", "", "search in URL and headers")
	fs.StringVar(&containsBody, "contains-body", "", "search in request/response body")
	fs.StringVar(&since, "since", "", "filter since flow_id or 'last'")
	fs.StringVar(&excludeHost, "exclude-host", "", "exclude hosts matching pattern")
	fs.StringVar(&excludePath, "exclude-path", "", "exclude paths matching pattern")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool proxy list [options]

List proxy history entries.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return list(timeout, host, path, method, status, contains, containsBody, since, excludeHost, excludePath)
}

func parseExport(args []string) error {
	fs := flag.NewFlagSet("proxy export", flag.ContinueOnError)
	var timeout time.Duration
	var out string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&out, "out", "", "output directory (default: .sectool/requests/<auto>)")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool proxy export <flow_id> [options]

Export a flow to disk for editing.

Creates a request bundle in .sectool/requests/<bundle_id>/ containing:
  request.http       HTTP headers (with body placeholder)
  body.bin           Request body (edit directly for modifications)
  request.meta.json  Metadata (method, URL, timestamps)

After replay, response files are added:
  response.http      Response headers
  response.body.bin  Response body

Edit body.bin for body modifications; Content-Length is auto-updated on replay.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("flow_id required")
	}

	return export(timeout, fs.Args()[0], out)
}

func parseIntercept(args []string) error {
	fs := flag.NewFlagSet("proxy intercept", flag.ContinueOnError)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool proxy intercept <on|off> [options]

Enable/disable proxy intercept mode.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("state required: on or off")
	}

	state := fs.Args()[0]
	if state != "on" && state != "off" {
		return fmt.Errorf("invalid intercept state: %s (expected on or off)", state)
	}

	return intercept(timeout, state)
}

func parseRule(args []string) error {
	if len(args) < 1 {
		printRuleUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case "add":
		return parseRuleAdd(args[1:])
	case "list":
		return parseRuleList(args[1:])
	case "remove":
		return parseRuleRemove(args[1:])
	case "help", "--help", "-h":
		printRuleUsage()
		return nil
	default:
		return fmt.Errorf("unknown proxy rule subcommand: %s", args[0])
	}
}

func printRuleUsage() {
	fmt.Fprint(os.Stderr, `Usage: sectool proxy rule <command> [options]

Manage intercept rules (planned for future release).

Commands:
  add        Add an intercept rule
  list       List active intercept rules
  remove     Remove an intercept rule

Use "sectool proxy rule <command> --help" for more information.
`)
}

func parseRuleAdd(args []string) error {
	fs := flag.NewFlagSet("proxy rule add", flag.ContinueOnError)
	var timeout time.Duration
	var host, path, method, action string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&host, "host", "", "host pattern to match")
	fs.StringVar(&path, "path", "", "path pattern to match")
	fs.StringVar(&method, "method", "", "HTTP method to match")
	fs.StringVar(&action, "action", "intercept", "action: intercept, allow, drop")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool proxy rule add [options]

Add an intercept rule.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return ruleAdd(timeout, host, path, method, action)
}

func parseRuleList(args []string) error {
	fs := flag.NewFlagSet("proxy rule list", flag.ContinueOnError)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool proxy rule list [options]

List active intercept rules.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return ruleList(timeout)
}

func parseRuleRemove(args []string) error {
	fs := flag.NewFlagSet("proxy rule remove", flag.ContinueOnError)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool proxy rule remove <rule_id> [options]

Remove an intercept rule.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("rule_id required")
	}

	return ruleRemove(timeout, fs.Args()[0])
}

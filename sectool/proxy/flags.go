package proxy

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/jentfoo/llm-security-toolbox/sectool/cli"
)

var proxySubcommands = []string{"list", "export", "rule", "help"} // TODO - "intercept" planned

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
	// case "intercept": // TODO - planned
	// 	return parseIntercept(args[1:])
	case "rule":
		return parseRule(args[1:])
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return cli.UnknownSubcommandError("proxy", args[0], proxySubcommands)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: sectool proxy <command> [options]

Query and manage proxy history from Burp Suite.

Workflow:
  1. Browse target with Burp proxy to capture traffic
  2. List requests to find interesting flows:
       sectool proxy list --host example.com
  3a. Replay with inline modifications (preferred for most testing):
       sectool replay send --flow f7k2x --set-json "role=admin"
       sectool replay send --flow f7k2x --set-header "X-Test: value"
  3b. Export for complex edits (raw body manipulation, binary data):
       sectool proxy export f7k2x
       # edit .sectool/requests/f7k2x/body
       sectool replay send --bundle .sectool/requests/f7k2x

Run 'sectool replay --help' to see all replay options and modification support.

---

proxy list [options]

  Without filters: aggregated summary grouped by host/path/method/status
  With filters: individual flows with flow_id for export

  Options:
    --host <pattern>        host glob pattern (*, ?)
    --path <pattern>        path glob pattern (*, ?)
    --method <list>         comma-separated methods (POST,PUT)
    --status <list>         comma-separated status codes (200,404)
    --contains <text>       search URL and headers
    --contains-body <text>  search request/response body
    --since <id>            flows after flow_id, or 'last' for new flows
    --exclude-host <pat>    exclude matching hosts
    --exclude-path <pat>    exclude matching paths
    --limit <n>             maximum number of flows to return

  Examples:
    sectool proxy list                                    # aggregated summary
    sectool proxy list --host api.example.com             # flows for host
    sectool proxy list --host "*.example.com" --method POST,PUT
    sectool proxy list --path "/api/*" --status 200,201
    sectool proxy list --since last --limit 10            # new flows only, at most 10 results

  Output: Markdown table. With filters: flow_id, method, host, path, status, size

---

proxy export <flow_id>

  Export a captured request to disk for editing and replay.
  Note: Prefer 'replay send --flow' with modification flags for simple changes.
  Export is useful for complex edits (raw body, binary data, etc).

  Creates bundle in .sectool/requests/<id>/:
    request.http       HTTP headers with body placeholder
    body               request body (edit this for modifications)
    request.meta.json  metadata (method, URL, timestamps)

  Options:
    --out <path>            custom output directory

  Examples:
    sectool proxy list --host example.com     # find flow_id
    sectool proxy export f7k2x                # outputs: .sectool/requests/f7k2x/
    sectool replay send --bundle .sectool/requests/f7k2x

  Output: Bundle path and files created

---

proxy rule <command> [options]

  Manage match and replace rules for request/response modification.
  Rules are applied by Burp's proxy to all traffic flowing through it.

  Commands:
    list       List configured rules
    add        Add a new rule
    update     Modify an existing rule
    delete     Remove a rule

  Rule types:
    --request --header        Modify request headers (default)
    --request --body          Modify request body
    --response --header       Modify response headers
    --response --body         Modify response body

proxy rule list [options]

  Options:
    --websocket             List WebSocket rules instead of HTTP
    --limit <n>             Maximum rules to display

proxy rule add [options] [match] [replace]

  Add request header (default): match is optional, replace is the header to add.
  For other types: match is the pattern, replace is the replacement.

  Options:
    --match <pattern>       Pattern to match (alternative to positional arg)
    --replace <string>      Replacement string (alternative to positional arg)
    --request               Apply to requests (default)
    --response              Apply to responses
    --header                Match/replace headers (default)
    --body                  Match/replace body content
    --regex                 Treat match as regex pattern
    --label <name>          Optional label for easier reference
    --websocket             Apply to WebSocket messages

  Examples:
    sectool proxy rule add "X-Custom: value"
    sectool proxy rule add --regex "^User-Agent.*$" "User-Agent: Custom"
    sectool proxy rule add --response --header --regex "^Set-Cookie.*$" ""
    sectool proxy rule add --request --body "old" "new" --label my-rule

proxy rule update <rule_id> [options] [match] [replace]

  Update an existing rule. All fields are replaced.
  Lookup by rule_id or label. Searches both HTTP and WebSocket rules.

  Options: Same as 'add' (except --websocket is ignored)

  Examples:
    sectool proxy rule update abc123 --request --header "X-New: value"
    sectool proxy rule update my-rule --request --body "updated" "value"

proxy rule delete <rule_id>

  Delete a rule by ID or label.
  Searches both HTTP and WebSocket rules automatically.

  Examples:
    sectool proxy rule delete abc123
    sectool proxy rule delete my-rule
`)
}

func parseList(args []string) error {
	fs := pflag.NewFlagSet("proxy list", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var limit int
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
	fs.IntVar(&limit, "limit", 0, "maximum number of flows to return")
	fs.IntVar(&limit, "count", 0, "alias for --limit")
	_ = fs.MarkHidden("count")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool proxy list [options]

List proxy history entries. Without filters shows aggregated view; with filters
shows individual flows with flow_ids for export.

Filter examples:
  --host api.example.com          Exact host match
  --host "*.example.com"          Glob pattern (subdomains)
  --path "/api/*"                 Path prefix
  --method POST,PUT               Multiple methods
  --status 200,201                Multiple status codes
  --limit 10                      Return at most 10 flows

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return list(timeout, host, path, method, status, contains, containsBody, since, excludeHost, excludePath, limit)
}

func parseExport(args []string) error {
	fs := pflag.NewFlagSet("proxy export", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var out string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&out, "out", "", "output directory (default: .sectool/requests/<auto>)")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool proxy export <flow_id> [options]

Export a flow to disk for editing and replay.
Note: Prefer 'replay send --flow' with modification flags for simple changes.
Export is useful for complex edits (raw body, binary data, etc).

First, find the flow_id using 'sectool proxy list' with filters:
  sectool proxy list --host example.com --path /api/*

Creates a request bundle in .sectool/requests/<bundle_id>/ containing:
  request.http       HTTP headers (with body placeholder)
  body               Request body (edit directly for modifications)
  request.meta.json  Metadata (method, URL, timestamps)

After replay, response files are added:
  response.http      Response headers
  response.body     Response body

Edit body for body modifications; Content-Length is auto-updated on replay.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("flow_id required (get from 'sectool proxy list' with filters)")
	}

	return export(timeout, fs.Args()[0], out)
}

// TODO - planned intercept feature
/*
func parseIntercept(args []string) error {
	fs := pflag.NewFlagSet("proxy intercept", pflag.ContinueOnError)
	fs.SetInterspersed(true)
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
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("state required: on or off")
	}

	state := fs.Args()[0]
	if state != "on" && state != "off" {
		return fmt.Errorf("invalid intercept state: %s (expected on or off)", state)
	}

	return intercept(timeout, state)
}
*/

var ruleSubcommands = []string{"list", "add", "update", "delete", "help"}

func parseRule(args []string) error {
	if len(args) < 1 {
		printRuleUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case "list":
		return parseRuleList(args[1:])
	case "add":
		return parseRuleAdd(args[1:])
	case "update":
		return parseRuleUpdate(args[1:])
	case "delete":
		return parseRuleDelete(args[1:])
	case "help", "--help", "-h":
		printRuleUsage()
		return nil
	default:
		return cli.UnknownSubcommandError("proxy rule", args[0], ruleSubcommands)
	}
}

func printRuleUsage() {
	fmt.Fprint(os.Stderr, `Usage: sectool proxy rule <command> [options]

Manage match and replace rules for request/response modification.

Commands:
  list       List configured rules
  add        Add a new rule
  update     Modify an existing rule
  delete     Remove a rule

Use "sectool proxy rule <command> --help" for more information.
`)
}

func parseRuleList(args []string) error {
	fs := pflag.NewFlagSet("proxy rule list", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var websocket bool
	var limit int

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.BoolVar(&websocket, "websocket", false, "list WebSocket rules")
	fs.IntVar(&limit, "limit", 0, "maximum rules to display")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool proxy rule list [options]

List configured match/replace rules.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return ruleList(timeout, websocket, limit)
}

func parseRuleAdd(args []string) error {
	fs := pflag.NewFlagSet("proxy rule add", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var websocket, request, response, header, body, isRegex bool
	var label, name, match, replace string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.BoolVar(&websocket, "websocket", false, "apply to WebSocket messages")
	fs.BoolVar(&request, "request", false, "apply to requests (default)")
	fs.BoolVar(&response, "response", false, "apply to responses")
	fs.BoolVar(&header, "header", false, "match/replace headers (default)")
	fs.BoolVar(&body, "body", false, "match/replace body content")
	fs.BoolVar(&isRegex, "regex", false, "treat match as regex pattern")
	fs.StringVar(&label, "label", "", "optional label for easier reference")
	fs.StringVar(&name, "name", "", "alias for --label")
	fs.StringVar(&match, "match", "", "pattern to match")
	fs.StringVar(&replace, "replace", "", "replacement string")
	_ = fs.MarkHidden("name")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool proxy rule add [options] [match] [replace]

Add a match/replace rule.
For header add (default): only replace is needed (adds header).
For replacements: both match and replace are needed.

Examples:
  sectool proxy rule add "X-Custom: value"                         # Add request header
  sectool proxy rule add --regex "^User-Agent.*$" "User-Agent: X"  # Replace User-Agent
  sectool proxy rule add --response --header --regex "^Set-Cookie.*$" ""  # Remove cookies

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if name != "" && label == "" {
		label = name
	}

	ruleType := resolveRuleType(response, body)

	// Positional args override empty flags
	posArgs := fs.Args()
	if match == "" && replace == "" {
		switch len(posArgs) {
		case 1:
			replace = posArgs[0]
		case 2:
			match = posArgs[0]
			replace = posArgs[1]
		}
	}

	return ruleAdd(timeout, websocket, ruleType, match, replace, label, isRegex)
}

func parseRuleUpdate(args []string) error {
	fs := pflag.NewFlagSet("proxy rule update", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var request, response, header, body, isRegex bool
	var label, name, match, replace string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.BoolVar(&request, "request", false, "apply to requests (default)")
	fs.BoolVar(&response, "response", false, "apply to responses")
	fs.BoolVar(&header, "header", false, "match/replace headers (default)")
	fs.BoolVar(&body, "body", false, "match/replace body content")
	fs.BoolVar(&isRegex, "regex", false, "treat match as regex pattern")
	fs.StringVar(&label, "label", "", "new label for the rule")
	fs.StringVar(&name, "name", "", "alias for --label")
	fs.StringVar(&match, "match", "", "pattern to match")
	fs.StringVar(&replace, "replace", "", "replacement string")
	_ = fs.MarkHidden("name")
	// Accept --websocket for tolerance but ignore it (searches both sets automatically)
	fs.Bool("websocket", false, "")
	_ = fs.MarkHidden("websocket")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool proxy rule update <rule_id> [options] [match] [replace]

Update an existing rule. Lookup by rule_id or label.
Searches both HTTP and WebSocket rules automatically.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("rule_id required")
	}

	if name != "" && label == "" {
		label = name
	}

	ruleID := fs.Args()[0]
	ruleType := resolveRuleType(response, body)

	// Positional args override empty flags
	posArgs := fs.Args()[1:]
	if match == "" && replace == "" {
		switch len(posArgs) {
		case 1:
			replace = posArgs[0]
		case 2:
			match = posArgs[0]
			replace = posArgs[1]
		}
	}

	return ruleUpdate(timeout, ruleID, ruleType, match, replace, label, isRegex)
}

func parseRuleDelete(args []string) error {
	fs := pflag.NewFlagSet("proxy rule delete", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	// Accept --websocket for tolerance but ignore it (searches both sets automatically)
	fs.Bool("websocket", false, "")
	_ = fs.MarkHidden("websocket")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool proxy rule delete <rule_id> [options]

Delete a rule by ID or label.
Searches both HTTP and WebSocket rules automatically.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("rule_id required")
	}

	return ruleDelete(timeout, fs.Args()[0])
}

// resolveRuleType determines the rule type from flags.
// Defaults to request_header if no flags are set.
func resolveRuleType(response, body bool) string {
	prefix := "request"
	if response {
		prefix = "response"
	}

	if body {
		return prefix + "_body"
	}
	return prefix + "_header"
}

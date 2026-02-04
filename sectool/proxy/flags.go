package proxy

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/go-appsec/llm-security-toolbox/sectool/cliutil"
)

var proxySubcommands = []string{"summary", "list", "export", "rule", "help"}

func Parse(args []string, mcpURL string) error {
	if len(args) < 1 {
		printUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case "summary":
		return parseSummary(args[1:], mcpURL)
	case "list":
		return parseList(args[1:], mcpURL)
	case "export":
		return parseExport(args[1:], mcpURL)
	case "rule":
		return parseRule(args[1:], mcpURL)
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return cliutil.UnknownSubcommandError("proxy", args[0], proxySubcommands)
	}
}

func printUsage() {
	_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy <command> [options]

Query and manage proxy history.

Run 'sectool replay --help' to see all replay options and modification support.

---

proxy summary [options]

  Get aggregated summary of proxy history grouped by host/path/method/status.
  Use this first to understand available traffic before using proxy list.

  Options:
    --source <type>         filter by source: 'proxy', 'replay', or empty for both
    --host <pattern>        host glob pattern (*, ?)
    --path <pattern>        path glob pattern (*, ?)
    --method <list>         comma-separated methods (POST,PUT)
    --status <list>         comma-separated status codes (200,404)
    --contains <text>       search URL and headers
    --contains-body <text>  search request/response body
    --exclude-host <pat>    exclude matching hosts
    --exclude-path <pat>    exclude matching paths

  Examples:
    sectool proxy summary                                 # full summary
    sectool proxy summary --host api.example.com          # summary for host
    sectool proxy summary --exclude-host "*.google.com"   # filter out noise
    sectool proxy summary --source replay                 # only replay-sent traffic

  Output: Markdown table with host, path, method, status, count

---

proxy list [options]

  List individual flows with flow_id for export or replay.

  Options:
    --source <type>         filter by source: 'proxy', 'replay', or empty for both
    --host <pattern>        host glob pattern (*, ?)
    --path <pattern>        path glob pattern (*, ?)
    --method <list>         comma-separated methods (POST,PUT)
    --status <list>         comma-separated status codes (200,404)
    --contains <text>       search URL and headers
    --contains-body <text>  search request/response body
    --since <id>            flows after flow_id
    --exclude-host <pat>    exclude matching hosts
    --exclude-path <pat>    exclude matching paths
    --limit <n>             maximum number of flows to return
    --offset <n>            skip first N results (applied after filtering)

  Examples:
    sectool proxy list --host api.example.com             # flows for host
    sectool proxy list --host "*.example.com" --method POST,PUT
    sectool proxy list --path "/api/*" --status 200,201
    sectool proxy list --since f7k2x --limit 10           # flows after specific ID
    sectool proxy list --source replay --limit 10         # recent replay requests

  Output: Markdown table with flow_id, method, host, path, status, size

---

proxy export <flow_id>

  Export a captured request to disk for editing and replay.
  Note: Prefer 'replay send --flow' with modification flags for simple changes.
  Export is useful for complex edits (raw body, binary data, etc).

  The bundle_id matches the flow_id for simplicity. Re-exporting the same
  flow overwrites the bundle, restoring it to the original captured state.

  Creates bundle in sectool-requests/<flow_id>/:
    request.http       HTTP headers with body placeholder
    body               request body (edit this for modifications)
    request.meta.json  metadata (method, URL, timestamps)

  Examples:
    sectool proxy list --host example.com     # find flow_id
    sectool proxy export f7k2x                # exports to sectool-requests/f7k2x/
    sectool replay send --bundle f7k2x        # replay the exported bundle

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

  Types:
    HTTP:      request_header (default), request_body, response_header, response_body
    WebSocket: ws:to-server, ws:to-client, ws:both

proxy rule list [options]

  Options:
    --websocket             List WebSocket rules instead of HTTP
    --limit <n>             Maximum rules to display

proxy rule add [options] [match] [replace]

  For header add: only replace is needed (adds header).
  For replacements: both match and replace are needed.

  Options:
    --type <type>           Rule type (default: request_header)
    --match <pattern>       Pattern to match (alternative to positional arg)
    --replace <string>      Replacement string (alternative to positional arg)
    --regex                 Treat match as regex pattern
    --label <name>          Optional label for easier reference

  Examples:
    sectool proxy rule add "X-Custom: value"
    sectool proxy rule add --type response_header "X-Frame-Options: DENY"
    sectool proxy rule add --regex "^User-Agent.*$" "User-Agent: Custom"
    sectool proxy rule add --type ws:both "old" "new"

proxy rule update <rule_id> [options] [match] [replace]

  Update an existing rule. Lookup by rule_id or label.
  Searches both HTTP and WebSocket rules automatically.

  Options:
    --type <type>           Rule type (required)
    --match <pattern>       Pattern to match
    --replace <string>      Replacement string
    --regex                 Treat match as regex pattern
    --label <name>          New label for the rule

  Examples:
    sectool proxy rule update abc123 --type request_header "X-New: value"
    sectool proxy rule update my-rule --type request_body "updated" "value"

proxy rule delete <rule_id>

  Delete a rule by ID or label.
  Searches both HTTP and WebSocket rules automatically.

  Examples:
    sectool proxy rule delete abc123
    sectool proxy rule delete my-rule
`)
}

func parseSummary(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy summary", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var host, path, method, status, contains, containsBody, excludeHost, excludePath, source string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&source, "source", "", "filter by source: 'proxy', 'replay', or empty for both")
	fs.StringVar(&host, "host", "", "filter by host pattern (glob: *, ?)")
	fs.StringVar(&path, "path", "", "filter by path pattern (glob: *, ?)")
	fs.StringVar(&method, "method", "", "filter by HTTP method (comma-separated)")
	fs.StringVar(&status, "status", "", "filter by status code (e.g., 200,4XX)")
	fs.StringVar(&contains, "contains", "", "search in URL and headers")
	fs.StringVar(&containsBody, "contains-body", "", "search in request/response body")
	fs.StringVar(&excludeHost, "exclude-host", "", "exclude hosts matching pattern")
	fs.StringVar(&excludePath, "exclude-path", "", "exclude paths matching pattern")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy summary [options]

Get aggregated summary of proxy history grouped by host/path/method/status.
Use this first to understand available traffic before using proxy list.

Filter examples:
  --host api.example.com          Exact host match
  --host "*.example.com"          Glob pattern (subdomains)
  --exclude-host "*.google.com"   Filter out noise
  --source proxy                  Only proxy-captured traffic
  --source replay                 Only replay-sent traffic

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return summary(mcpURL, timeout, source, host, path, method, status, contains, containsBody, excludeHost, excludePath)
}

func parseList(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy list", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var limit, offset int
	var host, path, method, status, contains, containsBody, since, excludeHost, excludePath, source string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&source, "source", "", "filter by source: 'proxy', 'replay', or empty for both")
	fs.StringVar(&host, "host", "", "filter by host pattern (glob: *, ?)")
	fs.StringVar(&path, "path", "", "filter by path pattern (glob: *, ?)")
	fs.StringVar(&method, "method", "", "filter by HTTP method (comma-separated)")
	fs.StringVar(&status, "status", "", "filter by status code (e.g., 200,4XX)")
	fs.StringVar(&contains, "contains", "", "search in URL and headers")
	fs.StringVar(&containsBody, "contains-body", "", "search in request/response body")
	fs.StringVar(&since, "since", "", "filter since flow_id or 'last'")
	fs.StringVar(&excludeHost, "exclude-host", "", "exclude hosts matching pattern")
	fs.StringVar(&excludePath, "exclude-path", "", "exclude paths matching pattern")
	fs.IntVar(&limit, "limit", 0, "maximum number of flows to return")
	fs.IntVar(&offset, "offset", 0, "skip first N results for pagination")
	fs.IntVar(&limit, "count", 0, "alias for --limit")
	_ = fs.MarkHidden("count")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy list [options]

List individual flows with flow_id for export or replay.

Filter examples:
  --host api.example.com          Exact host match
  --host "*.example.com"          Glob pattern (subdomains)
  --path "/api/*"                 Path prefix
  --method POST,PUT               Multiple methods
  --status 200,201                Multiple status codes
  --limit 10                      Return at most 10 flows
  --source proxy                  Only proxy-captured traffic
  --source replay                 Only replay-sent traffic

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return list(mcpURL, timeout, source, host, path, method, status, contains, containsBody, since, excludeHost, excludePath, limit, offset)
}

func parseExport(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy export", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy export <flow_id> [options]

Export a flow to disk for editing and replay.
Note: Prefer 'replay send --flow' with modification flags for simple changes.
Export is useful for complex edits (raw body, binary data, etc).

First, find the flow_id using 'sectool proxy list' with filters:
  sectool proxy list --host example.com --path /api/*

The bundle_id matches the flow_id for simplicity. Re-exporting the same
flow overwrites the bundle, restoring it to the original captured state.

Creates a request bundle in sectool-requests/<flow_id>/ containing:
  request.http       HTTP headers (with body placeholder)
  body               Request body (edit directly for modifications)
  request.meta.json  Metadata (method, URL, timestamps)

After replay, response files are added:
  response.http      Response headers
  response.body      Response body

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

	return export(mcpURL, timeout, fs.Args()[0])
}

var ruleSubcommands = []string{"list", "add", "update", "delete", "help"}

func parseRule(args []string, mcpURL string) error {
	if len(args) < 1 {
		printRuleUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case "list":
		return parseRuleList(args[1:], mcpURL)
	case "add":
		return parseRuleAdd(args[1:], mcpURL)
	case "update":
		return parseRuleUpdate(args[1:], mcpURL)
	case "delete":
		return parseRuleDelete(args[1:], mcpURL)
	case "help", "--help", "-h":
		printRuleUsage()
		return nil
	default:
		return cliutil.UnknownSubcommandError("proxy rule", args[0], ruleSubcommands)
	}
}

func printRuleUsage() {
	_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy rule <command> [options]

Manage match and replace rules for request/response modification.

Commands:
  list       List configured rules
  add        Add a new rule
  update     Modify an existing rule
  delete     Remove a rule

Use "sectool proxy rule <command> --help" for more information.
`)
}

func parseRuleList(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy rule list", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var websocket bool
	var limit int

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.BoolVar(&websocket, "websocket", false, "list WebSocket rules")
	fs.IntVar(&limit, "limit", 0, "maximum rules to display")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy rule list [options]

List configured match/replace rules.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return ruleList(mcpURL, timeout, websocket, limit)
}

func parseRuleAdd(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy rule add", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var isRegex bool
	var ruleType, label, name, match, replace string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&ruleType, "type", "request_header", "rule type")
	fs.BoolVar(&isRegex, "regex", false, "treat match as regex pattern")
	fs.StringVar(&label, "label", "", "optional label for easier reference")
	fs.StringVar(&name, "name", "", "alias for --label")
	fs.StringVar(&match, "match", "", "pattern to match")
	fs.StringVar(&replace, "replace", "", "replacement string")
	_ = fs.MarkHidden("name")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy rule add [options] [match] [replace]

Add a match/replace rule.
For header add: only replace is needed (adds header).
For replacements: both match and replace are needed.

Types:
  HTTP:      request_header (default), request_body, response_header, response_body
  WebSocket: ws:to-server, ws:to-client, ws:both

Examples:
  sectool proxy rule add "X-Custom: value"                              # Add request header
  sectool proxy rule add --type response_header "X-Frame-Options: DENY" # Add response header
  sectool proxy rule add --regex "^User-Agent.*$" "User-Agent: X"       # Replace User-Agent
  sectool proxy rule add --type ws:both "old" "new"                     # WebSocket replacement

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

	return ruleAdd(mcpURL, timeout, ruleType, match, replace, label, isRegex)
}

func parseRuleUpdate(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy rule update", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var isRegex bool
	var ruleType, label, name, match, replace string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&ruleType, "type", "", "rule type (required)")
	fs.BoolVar(&isRegex, "regex", false, "treat match as regex pattern")
	fs.StringVar(&label, "label", "", "new label for the rule")
	fs.StringVar(&name, "name", "", "alias for --label")
	fs.StringVar(&match, "match", "", "pattern to match")
	fs.StringVar(&replace, "replace", "", "replacement string")
	_ = fs.MarkHidden("name")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy rule update <rule_id> [options] [match] [replace]

Update an existing rule. Lookup by rule_id or label.
Searches both HTTP and WebSocket rules automatically.

Types:
  HTTP:      request_header, request_body, response_header, response_body
  WebSocket: ws:to-server, ws:to-client, ws:both

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

	// Only pass isRegex if explicitly set by user
	var isRegexPtr *bool
	if fs.Changed("regex") {
		isRegexPtr = &isRegex
	}

	return ruleUpdate(mcpURL, timeout, ruleID, ruleType, match, replace, label, isRegexPtr)
}

func parseRuleDelete(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy rule delete", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	// Accept --websocket for tolerance but ignore it (searches both sets automatically)
	fs.Bool("websocket", false, "")
	_ = fs.MarkHidden("websocket")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy rule delete <rule_id> [options]

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

	return ruleDelete(mcpURL, timeout, fs.Args()[0])
}

package proxy

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"github.com/go-appsec/toolbox/sectool/cliutil"
)

var proxySubcommands = []string{"summary", "list", "get", "cookies", "export", "rule", "clear", "help"}

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
	case "get":
		return parseGet(args[1:], mcpURL)
	case "cookies":
		return parseCookies(args[1:], mcpURL)
	case "export":
		return parseExport(args[1:], mcpURL)
	case "rule":
		return parseRule(args[1:], mcpURL)
	case "clear":
		return parseClear(args[1:], mcpURL)
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

---

proxy summary [options]

  Aggregated summary of proxy history grouped by host/path/method/status.
  Use this first to understand available traffic before using proxy list.

  Options:
    --source <type>           filter by source: 'proxy', 'replay', or empty for both
    --host <pattern>          host glob pattern (*, ?)
    --path <pattern>          path glob pattern (*, ?)
    --method <list>           comma-separated methods (POST,PUT)
    --status <list>           comma-separated status codes (200,404)
    --search-header <regex>   regex search in request/response headers (RE2)
    --search-body <regex>     regex search in request/response body (RE2)
    --exclude-host <pat>      exclude matching hosts
    --exclude-path <pat>      exclude matching paths

---

proxy list [options]

  List individual flows with flow_id for export or replay.

  Options:
    --source <type>           filter by source: 'proxy', 'replay', or empty for both
    --host <pattern>          host glob pattern (*, ?)
    --path <pattern>          path glob pattern (*, ?)
    --method <list>           comma-separated methods (POST,PUT)
    --status <list>           comma-separated status codes (200,404)
    --search-header <regex>   regex search in request/response headers (RE2)
    --search-body <regex>     regex search in request/response body (RE2)
    --since <id>              flows after flow_id
    --exclude-host <pat>      exclude matching hosts
    --exclude-path <pat>      exclude matching paths
    --limit <n>               maximum number of flows to return
    --offset <n>              skip first N results (applied after filtering)

---

proxy get <flow_id> [options]

  Full request and response data for a flow.

  Options:
    --scope <sections>        sections to include (comma-separated):
                              request_headers, request_body, response_headers,
                              response_body, all (default)
    --pattern <regex>         regex search within scoped sections (RE2);
                              returns matching snippets instead of full content

---

proxy cookies [options]

  Extract and deduplicate cookies from proxy and replay traffic.
  Shows Set-Cookie attributes, values, and auto-decodes JWT cookie values.

  Options:
    --name <name>           filter by cookie name (exact match)
    --domain <name>         filter by domain (matches domain and all subdomains)

---

proxy export <flow_id>

  Export a captured request to disk for editing and replay.
  Prefer 'replay send --flow' with modification flags for simple changes.

  Creates bundle in sectool-requests/<flow_id>/:
    request.http       HTTP headers with body placeholder
    body               request body (edit this for modifications)
    request.meta.json  metadata (method, URL, timestamps)

---

proxy rule <command> [options]

  Manage rules applied to proxied and sent request/response traffic.
  To modify a rule, delete it and recreate with the new values.

  Commands:
    list       List configured rules
    add        Add a new rule
    delete     Remove a rule

  Types:
    HTTP:      request_header (default), request_body, response_header, response_body
    WebSocket: ws:to-server, ws:to-client, ws:both

proxy rule list [options]

  Options:
    --websocket             List WebSocket rules instead of HTTP
    --limit <n>             Maximum rules to display

proxy rule add [options]

  Modes:
    --set <text>                    Append text (e.g., add a header line)
    --find <text> --replace <text>  Find and replace text
    --remove <text>                 Remove matching text

  Options:
    --type <type>           Rule type (default: request_header)
    --regex                 Treat pattern as regex (RE2)
    --label <name>          Optional label for easier reference

proxy rule delete <rule_id>

  Delete a rule by ID or label.
  Searches both HTTP and WebSocket rules automatically.

---

proxy clear [options]

  Remove flows from proxy and replay history. Exactly one mode is required.
  Native proxy backend only; Burp should use the UI to remove proxy records.

  Modes:
    --flow <id>             delete a single flow
    --before <id>           delete all flows before id (anchor kept)
    --after <id>            delete all flows after id (anchor kept)
    --from <id> --to <id>   inclusive range; either flag alone is open-ended
    --all                   delete every flow
`)
}

func parseSummary(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy summary", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var host, path, method, status, searchHeader, searchBody, excludeHost, excludePath, source string

	fs.StringVar(&source, "source", "", "filter by source: 'proxy', 'replay', or empty for both")
	fs.StringVar(&host, "host", "", "filter by host pattern (glob: *, ?)")
	fs.StringVar(&path, "path", "", "filter by path pattern (glob: *, ?)")
	fs.StringVar(&method, "method", "", "filter by HTTP method (comma-separated)")
	fs.StringVar(&status, "status", "", "filter by status code (e.g., 200,4XX)")
	fs.StringVar(&searchHeader, "search-header", "", "regex search in request/response headers (RE2)")
	fs.StringVar(&searchBody, "search-body", "", "regex search in request/response body (RE2)")
	fs.StringVar(&excludeHost, "exclude-host", "", "exclude hosts matching pattern")
	fs.StringVar(&excludePath, "exclude-path", "", "exclude paths matching pattern")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy summary [options]

Get aggregated summary of proxy history grouped by host/path/method/status.
Use this first to understand available traffic before using proxy list.

Filter examples:
  --host api.example.com          Exact host match
  --host "*example.com"           Glob pattern
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

	return summary(mcpURL, source, host, path, method, status, searchHeader, searchBody, excludeHost, excludePath)
}

func parseList(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy list", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var limit, offset int
	var host, path, method, status, searchHeader, searchBody, since, excludeHost, excludePath, source string
	var adapter, protocolTag, parentFlowID string

	fs.StringVar(&source, "source", "", "filter by source: 'proxy', 'replay', or empty for both")
	fs.StringVar(&host, "host", "", "filter by host pattern (glob: *, ?)")
	fs.StringVar(&path, "path", "", "filter by path pattern (glob: *, ?)")
	fs.StringVar(&method, "method", "", "filter by HTTP method (comma-separated)")
	fs.StringVar(&status, "status", "", "filter by status code (e.g., 200,4XX)")
	fs.StringVar(&searchHeader, "search-header", "", "regex search in request/response headers (RE2)")
	fs.StringVar(&searchBody, "search-body", "", "regex search in request/response body (RE2)")
	fs.StringVar(&since, "since", "", "filter since flow_id or 'last'")
	fs.StringVar(&excludeHost, "exclude-host", "", "exclude hosts matching pattern")
	fs.StringVar(&excludePath, "exclude-path", "", "exclude paths matching pattern")
	fs.StringVar(&adapter, "adapter", "", "filter by emitting adapter name (glob: *, ?)")
	fs.StringVar(&protocolTag, "protocol-tag", "", "filter by protocol tag (glob: *, ?)")
	fs.StringVar(&parentFlowID, "parent-flow-id", "", "list child flows of this parent flow_id")
	fs.IntVar(&limit, "limit", 0, "maximum number of flows to return")
	fs.IntVar(&offset, "offset", 0, "skip first N results for pagination")
	fs.IntVar(&limit, "count", 0, "alias for --limit")
	_ = fs.MarkHidden("count")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy list [options]

List individual flows with flow_id for export or replay.

Filter examples:
  --host api.example.com          Exact host match
  --host "*example.com"           Glob pattern
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

	// Auto-set large limit if no filters provided (MCP refuses list with no limits or filters)
	if limit == 0 && source == "" && host == "" && path == "" && method == "" && status == "" && searchHeader == "" && searchBody == "" && since == "" && excludeHost == "" && excludePath == "" && adapter == "" && protocolTag == "" && parentFlowID == "" {
		limit = 1_000_000_000
	}

	return list(mcpURL, listFilters{
		source: source, host: host, path: path, method: method, status: status,
		searchHeader: searchHeader, searchBody: searchBody, since: since,
		excludeHost: excludeHost, excludePath: excludePath,
		adapter: adapter, protocolTag: protocolTag, parentFlowID: parentFlowID,
		limit: limit, offset: offset,
	})
}

func parseGet(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy get", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var scope, pattern string

	fs.StringVar(&scope, "scope", "", "sections to include (comma-separated): request_headers, request_body, response_headers, response_body, all")
	fs.StringVar(&pattern, "pattern", "", "regex pattern to search within scoped sections (RE2)")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy get <flow_id> [options]

Get full request and response data for a flow.

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

	return get(mcpURL, fs.Args()[0], scope, pattern)
}

func parseExport(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy export", pflag.ContinueOnError)
	fs.SetInterspersed(true)

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

	return export(mcpURL, fs.Args()[0])
}

var ruleSubcommands = []string{"list", "add", "delete", "help"}

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

Manage rules for request/response modification.
To modify a rule, delete it and recreate with the new values.

Commands:
  list       List configured rules
  add        Add a new rule
  delete     Remove a rule

Use "sectool proxy rule <command> --help" for more information.
`)
}

func parseRuleList(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy rule list", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var websocket bool
	var limit int

	fs.BoolVar(&websocket, "websocket", false, "list WebSocket rules")
	fs.IntVar(&limit, "limit", 0, "maximum rules to display")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy rule list [options]

List configured find/replace rules.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return ruleList(mcpURL, websocket, limit)
}

func parseRuleAdd(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy rule add", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var isRegex bool
	var ruleType, label, name, find, replace, set, remove string

	fs.StringVar(&ruleType, "type", "request_header", "rule type")
	fs.BoolVar(&isRegex, "regex", false, "treat find as regex pattern (RE2)")
	fs.StringVar(&label, "label", "", "optional label for easier reference")
	fs.StringVar(&name, "name", "", "alias for --label")
	fs.StringVar(&set, "set", "", "text to append")
	fs.StringVar(&find, "find", "", "text or pattern to find")
	fs.StringVar(&replace, "replace", "", "replacement text")
	fs.StringVar(&remove, "remove", "", "text or pattern to remove")
	_ = fs.MarkHidden("name")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy rule add [options]

Add a rule to modify proxied and sent requests/responses.

Modes:
  --set <text>                    Append text (e.g., add a header line)
  --find <text> --replace <text>  Find and replace text
  --remove <text>                 Remove matching text

Types:
  HTTP:      request_header (default), request_body, response_header, response_body
  WebSocket: ws:to-server, ws:to-client, ws:both

Examples:
  sectool proxy rule add --set "X-Bug-Bounty: HackerOne-12345"                 # Add request header
  sectool proxy rule add --find "User-Agent: old" --replace "User-Agent: new"  # Replace header
  sectool proxy rule add --type request_body --find "test" --replace "prod"    # Replace in body
  sectool proxy rule add --remove "X-Debug-Info:.*\r\n" --regex                # Remove header

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

	// Validate flag combinations
	if set != "" && (find != "" || replace != "" || remove != "") {
		return errors.New("--set cannot be combined with --find, --replace, or --remove")
	}
	if remove != "" && (find != "" || replace != "" || set != "") {
		return errors.New("--remove cannot be combined with --find, --replace, or --set")
	}

	// Map high-level flags to find/replace pair
	switch {
	case set != "":
		find, replace = "", set
	case remove != "":
		find, replace = remove, ""
	}

	if find == "" && replace == "" {
		return errors.New("one of --set, --find, or --remove is required")
	}

	return ruleAdd(mcpURL, ruleType, find, replace, label, isRegex)
}

func parseRuleDelete(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy rule delete", pflag.ContinueOnError)
	fs.SetInterspersed(true)

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

	return ruleDelete(mcpURL, fs.Args()[0])
}

func parseCookies(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy cookies", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var name, domain string

	fs.StringVar(&name, "name", "", "filter by cookie name (exact match)")
	fs.StringVar(&domain, "domain", "", "filter by domain (matches domain and subdomains)")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy cookies [options]

Extract and deduplicate cookies from proxy and replay traffic.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return cookies(mcpURL, name, domain)
}

func parseClear(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("proxy clear", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var opts clearOpts

	fs.StringVar(&opts.flow, "flow", "", "delete a single flow by flow_id")
	fs.StringVar(&opts.before, "before", "", "delete all flows before this flow_id (anchor kept)")
	fs.StringVar(&opts.after, "after", "", "delete all flows after this flow_id (anchor kept)")
	fs.StringVar(&opts.from, "from", "", "lower bound flow_id for inclusive range (pair with --to; either alone is open-ended)")
	fs.StringVar(&opts.to, "to", "", "upper bound flow_id for inclusive range")
	fs.BoolVar(&opts.all, "all", false, "delete all proxy and replay history")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool proxy clear [options]

Remove flows from proxy and replay history. Exactly one mode is required.
Native proxy backend only; Burp returns an actionable error.

Modes:
  --flow <id>             delete a single flow
  --before <id>           delete all flows before id (id itself kept)
  --after <id>            delete all flows after id (id itself kept)
  --from <id> --to <id>   inclusive range; either flag alone is open-ended
  --all                   delete every flow
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	switch opts.modeCount() {
	case 0:
		fs.Usage()
		return errors.New("a clear mode is required (--flow, --before, --after, --from/--to, or --all)")
	case 1:
		// ok
	default:
		fs.Usage()
		return errors.New("clear modes are mutually exclusive")
	}

	return clear(mcpURL, opts)
}

package crawl

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/go-appsec/toolbox/sectool/cliutil"
)

const (
	subcmdForms  = "forms"
	subcmdErrors = "errors"
)

var crawlSubcommands = []string{"create", "seed", "status", "summary", "list", "get", subcmdForms, subcmdErrors, "sessions", "stop", "export", "help"}

func Parse(args []string, mcpURL string) error {
	if len(args) < 1 {
		printUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case "create":
		return parseCreate(args[1:], mcpURL)
	case "seed":
		return parseSeed(args[1:], mcpURL)
	case "status":
		return parseStatus(args[1:], mcpURL)
	case "summary":
		return parseSummary(args[1:], mcpURL)
	case "list":
		return parseList(args[1:], mcpURL)
	case "get":
		return parseGet(args[1:], mcpURL)
	case subcmdForms:
		return parseForms(args[1:], mcpURL)
	case subcmdErrors:
		return parseErrors(args[1:], mcpURL)
	case "sessions":
		return parseSessions(args[1:], mcpURL)
	case "stop":
		return parseStop(args[1:], mcpURL)
	case "export":
		return parseExport(args[1:], mcpURL)
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return cliutil.UnknownSubcommandError("crawl", args[0], crawlSubcommands)
	}
}

func printUsage() {
	_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl <command> [options]

Web crawler for discovering URLs, forms, and content by following links.

---

crawl create [options]

  Start a new crawl session. Crawling runs asynchronously in the background.

  Options:
    --url <url>            seed URL (can specify multiple times)
    --flow <flow_id>       seed from proxy flow (can specify multiple times)
    --domain <domain>      additional allowed domain (can specify multiple times)
    --label <str>          optional unique label for easier reference
    --max-depth <n>        maximum crawl depth (0 = unlimited)
    --max-requests <n>     maximum total requests (0 = unlimited)
    --delay <dur>          delay between requests (default: 200ms)
    --parallelism <n>      concurrent requests (default: 2)
    --submit-forms         automatically submit discovered forms
    --ignore-robots        ignore robots.txt restrictions

  Output: session_id and initial state

---

crawl seed <session_id> [options]

  Add seeds to a running crawl session.

  Options:
    --url <url>            seed URL (can specify multiple times)
    --flow <flow_id>       seed from proxy flow (can specify multiple times)

  Output: Number of seeds added

---

crawl status <session_id>

  Get progress metrics for a crawl session.

  Output: URLs queued, visited, errored, forms discovered

---

crawl summary <session_id> [options]

  Get aggregated summary grouped by host/path/method/status.

  Options:
    --host <pattern>          filter by host pattern (glob: *, ?)
    --path <pattern>          filter by path pattern (glob: *, ?)
    --method <list>           filter by HTTP method (comma-separated)
    --status <list>           filter by status codes (comma-separated, e.g., 200,4XX)
    --search-header <regex>   regex search in request/response headers (RE2)
    --search-body <regex>     regex search in request/response body (RE2)
    --exclude-host <pat>      exclude hosts matching pattern
    --exclude-path <pat>      exclude paths matching pattern

  Output: Markdown table with host, path, method, status, count

---

crawl list <session_id> [options]

  List crawled URLs from a session.

  Options:
    --host <pattern>          filter by host pattern (glob: *, ?)
    --path <pattern>          filter by path pattern (glob: *, ?)
    --method <list>           filter by HTTP method (comma-separated)
    --status <list>           filter by status codes (comma-separated, e.g., 200,4XX)
    --search-header <regex>   regex search in request/response headers (RE2)
    --search-body <regex>     regex search in request/response body (RE2)
    --exclude-host <pat>      exclude hosts matching pattern
    --exclude-path <pat>      exclude paths matching pattern
    --since <val>             flows after: flow_id, timestamp, or 'last'
    --limit <n>               maximum result count
    --offset <n>              skip first N results

  Output: Markdown table with flow_id, method, host, path, status, size

---

crawl get <flow_id> [options]

  Get full request and response data for a crawled flow.

  Options:
    --scope <sections>        sections to include (comma-separated):
                              request_headers, request_body, response_headers,
                              response_body, all (default)
    --pattern <regex>         regex search within scoped sections (RE2)

  Output: Request/response headers and body for the specified sections

---

crawl forms <session_id> [options]

  List forms discovered during crawling.

  Options:
    --limit <n>            maximum result count

  Output: Forms with fields and CSRF detection

---

crawl errors <session_id> [options]

  List errors encountered during crawling.

  Options:
    --limit <n>            maximum result count

  Output: Markdown table with URL and error message

---

crawl sessions [options]

  List all crawl sessions (most recent first).

  Options:
    --limit <n>            maximum sessions to return

  Output: Markdown table with session_id, label, state, created_at

---

crawl stop <session_id>

  Stop a running crawl session. In-flight requests are abandoned.

  Output: Confirmation message

---

crawl export <flow_id>

  Export a crawled flow to an editable bundle on disk.

  Output: Bundle path and list of created files
`)
}

func parseCreate(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl create", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var delay time.Duration
	var urls, flows, domains []string
	var label string
	var maxDepth, maxRequests, parallelism int
	var submitForms, ignoreRobots bool

	fs.StringArrayVar(&urls, "url", nil, "seed URL (can specify multiple times)")
	fs.StringArrayVar(&flows, "flow", nil, "seed from proxy flow_id (can specify multiple times)")
	fs.StringArrayVar(&domains, "domain", nil, "additional allowed domain (can specify multiple times)")
	fs.StringVar(&label, "label", "", "optional unique label for easier reference")
	fs.IntVar(&maxDepth, "max-depth", 0, "maximum crawl depth (0 = unlimited)")
	fs.IntVar(&maxRequests, "max-requests", 0, "maximum total requests (0 = unlimited)")
	fs.DurationVar(&delay, "delay", 0, "delay between requests")
	fs.IntVar(&parallelism, "parallelism", 0, "concurrent requests")
	fs.BoolVar(&submitForms, "submit-forms", false, "automatically submit discovered forms")
	fs.BoolVar(&ignoreRobots, "ignore-robots", false, "ignore robots.txt restrictions")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl create [options]

Start a new crawl session.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(urls) == 0 && len(flows) == 0 {
		fs.Usage()
		return errors.New("at least one --url or --flow is required")
	}

	return create(mcpURL, urls, flows, domains, label, maxDepth, maxRequests, delay, parallelism, submitForms, ignoreRobots)
}

func parseSeed(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl seed", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var urls, flows []string

	fs.StringArrayVar(&urls, "url", nil, "seed URL (can specify multiple times)")
	fs.StringArrayVar(&flows, "flow", nil, "seed from proxy flow_id (can specify multiple times)")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl seed <session_id> [options]

Add seeds to a running crawl session.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("session_id required (get from 'sectool crawl create' or 'sectool crawl sessions')")
	} else if len(urls) == 0 && len(flows) == 0 {
		fs.Usage()
		return errors.New("at least one --url or --flow is required")
	}

	return seed(mcpURL, fs.Args()[0], urls, flows)
}

func parseStatus(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl status", pflag.ContinueOnError)
	fs.SetInterspersed(true)

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl status <session_id> [options]

Get status of a crawl session.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("session_id required")
	}

	return status(mcpURL, fs.Args()[0])
}

func parseSummary(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl summary", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var host, path, method, status, searchHeader, searchBody, excludeHost, excludePath string

	fs.StringVar(&host, "host", "", "filter by host pattern (glob: *, ?)")
	fs.StringVar(&path, "path", "", "filter by path pattern (glob: *, ?)")
	fs.StringVar(&method, "method", "", "filter by HTTP method (comma-separated)")
	fs.StringVar(&status, "status", "", "filter by status code (e.g., 200,4XX)")
	fs.StringVar(&searchHeader, "search-header", "", "regex search in request/response headers (RE2)")
	fs.StringVar(&searchBody, "search-body", "", "regex search in request/response body (RE2)")
	fs.StringVar(&excludeHost, "exclude-host", "", "exclude hosts matching pattern")
	fs.StringVar(&excludePath, "exclude-path", "", "exclude paths matching pattern")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl summary <session_id> [options]

Get aggregated summary of a crawl session.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("session_id required")
	}

	return summary(mcpURL, fs.Args()[0], host, path, method, status, searchHeader, searchBody, excludeHost, excludePath)
}

func parseList(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl list", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var host, path, method, status, searchHeader, searchBody, excludeHost, excludePath, since string
	var limit, offset int

	fs.StringVar(&host, "host", "", "filter by host pattern (glob: *, ?)")
	fs.StringVar(&path, "path", "", "filter by path pattern (glob: *, ?)")
	fs.StringVar(&method, "method", "", "filter by HTTP method (comma-separated)")
	fs.StringVar(&status, "status", "", "filter by status codes (e.g., 200,4XX)")
	fs.StringVar(&searchHeader, "search-header", "", "regex search in request/response headers (RE2)")
	fs.StringVar(&searchBody, "search-body", "", "regex search in request/response body (RE2)")
	fs.StringVar(&excludeHost, "exclude-host", "", "exclude hosts matching pattern")
	fs.StringVar(&excludePath, "exclude-path", "", "exclude paths matching pattern")
	fs.StringVar(&since, "since", "", "flows after flow_id or timestamp")
	fs.IntVar(&limit, "limit", 0, "maximum result count")
	fs.IntVar(&offset, "offset", 0, "skip first N results")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl list <session_id> [options]

List crawled URLs from a session.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("session_id required")
	}

	// Auto-set large limit if no filters provided (MCP refuses list with no limits or filters)
	if limit == 0 && host == "" && path == "" && method == "" && status == "" && searchHeader == "" && searchBody == "" && excludeHost == "" && excludePath == "" && since == "" {
		limit = 1_000_000_000
	}

	return list(mcpURL, fs.Args()[0], "urls", host, path, method, status, searchHeader, searchBody, excludeHost, excludePath, since, limit, offset)
}

func parseGet(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl get", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var scope, pattern string

	fs.StringVar(&scope, "scope", "", "sections to include (comma-separated): request_headers, request_body, response_headers, response_body, all")
	fs.StringVar(&pattern, "pattern", "", "regex pattern to search within scoped sections (RE2)")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl get <flow_id> [options]

Get full request and response data for a crawled flow.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("flow_id required (get from 'sectool crawl list')")
	}

	return get(mcpURL, fs.Args()[0], scope, pattern)
}

func parseForms(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl forms", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var limit int

	fs.IntVar(&limit, "limit", 0, "maximum result count")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl forms <session_id> [options]

List forms discovered during crawling.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("session_id required")
	}

	return list(mcpURL, fs.Args()[0], "forms", "", "", "", "", "", "", "", "", "", limit, 0)
}

func parseErrors(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl errors", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var limit int

	fs.IntVar(&limit, "limit", 0, "maximum result count")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl errors <session_id> [options]

List errors encountered during crawling.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("session_id required")
	}

	return list(mcpURL, fs.Args()[0], "errors", "", "", "", "", "", "", "", "", "", limit, 0)
}

func parseSessions(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl sessions", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var limit int

	fs.IntVar(&limit, "limit", 0, "maximum sessions to return")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl sessions [options]

List all crawl sessions.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return sessions(mcpURL, limit)
}

func parseStop(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl stop", pflag.ContinueOnError)
	fs.SetInterspersed(true)

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl stop <session_id> [options]

Stop a running crawl session.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("session_id required")
	}

	return stop(mcpURL, fs.Args()[0])
}

func parseExport(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl export", pflag.ContinueOnError)
	fs.SetInterspersed(true)

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl export <flow_id> [options]

Export a crawled flow to an editable bundle on disk.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("flow_id required (get from 'sectool crawl list')")
	}

	return export(mcpURL, fs.Args()[0])
}

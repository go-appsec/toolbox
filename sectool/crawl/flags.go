package crawl

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/go-harden/llm-security-toolbox/sectool/cli"
)

const (
	subcmdForms  = "forms"
	subcmdErrors = "errors"
)

var crawlSubcommands = []string{"create", "seed", "status", "summary", "list", subcmdForms, subcmdErrors, "sessions", "stop", "export", "help"}

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
		return cli.UnknownSubcommandError("crawl", args[0], crawlSubcommands)
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
    --no-subdomains        don't include subdomains
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

crawl summary <session_id>

  Get aggregated summary grouped by host/path/method/status.
  Same format as 'proxy summary' for consistency.

  Output: Markdown table with host, path, method, status, count

---

crawl list <session_id> [options]

  List crawled URLs from a session.

  Options:
    --host <pattern>       filter by host pattern (glob: *, ?)
    --path <pattern>       filter by path pattern (glob: *, ?)
    --method <list>        filter by HTTP method (comma-separated)
    --status <list>        filter by status codes (comma-separated, e.g., 200,4XX)
    --contains <text>      search URL and headers
    --contains-body <text> search request/response body
    --exclude-host <pat>   exclude hosts matching pattern
    --exclude-path <pat>   exclude paths matching pattern
    --since <val>          flows after: flow_id, timestamp, or 'last'
    --limit <n>            maximum results (default: 100)
    --offset <n>           skip first N results

  Output: Markdown table with flow_id, method, host, path, status, size

---

crawl forms <session_id> [options]

  List forms discovered during crawling.

  Options:
    --limit <n>            maximum results (default: 100)

  Output: Forms with fields and CSRF detection

---

crawl errors <session_id> [options]

  List errors encountered during crawling.

  Options:
    --limit <n>            maximum results (default: 100)

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
	var timeout, delay time.Duration
	var urls, flows, domains []string
	var label string
	var maxDepth, maxRequests, parallelism int
	var noSubdomains, submitForms, ignoreRobots bool

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringArrayVar(&urls, "url", nil, "seed URL (can specify multiple times)")
	fs.StringArrayVar(&flows, "flow", nil, "seed from proxy flow_id (can specify multiple times)")
	fs.StringArrayVar(&domains, "domain", nil, "additional allowed domain (can specify multiple times)")
	fs.StringVar(&label, "label", "", "optional unique label for easier reference")
	fs.IntVar(&maxDepth, "max-depth", 0, "maximum crawl depth (0 = unlimited)")
	fs.IntVar(&maxRequests, "max-requests", 0, "maximum total requests (0 = unlimited)")
	fs.DurationVar(&delay, "delay", 0, "delay between requests")
	fs.IntVar(&parallelism, "parallelism", 0, "concurrent requests")
	fs.BoolVar(&noSubdomains, "no-subdomains", false, "don't include subdomains")
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
	}

	if len(urls) == 0 && len(flows) == 0 {
		fs.Usage()
		return errors.New("at least one --url or --flow is required")
	}

	return create(mcpURL, timeout, urls, flows, domains, label, maxDepth, maxRequests, delay, parallelism, !noSubdomains, submitForms, ignoreRobots)
}

func parseSeed(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl seed", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var urls, flows []string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
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
	}

	if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("session_id required (get from 'sectool crawl create' or 'sectool crawl sessions')")
	}

	if len(urls) == 0 && len(flows) == 0 {
		fs.Usage()
		return errors.New("at least one --url or --flow is required")
	}

	return seed(mcpURL, timeout, fs.Args()[0], urls, flows)
}

func parseStatus(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl status", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl status <session_id> [options]

Get status of a crawl session.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("session_id required")
	}

	return status(mcpURL, timeout, fs.Args()[0])
}

func parseSummary(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl summary", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl summary <session_id> [options]

Get aggregated summary of a crawl session.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("session_id required")
	}

	return summary(mcpURL, timeout, fs.Args()[0])
}

func parseList(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl list", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var host, path, method, status, contains, containsBody, excludeHost, excludePath, since string
	var limit, offset int

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&host, "host", "", "filter by host pattern (glob: *, ?)")
	fs.StringVar(&path, "path", "", "filter by path pattern (glob: *, ?)")
	fs.StringVar(&method, "method", "", "filter by HTTP method (comma-separated)")
	fs.StringVar(&status, "status", "", "filter by status codes (e.g., 200,4XX)")
	fs.StringVar(&contains, "contains", "", "search in URL and headers")
	fs.StringVar(&containsBody, "contains-body", "", "search in request/response body")
	fs.StringVar(&excludeHost, "exclude-host", "", "exclude hosts matching pattern")
	fs.StringVar(&excludePath, "exclude-path", "", "exclude paths matching pattern")
	fs.StringVar(&since, "since", "", "flows after flow_id or timestamp")
	fs.IntVar(&limit, "limit", 100, "maximum results")
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
	}

	if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("session_id required")
	}

	return list(mcpURL, timeout, fs.Args()[0], "urls", host, path, method, status, contains, containsBody, excludeHost, excludePath, since, limit, offset)
}

func parseForms(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl forms", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var limit int

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.IntVar(&limit, "limit", 100, "maximum results")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl forms <session_id> [options]

List forms discovered during crawling.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("session_id required")
	}

	return list(mcpURL, timeout, fs.Args()[0], "forms", "", "", "", "", "", "", "", "", "", limit, 0)
}

func parseErrors(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl errors", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var limit int

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.IntVar(&limit, "limit", 100, "maximum results")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl errors <session_id> [options]

List errors encountered during crawling.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("session_id required")
	}

	return list(mcpURL, timeout, fs.Args()[0], "errors", "", "", "", "", "", "", "", "", "", limit, 0)
}

func parseSessions(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl sessions", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var limit int

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
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

	return sessions(mcpURL, timeout, limit)
}

func parseStop(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl stop", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl stop <session_id> [options]

Stop a running crawl session.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("session_id required")
	}

	return stop(mcpURL, timeout, fs.Args()[0])
}

func parseExport(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("crawl export", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool crawl export <flow_id> [options]

Export a crawled flow to an editable bundle on disk.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("flow_id required (get from 'sectool crawl list')")
	}

	return export(mcpURL, timeout, fs.Args()[0])
}

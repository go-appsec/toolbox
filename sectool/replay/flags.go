package replay

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/go-appsec/llm-security-toolbox/sectool/cliutil"
)

var replaySubcommands = []string{"send", "get", "create", "help"}

func Parse(args []string, mcpURL string) error {
	if len(args) < 1 {
		printUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case "send":
		return parseSend(args[1:], mcpURL)
	case "get":
		return parseGet(args[1:], mcpURL)
	case "create":
		return parseCreate(args[1:], mcpURL)
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return cliutil.UnknownSubcommandError("replay", args[0], replaySubcommands)
	}
}

func printUsage() {
	_, _ = fmt.Fprint(os.Stderr, `Usage: sectool replay <command> [options]

Replay or send HTTP requests through the http backend.

---

replay send [options]

  Send a request through the HTTP backend.

  Input sources (exactly one required):
    --flow <flow_id>      replay from proxy history
    --bundle <bundle_id>  replay from exported bundle (from proxy export)
    --file <path>         replay from raw HTTP file (- for stdin)

  Request modifications (combine multiple):
    --set-header "Name: Value"     add or replace header
    --remove-header "Name"         remove header
    --path "/new/path"             replace URL path
    --query "key=val&k2=v2"        replace entire query string
    --set-query "key=value"        add or replace query param
    --remove-query "key"           remove query param
    --target "https://other:8443"  override destination host

  JSON body modifications:
    --set-json "key=value"         set key (infers type: null/bool/number/object/string)
    --set-json "key"               set key to null (no = sign)
    --remove-json "key"            remove key from JSON body

    Nested paths: user.email, items[0].id, data.users[0].name
    Objects/arrays: --set-json 'meta={"k":"v"}' or 'ids=[1,2,3]'

  Note: Content-Length header is automatically updated when body changes.

  Other options:
    --follow-redirects             follow 3xx redirects
    --request-timeout <dur>        HTTP timeout (0 = no timeout)
    --force                        send even if validation fails
    --body <path>                  body file (with --file)

  Examples:
    sectool replay send --flow f7k2x
    sectool replay send --flow f7k2x --set-header "Authorization: Bearer tok"
    sectool replay send --flow f7k2x --path /api/v2/users --set-query "id=123"
    sectool replay send --flow f7k2x --set-json "user.role=admin"
    sectool replay send --bundle abc123
    sectool replay send --file request.http --body payload

  Output: Markdown with replay_id, status, headers, body preview

---

replay get <replay_id>

  Retrieve full details of a previous replay.

  Example:
    sectool replay get rpl_abc123           # get full response

  Output: Markdown with status, headers, and complete response body

---

replay create <url> [options]

  Create a request bundle from scratch (without capturing traffic first).
  Creates an editable bundle that can be modified and sent with 'replay send'.

  Arguments:
    <url>       Target URL (defaults to HTTPS)

  Options:
    --method        HTTP method (default: GET)
    --header        Header in 'Name: Value' format (repeatable)
    --body          Path to body file (- for stdin)

  Examples:
    sectool replay create https://api.example.com/users
    sectool replay create example.com/api/v1/data --method POST --body payload.json
    sectool replay create https://api.example.com --header "Authorization: Bearer token"

  Output: Bundle path that can be used with 'sectool replay send --bundle'
`)
}

func parseSend(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("replay send", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout, requestTimeout time.Duration
	var flow, bundle, file, body, target, path, query string
	var followRedirects, force bool
	var headers, removeHeaders, setQuery, removeQuery, setJSON, removeJSON []string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&flow, "flow", "", "flow_id to replay from proxy history")
	fs.StringVar(&bundle, "bundle", "", "bundle_id from proxy export")
	fs.StringVar(&file, "file", "", "path to request.http file (- for stdin)")
	fs.StringVar(&body, "body", "", "path to body file (use with --file)")
	fs.StringVar(&target, "target", "", "override target URL (scheme://host:port)")
	fs.StringArrayVar(&headers, "set-header", nil, "add or replace header (repeatable)")
	fs.StringArrayVar(&removeHeaders, "remove-header", nil, "remove header by name (repeatable)")
	fs.StringVar(&path, "path", "", "replace URL path (e.g., /api/v2/users)")
	fs.StringVar(&query, "query", "", "replace entire query string (e.g., id=1&debug=true)")
	fs.StringArrayVar(&setQuery, "set-query", nil, "add or replace query param (repeatable, e.g., id=123)")
	fs.StringArrayVar(&removeQuery, "remove-query", nil, "remove query param by name (repeatable)")
	fs.StringArrayVar(&setJSON, "set-json", nil, "set JSON key (repeatable, e.g., user.role=admin)")
	fs.StringArrayVar(&removeJSON, "remove-json", nil, "remove JSON key (repeatable)")
	fs.BoolVar(&followRedirects, "follow-redirects", false, "follow 3xx redirects")
	fs.DurationVar(&requestTimeout, "request-timeout", 0, "HTTP request timeout (0 = no timeout)")
	fs.BoolVar(&force, "force", false, "send request even if validation fails")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool replay send [options]

Send a request through the HTTP backend.

Input sources (exactly one required):
  --flow <flow_id>      Replay from proxy history (get flow_id from 'sectool proxy list')
  --bundle <bundle_id>  Replay from exported bundle (create with 'sectool proxy export')
  --file <path>         Replay from raw HTTP file (- for stdin)

File format (--file):
  Standard HTTP/1.1 request format. First line is the request line, followed
  by headers, a blank line, then optional body.

  IMPORTANT: HTTP requires CRLF (\r\n) line endings, not Unix-style LF (\n).
  Most text editors save with LF by default. To create a valid request file:
    printf 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' > request.http
  Or use 'sectool proxy export' to create an editable bundle from captured traffic.

Request modifications:
  Modify request without editing files. Multiple modifications can be combined.

  Headers:
    --set-header "Name: Value"    Add or replace a header
    --remove-header "Name"        Remove a header by name

  Path and query string:
    --path "/new/path"        Replace the URL path
    --query "key=val&k2=v2"   Replace the entire query string
    --set-query "key=value"   Add or replace a query parameter
    --remove-query "key"      Remove a query parameter by name

  Target:
    --target scheme://host    Override destination host and scheme

  Query modification order: remove -> set

JSON body modifications:
  Modify JSON request bodies inline without editing files. Requires the request
  body to be valid JSON (returns error with hint otherwise).

  Smart type inference:
    --set-json "key=value"         Infers type from value:
                                   - null, true, false -> literal
                                   - 123, 3.14 -> number
                                   - {"a":1}, [1,2] -> object/array
                                   - everything else -> string
    --set-json "key"               Set to null (no = sign)
    --remove-json "key"            Remove key from JSON

  Nested paths (dot notation with array indices):
    --set-json "user.email=test@evil.com"
    --set-json "items[0].id=injected"
    --set-json 'config={"debug":true}'

  Modification order: remove -> set

  Note: Content-Length header is automatically updated when body changes.

Validation:
  Requests are validated before sending. If validation fails, the request
  is NOT sent and errors are displayed. Use --force to send anyway (useful
  for testing HTTP parser behavior with intentionally malformed requests).

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	var sources int
	if flow != "" {
		sources++
	}
	if bundle != "" {
		sources++
	}
	if file != "" {
		sources++
	}
	if sources == 0 {
		fs.Usage()
		return errors.New("one of --flow, --bundle, or --file is required")
	} else if sources > 1 {
		return errors.New("only one of --flow, --bundle, or --file can be specified")
	}

	return send(mcpURL, timeout, flow, bundle, file, body, target, headers, removeHeaders,
		path, query, setQuery, removeQuery,
		setJSON, removeJSON,
		followRedirects, requestTimeout, force)
}

func parseGet(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("replay get", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool replay get <replay_id> [options]

Get details of a previous replay.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("replay_id required (get from 'sectool replay send' output)")
	}

	return get(mcpURL, timeout, fs.Args()[0])
}

func parseCreate(args []string, mcpURL string) error {
	fs := pflag.NewFlagSet("replay create", pflag.ContinueOnError)
	fs.SetInterspersed(true)

	var timeout time.Duration
	var method, bodyPath string
	var headers []string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&method, "method", "GET", "HTTP method")
	fs.StringArrayVar(&headers, "header", nil, "header in 'Name: Value' format (repeatable)")
	fs.StringVar(&bodyPath, "body", "", "path to body file (- for stdin)")

	fs.Usage = func() {
		_, _ = fmt.Fprint(os.Stderr, `Usage: sectool replay create <url> [options]

Create a request bundle from scratch (without capturing traffic first).

Arguments:
  <url>       Target URL (defaults to HTTPS if scheme not specified)

Options:
`)
		fs.PrintDefaults()
		_, _ = fmt.Fprint(os.Stderr, `
Examples:
  sectool replay create https://api.example.com/users
  sectool replay create example.com/api/v1/data --method POST --body payload.json
  sectool replay create https://api.example.com --header "Authorization: Bearer token"

Output: Bundle path that can be used with 'sectool replay send --bundle'
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	} else if len(fs.Args()) < 1 {
		fs.Usage()
		return errors.New("url argument is required")
	}

	return create(mcpURL, timeout, fs.Args()[0], method, headers, bodyPath)
}

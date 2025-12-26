package replay

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/jentfoo/llm-security-toolbox/sectool/cli"
)

var replaySubcommands = []string{"send", "get", "help"}

func Parse(args []string) error {
	if len(args) < 1 {
		printUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case "send":
		return parseSend(args[1:])
	case "get":
		return parseGet(args[1:])
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return cli.UnknownSubcommandError("replay", args[0], replaySubcommands)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: sectool replay <command> [options]

Replay HTTP requests through Burp.

Commands:
  send       Send a request (from flow, bundle, or file)
  get        Get details of a previous replay

Use "sectool replay <command> --help" for more information.
`)
}

func parseSend(args []string) error {
	fs := pflag.NewFlagSet("replay send", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout, requestTimeout time.Duration
	var flow, bundle, file, body, target string
	var followRedirects, force bool
	var headers, removeHeaders []string

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.StringVar(&flow, "flow", "", "flow_id to replay from proxy history")
	fs.StringVar(&bundle, "bundle", "", "path to request bundle directory")
	fs.StringVar(&file, "file", "", "path to request.http file (- for stdin)")
	fs.StringVar(&body, "body", "", "path to body file (use with --file)")
	fs.StringVar(&target, "target", "", "override target URL (scheme://host:port)")
	fs.StringArrayVar(&headers, "header", nil, "add/replace header (repeatable)")
	fs.StringArrayVar(&removeHeaders, "remove-header", nil, "remove header by name (repeatable)")
	fs.BoolVar(&followRedirects, "follow-redirects", false, "follow 3xx redirects")
	fs.DurationVar(&requestTimeout, "request-timeout", 0, "HTTP request timeout (0 = no timeout)")
	fs.BoolVar(&force, "force", false, "send request even if validation fails")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool replay send [options]

Send a request through Burp Repeater.

Input sources (exactly one required):
  --flow <flow_id>      Replay from proxy history (get flow_id from 'sectool proxy list')
  --bundle <path>       Replay from exported bundle (create with 'sectool proxy export')
  --file <path>         Replay from raw HTTP file (- for stdin)

File format (--file):
  Standard HTTP/1.1 request format. First line is the request line, followed
  by headers, a blank line, then optional body.

  IMPORTANT: HTTP requires CRLF (\r\n) line endings, not Unix-style LF (\n).
  Most text editors save with LF by default. To create a valid request file:
    printf 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n' > request.http
  Or use 'sectool proxy export' to create an editable bundle from captured traffic.

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

	return send(timeout, flow, bundle, file, body, target, headers, removeHeaders, followRedirects, requestTimeout, force)
}

func parseGet(args []string) error {
	fs := pflag.NewFlagSet("replay get", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool replay get <replay_id> [options]

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

	return get(timeout, fs.Args()[0])
}

package encode

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/go-appsec/llm-security-toolbox/sectool/cli"
)

var encodeSubcommands = []string{"url", "base64", "html", "help"}

func Parse(args []string) error {
	if len(args) < 1 {
		printUsage()
		return errors.New("encoding type required")
	}

	switch args[0] {
	case "url":
		return parseAndRun("url", args[1:], encodeURL)
	case "base64":
		return parseAndRun("base64", args[1:], encodeBase64)
	case "html":
		return parseAndRun("html", args[1:], encodeHTML)
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return cli.UnknownSubcommandError("encode", args[0], encodeSubcommands)
	}
}

func printUsage() {
	_, _ = fmt.Fprint(os.Stderr, `Usage: sectool encode <type> [options] <string | -f PATH>

Encoding/decoding utilities for security testing payloads.
Runs locally, no service required.

---

encode url [options] <string>

  URL percent-encoding for query parameters and path segments.

  Examples:
    sectool encode url "hello world"           # hello%20world
    sectool encode url -d "hello%20world"      # hello world

---

encode base64 [options] <string>

  Base64 encoding for binary data and obfuscation.

  Examples:
    sectool encode base64 "secret"             # c2VjcmV0
    sectool encode base64 -d "c2VjcmV0"        # secret
    sectool encode base64 -f payload.bin       # encode file contents

---

encode html [options] <string>

  HTML entity encoding for XSS payload construction.

  Examples:
    sectool encode html "<script>"             # &lt;script&gt;
    sectool encode html -d "&lt;script&gt;"   # <script>

---

Common Options (all types):
  -d, --decode      decode instead of encode
  -f, --file PATH   read input from file (- for stdin)
  --raw             output without trailing newline

Output: Encoded/decoded string to stdout
`)
}

func parseAndRun(name string, args []string, fn func(string, bool) (string, error)) error {
	fs := pflag.NewFlagSet("encode "+name, pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var decode, raw bool
	var file string

	fs.BoolVarP(&decode, "decode", "d", false, "decode instead of encode")
	fs.StringVarP(&file, "file", "f", "", "read input from file (- for stdin)")
	fs.BoolVar(&raw, "raw", false, "output without trailing newline")

	fs.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: sectool encode %s [options] <string>\n\nOptions:\n", name)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	var input string
	if file != "" {
		var data []byte
		var err error
		if file == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(file)
		}
		if err != nil {
			return fmt.Errorf("reading input: %w", err)
		}
		input = string(data)
	} else if remaining := fs.Args(); len(remaining) > 0 {
		input = strings.Join(remaining, " ")
	} else {
		return errors.New("input required: provide string argument or use -f")
	}

	return run(input, decode, raw, fn)
}

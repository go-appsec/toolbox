package encoding

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/go-appsec/toolbox/sectool/cliutil"
)

var encodeTypes = []string{"url", "base64", "html", "help"}

// ParseEncode is the entry point for `sectool encode <type> <input>`.
func ParseEncode(args []string) error {
	if len(args) < 1 {
		printEncodeUsage()
		return errors.New("encoding type required")
	}

	switch args[0] {
	case "url", "base64", "html":
		encType := args[0]
		return parseAndRun("encode", encType, args[1:], func(s string) (string, error) { return Encode(s, encType) })
	case "help", "--help", "-h":
		printEncodeUsage()
		return nil
	default:
		return cliutil.UnknownSubcommandError("encode", args[0], encodeTypes)
	}
}

// ParseDecode is the entry point for `sectool decode <type> <input>`.
func ParseDecode(args []string) error {
	if len(args) < 1 {
		printDecodeUsage()
		return errors.New("encoding type required")
	}

	switch args[0] {
	case "url", "base64", "html":
		encType := args[0]
		return parseAndRun("decode", encType, args[1:], func(s string) (string, error) { return Decode(s, encType) })
	case "help", "--help", "-h":
		printDecodeUsage()
		return nil
	default:
		return cliutil.UnknownSubcommandError("decode", args[0], encodeTypes)
	}
}

func printEncodeUsage() {
	_, _ = fmt.Fprint(os.Stderr, `Usage: sectool encode <type> [options] <string | -f PATH>

Encode strings for security testing payloads.
Runs locally, no service required.

Types: url, base64, html

Examples:
  sectool encode url "hello world"           # hello+world
  sectool encode base64 "secret"             # c2VjcmV0
  sectool encode html "<script>"             # &lt;script&gt;
  sectool encode base64 -f payload.bin       # encode file contents

Options:
  -f, --file PATH   read input from file (- for stdin)
  --raw             output without trailing newline
`)
}

func printDecodeUsage() {
	_, _ = fmt.Fprint(os.Stderr, `Usage: sectool decode <type> [options] <string | -f PATH>

Decode strings for security testing payloads.
Runs locally, no service required.

Types: url, base64, html

Examples:
  sectool decode url "hello+world"           # hello world
  sectool decode base64 "c2VjcmV0"           # secret
  sectool decode html "&lt;script&gt;"       # <script>

Options:
  -f, --file PATH   read input from file (- for stdin)
  --raw             output without trailing newline
`)
}

func parseAndRun(command, typeName string, args []string, fn func(string) (string, error)) error {
	fs := pflag.NewFlagSet(command+" "+typeName, pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var raw bool
	var file string

	fs.StringVarP(&file, "file", "f", "", "read input from file (- for stdin)")
	fs.BoolVar(&raw, "raw", false, "output without trailing newline")

	fs.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "Usage: sectool %s %s [options] <string>\n\nOptions:\n", command, typeName)
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

	result, err := fn(input)
	if err != nil {
		return err
	}

	if raw {
		fmt.Print(result)
	} else {
		fmt.Println(result)
	}
	return nil
}

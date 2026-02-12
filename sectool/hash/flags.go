package hash

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/pflag"
)

// Parse is the entry point for `sectool hash <input> [--algorithm sha256] [--key hmac-key]`.
func Parse(args []string) error {
	fs := pflag.NewFlagSet("hash", pflag.ContinueOnError)
	fs.SetInterspersed(true)

	var algorithm, key, file string
	var raw bool

	fs.StringVar(&algorithm, "algorithm", "sha256", "hash algorithm: md5, sha1, sha256, sha512")
	fs.StringVar(&key, "key", "", "HMAC key (if set, computes HMAC instead of plain hash)")
	fs.StringVarP(&file, "file", "f", "", "read input from file (- for stdin)")
	fs.BoolVar(&raw, "raw", false, "output without trailing newline")

	fs.Usage = printUsage

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return nil
		}
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
		printUsage()
		return errors.New("input required: provide string argument or use -f")
	}

	result, err := ComputeHash(input, algorithm, key)
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

func printUsage() {
	_, _ = fmt.Fprint(os.Stderr, `Usage: sectool hash [options] <string | -f PATH>

Compute hash digests for security testing.
Runs locally, no service required.

Examples:
  sectool hash "test"                           # SHA-256 (default)
  sectool hash --algorithm md5 "test"           # MD5
  sectool hash --algorithm sha1 "test"          # SHA-1
  sectool hash --key "secret" "test"            # HMAC-SHA-256
  sectool hash -f payload.bin                   # hash file contents

Options:
  --algorithm <alg>   hash algorithm: md5, sha1, sha256, sha512 (default: sha256)
  --key <key>         HMAC key (computes HMAC instead of plain hash)
  -f, --file PATH     read input from file (- for stdin)
  --raw               output without trailing newline
`)
}

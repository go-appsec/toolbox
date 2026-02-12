package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"
)

// Parse is the entry point for `sectool jwt <token>`.
func Parse(args []string) error {
	fs := pflag.NewFlagSet("jwt", pflag.ContinueOnError)
	fs.Usage = printUsage

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return nil
		}
		return err
	}

	remaining := fs.Args()
	if len(remaining) < 1 {
		printUsage()
		return errors.New("JWT token required")
	}

	token := strings.Join(remaining, "")

	result, err := DecodeJWT(token)
	if err != nil {
		return err
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling result: %w", err)
	}

	fmt.Println(string(out))
	return nil
}

func printUsage() {
	_, _ = fmt.Fprint(os.Stderr, `Usage: sectool jwt <token>

Decode and inspect a JWT token.
Runs locally, no service required.

Strips "Bearer " prefix automatically. Reports security issues:
- Algorithm set to 'none'
- Missing expiry claim
- Expired token
- Long-lived token (>30 days)

Examples:
  sectool jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature
  sectool jwt "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"
`)
}

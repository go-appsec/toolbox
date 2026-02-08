package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/go-appsec/llm-security-toolbox/sectool/cliutil"
	"github.com/go-appsec/llm-security-toolbox/sectool/config"
	"github.com/go-appsec/llm-security-toolbox/sectool/crawl"
	"github.com/go-appsec/llm-security-toolbox/sectool/encode"
	"github.com/go-appsec/llm-security-toolbox/sectool/oast"
	"github.com/go-appsec/llm-security-toolbox/sectool/proxy"
	"github.com/go-appsec/llm-security-toolbox/sectool/replay"
	"github.com/go-appsec/llm-security-toolbox/sectool/service"
)

func main() {
	globalFlags, args := parseGlobalFlags(os.Args[1:])

	if len(args) < 1 {
		printRootUsage()
		os.Exit(1)
	}

	var err error
	switch args[0] {
	// Commands that don't need MCP client
	case "mcp":
		os.Exit(runServiceMode(args[1:]))
	case "encode":
		err = encode.Parse(args[1:])
	case "version", "--version", "-v":
		_, _ = fmt.Printf("sectool version %s\n", config.Version)
		return
	case "help", "--help", "-h":
		printRootUsage()
		return

	// Commands that need MCP client
	case "proxy", "replay", "oast", "crawl":
		var mcpURL string
		mcpURL, err = getMCPURL(globalFlags)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		switch args[0] {
		case "proxy":
			err = proxy.Parse(args[1:], mcpURL)
		case "replay":
			err = replay.Parse(args[1:], mcpURL)
		case "oast":
			err = oast.Parse(args[1:], mcpURL)
		case "crawl":
			err = crawl.Parse(args[1:], mcpURL)
		}

	default:
		validCommands := []string{"mcp", "proxy", "replay", "oast", "crawl", "encode", "version", "help"}
		err = cliutil.UnknownCommandError(args[0], validCommands)
	}

	if err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return
		}
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runServiceMode(args []string) int {
	flags, err := service.ParseMCPServerFlags(args)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error parsing service flags: %v\n", err)
		return 1
	}

	if srv, err := service.NewServer(flags, nil, nil, nil); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error creating service: %v\n", err)
		return 1
	} else if err := srv.Run(context.Background()); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Service error: %v\n", err)
		return 1
	}
	return 0
}

func printRootUsage() {
	_, _ = fmt.Fprint(os.Stderr, `Usage: sectool <command> [options]

Commands:
  mcp        Start MCP server (required before other commands work)
  proxy      Query and manage proxy history
  replay     Replay HTTP requests (with modifications)
  oast       Manage OAST domains for out-of-band testing
  crawl      Web crawler for URL and form discovery
  encode     Encoding/decoding utilities (url, base64, html)

Global Options:
  --config <path>    Config file path (default: ~/.sectool/config.json)
  --mcp-url <url>    MCP server URL (default: http://127.0.0.1:<port from config>/mcp)

Use "sectool <command> --help" for specific command usage.
`)
}

// globalFlags holds CLI global flags parsed before command dispatch.
type globalFlags struct {
	ConfigPath string
	MCPURL     string
}

// parseGlobalFlags extracts global flags from args, returning remaining args.
func parseGlobalFlags(args []string) (globalFlags, []string) {
	var flags globalFlags
	remaining := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]

		// --config <path> or --config=<path>
		if arg == "--config" && i+1 < len(args) {
			flags.ConfigPath = args[i+1]
			i++
			continue
		} else if strings.HasPrefix(arg, "--config=") {
			flags.ConfigPath = strings.TrimPrefix(arg, "--config=")
			continue
		}

		// --mcp-url <url> or --mcp-url=<url>
		if arg == "--mcp-url" && i+1 < len(args) {
			flags.MCPURL = args[i+1]
			i++
			continue
		} else if strings.HasPrefix(arg, "--mcp-url=") {
			flags.MCPURL = strings.TrimPrefix(arg, "--mcp-url=")
			continue
		}

		remaining = append(remaining, arg)
	}

	return flags, remaining
}

// getMCPURL returns the MCP server URL from flags or config.
func getMCPURL(flags globalFlags) (string, error) {
	if flags.MCPURL != "" {
		return flags.MCPURL, nil
	}

	configPath := flags.ConfigPath
	if configPath == "" {
		configPath = config.DefaultPath()
	}

	cfg, err := config.LoadOrDefaultConfig(configPath)
	if err != nil {
		return "", fmt.Errorf("load config: %w", err)
	}

	if cfg.MCPPort != 0 && cfg.MCPPort != config.DefaultMCPPort {
		return fmt.Sprintf("http://127.0.0.1:%d/mcp", cfg.MCPPort), nil
	}

	return "", nil // empty string means use default
}

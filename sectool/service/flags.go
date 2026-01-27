package service

import (
	"fmt"

	"github.com/spf13/pflag"

	"github.com/go-harden/llm-security-toolbox/sectool/config"
	"github.com/go-harden/llm-security-toolbox/sectool/protocol"
)

const DefaultMCPPort = 9119

// Workflow mode constants
const (
	WorkflowModeNone       = protocol.WorkflowModeNone
	WorkflowModeExplore    = protocol.WorkflowModeExplore
	WorkflowModeTestReport = protocol.WorkflowModeTestReport
	WorkflowModeCLI        = protocol.WorkflowModeCLI // undocumented, for CLI client use only
)

// MCPServerFlags holds flags for MCP server mode.
type MCPServerFlags struct {
	ConfigPath   string
	BurpMCPURL   string
	MCPPort      int
	ProxyPort    int    // 0 = not set via CLI
	RequireBurp  bool   // --burp flag: require Burp, error if unavailable
	WorkflowMode string // "", "none", "explore", "test-report"
}

// ParseMCPServerFlags parses flags for MCP server mode (sectool mcp).
func ParseMCPServerFlags(args []string) (MCPServerFlags, error) {
	fs := pflag.NewFlagSet("mcp", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	flags := MCPServerFlags{
		BurpMCPURL: config.DefaultBurpMCPURL,
	}

	fs.StringVar(&flags.ConfigPath, "config", "", "config file path (default: ~/.sectool/config.json)")
	fs.StringVar(&flags.BurpMCPURL, "burp-mcp-url", flags.BurpMCPURL, "Burp MCP SSE endpoint URL")
	fs.IntVar(&flags.MCPPort, "port", 0, "MCP server port (default: from config or 9119)")
	fs.IntVar(&flags.ProxyPort, "proxy-port", 0, "built-in proxy port (skips Burp, default: from config or 8080)")
	fs.BoolVar(&flags.RequireBurp, "burp", false, "require Burp MCP (error if unavailable)")
	fs.StringVar(&flags.WorkflowMode, "workflow", "", "MCP workflow mode: none, explore, test-report")

	if err := fs.Parse(args); err != nil {
		return flags, err
	}

	// Validate workflow mode value
	switch flags.WorkflowMode {
	case "", WorkflowModeNone, WorkflowModeExplore, WorkflowModeTestReport:
		// Valid
	default:
		return flags, fmt.Errorf("invalid --workflow value %q: must be none, explore, or test-report", flags.WorkflowMode)
	}

	return flags, nil
}

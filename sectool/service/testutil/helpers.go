package testutil

import (
	"context"
	"os"
	"testing"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/llm-security-toolbox/sectool/config"
)

// ConnectBurpSSEOrSkip connects to Burp MCP using SSE client and skips if unavailable.
// Used for MCP server tests that need the mcp-go client.
func ConnectBurpSSEOrSkip(t *testing.T) *mcpclient.Client {
	t.Helper()

	AcquireBurpLock(t)

	burpClient, err := mcpclient.NewSSEMCPClient(config.DefaultBurpMCPURL)
	if err != nil {
		t.Skipf("Burp MCP not available at %s: %v", config.DefaultBurpMCPURL, err)
	}

	if err := burpClient.Start(context.Background()); err != nil {
		_ = burpClient.Close()
		t.Skipf("Burp MCP not available at %s: %v", config.DefaultBurpMCPURL, err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, err = burpClient.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ClientInfo: mcp.Implementation{
				Name:    "sectool-test",
				Version: "1.0.0",
			},
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
		},
	})
	if err != nil {
		_ = burpClient.Close()
		t.Skipf("Burp MCP not available at %s: %v", config.DefaultBurpMCPURL, err)
	}

	t.Cleanup(func() { _ = burpClient.Close() })
	return burpClient
}

// GetBurpProxyAddr returns the Burp proxy listener address for seeding traffic.
// Uses SECTOOL_BURP_PROXY env var if set, otherwise default 127.0.0.1:8080.
func GetBurpProxyAddr() string {
	if addr := os.Getenv("SECTOOL_BURP_PROXY"); addr != "" {
		return addr
	}
	return config.DefaultBurpProxyAddr
}

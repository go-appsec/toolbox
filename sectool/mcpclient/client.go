// Package mcpclient provides an MCP client wrapper for CLI commands.
package mcpclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/llm-security-toolbox/sectool/config"
	"github.com/go-appsec/llm-security-toolbox/sectool/protocol"
)

const (
	DefaultMCPURL = "http://127.0.0.1:9119/mcp"
	ClientTimeout = 25 * time.Minute // exceeds 20m long-poll max
)

// Connect returns a connected MCP client. Uses DefaultMCPURL if url is empty.
func Connect(ctx context.Context, url string) (*Client, error) {
	if url == "" {
		url = DefaultMCPURL
	}
	return New(ctx, url)
}

// Client wraps the MCP client for CLI usage.
type Client struct {
	mcpClient *client.Client
	mcpURL    string
}

// New creates a new MCP client and connects to the server.
// It automatically calls the workflow tool with "cli" task if available.
func New(ctx context.Context, mcpURL string) (*Client, error) {
	if mcpURL == "" {
		mcpURL = DefaultMCPURL
	}

	httpClient := &http.Client{
		Timeout: ClientTimeout,
	}

	mcpClient, err := client.NewStreamableHttpClient(mcpURL,
		transport.WithHTTPBasicClient(httpClient),
	)
	if err != nil {
		return nil, formatConnectionError(mcpURL, err)
	}

	c := &Client{
		mcpClient: mcpClient,
		mcpURL:    mcpURL,
	}

	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{
		Name:    "sectool-cli",
		Version: config.Version,
	}
	initReq.Params.Capabilities = mcp.ClientCapabilities{}

	if _, err := mcpClient.Initialize(ctx, initReq); err != nil {
		_ = mcpClient.Close()
		return nil, formatConnectionError(mcpURL, err)
	}

	tools, err := mcpClient.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		_ = mcpClient.Close()
		return nil, formatConnectionError(mcpURL, err)
	}

	for _, tool := range tools.Tools {
		if tool.Name == "workflow" {
			_, err = mcpClient.CallTool(ctx, mcp.CallToolRequest{
				Params: mcp.CallToolParams{
					Name: "workflow",
					Arguments: map[string]interface{}{
						"task": protocol.WorkflowModeCLI,
					},
				},
			})
			if err != nil {
				_ = mcpClient.Close()
				return nil, fmt.Errorf("failed to initialize CLI workflow: %w", err)
			}
			break
		}
	}

	return c, nil
}

// Close closes the MCP client connection.
func (c *Client) Close() error {
	if c.mcpClient != nil {
		return c.mcpClient.Close()
	}
	return nil
}

// CallTool calls an MCP tool and returns the raw result.
func (c *Client) CallTool(ctx context.Context, name string, args map[string]interface{}) (*mcp.CallToolResult, error) {
	result, err := c.mcpClient.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		},
	})
	if err != nil {
		return nil, translateTimeoutError(err)
	} else if result.IsError {
		return nil, errors.New(extractTextContent(result.Content))
	}
	return result, nil
}

// CallToolJSON calls an MCP tool and unmarshals the JSON result into dest.
func (c *Client) CallToolJSON(ctx context.Context, name string, args map[string]interface{}, dest interface{}) error {
	result, err := c.CallTool(ctx, name, args)
	if err != nil {
		return fmt.Errorf("call tool %s: %w", name, err)
	}
	text := extractTextContent(result.Content)
	if err := json.Unmarshal([]byte(text), dest); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	return nil
}

// CallToolText calls an MCP tool and returns the text result.
func (c *Client) CallToolText(ctx context.Context, name string, args map[string]interface{}) (string, error) {
	result, err := c.CallTool(ctx, name, args)
	if err != nil {
		return "", err
	}
	return extractTextContent(result.Content), nil
}

// extractTextContent extracts text from MCP content items.
func extractTextContent(content []mcp.Content) string {
	var parts []string
	for _, c := range content {
		if tc, ok := c.(mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// isContextStopError returns a user-friendly message for context errors, or empty string.
func isContextStopError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	return ""
}

// formatConnectionError formats connection errors with actionable messages.
func formatConnectionError(mcpURL string, err error) error {
	if msg := isContextStopError(err); msg != "" {
		return fmt.Errorf("connection to MCP server at %s %s", mcpURL, msg)
	}

	errStr := err.Error()

	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "no such host") || strings.Contains(errStr, "dial tcp") {
		return fmt.Errorf("cannot connect to MCP server at %s\nStart the server with: sectool mcp", mcpURL)
	}

	return fmt.Errorf("MCP connection failed: %w", err)
}

// translateTimeoutError translates MCP errors to user-friendly messages.
func translateTimeoutError(err error) error {
	if err == nil {
		return nil
	}

	if msg := isContextStopError(err); msg != "" {
		return fmt.Errorf("request %s", msg)
	}

	errStr := err.Error()

	// Connection errors
	if strings.Contains(errStr, "connection refused") {
		return errors.New("MCP server not running. Start with: sectool mcp")
	}

	// Backend errors
	if strings.Contains(errStr, "Backend error") || strings.Contains(errStr, "backend error") {
		if strings.Contains(errStr, "Burp") || strings.Contains(errStr, "burp") {
			return errors.New("burp connection failed: ensure Burp Suite is running with MCP extension enabled")
		}
		return fmt.Errorf("backend error: %s", errStr)
	}

	// Not found errors
	if strings.Contains(errStr, "not found") {
		return err // Pass through as-is
	}

	return err
}

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func CallMCPTool(t *testing.T, client *mcpclient.Client, name string, args map[string]interface{}) *mcp.CallToolResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	result, err := client.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		},
	})
	require.NoError(t, err)
	return result
}

func ExtractMCPText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()

	assert.NotEmpty(t, result.Content, "result should have content")
	for _, c := range result.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			return tc.Text
		}
	}
	assert.Fail(t, "text content not found in result")
	return ""
}

func CallMCPToolTextOK(t *testing.T, client *mcpclient.Client, name string, args map[string]interface{}) string {
	t.Helper()

	result := CallMCPTool(t, client, name, args)
	require.False(t, result.IsError,
		"%s failed: %s", name, ExtractMCPText(t, result))
	return ExtractMCPText(t, result)
}

func CallMCPToolJSONOK[T any](t *testing.T, client *mcpclient.Client, name string, args map[string]interface{}) T {
	t.Helper()

	text := CallMCPToolTextOK(t, client, name, args)
	var v T
	require.NoError(t, json.Unmarshal([]byte(text), &v))
	return v
}

type TestMCPServer struct {
	HTTPServer *httptest.Server
	MCPServer  *mcpserver.MCPServer

	mu               sync.Mutex
	proxyHistory     []testProxyEntry
	sendResponses    []string // Stack of responses for send_http1_request and send_http2_request
	lastSentRequest  string   // Last raw request sent via send_http1_request
	matchReplaceHTTP []testMatchReplaceRule
	matchReplaceWS   []testMatchReplaceRule
	toolCallLog      []string // Ordered log of tool names called
}

type testMatchReplaceRule struct {
	Category      string `json:"category"`
	Comment       string `json:"comment"`
	Enabled       bool   `json:"enabled"`
	RuleType      string `json:"rule_type,omitempty"`
	Direction     string `json:"direction,omitempty"`
	StringMatch   string `json:"string_match,omitempty"`
	StringReplace string `json:"string_replace,omitempty"`
}

type testProxyEntry struct {
	Request  string `json:"request"`
	Response string `json:"response"`
	Notes    string `json:"notes"`
}

// NewTestMCPServer creates a mock MCP server for testing.
func NewTestMCPServer(t *testing.T) *TestMCPServer {
	t.Helper()

	ts := &TestMCPServer{}

	mcpServer := mcpserver.NewMCPServer("test-burp-mcp", "1.0.0",
		mcpserver.WithToolCapabilities(false),
	)

	mcpServer.AddTool(
		mcp.NewTool("get_proxy_http_history",
			mcp.WithDescription("Get proxy HTTP history"),
			mcp.WithNumber("count", mcp.Description("Number of entries to return")),
			mcp.WithNumber("offset", mcp.Description("Offset to start from")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ts.mu.Lock()
			defer ts.mu.Unlock()

			args := req.Params.Arguments.(map[string]any)
			count := int(args["count"].(float64))
			offset := int(args["offset"].(float64))

			if offset >= len(ts.proxyHistory) {
				return mcp.NewToolResultText("Reached end of items"), nil
			}

			end := offset + count
			if end > len(ts.proxyHistory) {
				end = len(ts.proxyHistory)
			}

			// Return NDJSON format like real Burp
			var sb strings.Builder
			for _, entry := range ts.proxyHistory[offset:end] {
				line, _ := json.Marshal(entry)
				sb.Write(line)
				sb.WriteByte('\n')
			}
			return mcp.NewToolResultText(sb.String()), nil
		},
	)

	mcpServer.AddTool(
		mcp.NewTool("get_proxy_http_history_regex",
			mcp.WithDescription("Get filtered proxy HTTP history"),
			mcp.WithString("regex", mcp.Description("Regex filter")),
			mcp.WithNumber("count", mcp.Description("Number of entries to return")),
			mcp.WithNumber("offset", mcp.Description("Offset to start from")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			// For simplicity, just delegate to the non-regex version
			// Real filtering would apply the regex
			ts.mu.Lock()
			defer ts.mu.Unlock()

			args := req.Params.Arguments.(map[string]any)
			count := int(args["count"].(float64))
			offset := int(args["offset"].(float64))

			if offset >= len(ts.proxyHistory) {
				return mcp.NewToolResultText("Reached end of items"), nil
			}

			end := offset + count
			if end > len(ts.proxyHistory) {
				end = len(ts.proxyHistory)
			}

			var sb strings.Builder
			for _, entry := range ts.proxyHistory[offset:end] {
				line, _ := json.Marshal(entry)
				sb.Write(line)
				sb.WriteByte('\n')
			}
			return mcp.NewToolResultText(sb.String()), nil
		},
	)

	mcpServer.AddTool(
		mcp.NewTool("send_http1_request",
			mcp.WithDescription("Send HTTP/1.1 request"),
			mcp.WithString("content", mcp.Description("Raw HTTP request")),
			mcp.WithString("targetHostname", mcp.Description("Target hostname")),
			mcp.WithNumber("targetPort", mcp.Description("Target port")),
			mcp.WithBoolean("usesHttps", mcp.Description("Use HTTPS")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ts.mu.Lock()
			defer ts.mu.Unlock()
			ts.toolCallLog = append(ts.toolCallLog, "send_http1_request")

			// Capture the sent request content
			ts.lastSentRequest = req.GetString("content", "")

			// Pop from sendResponses stack if available
			if len(ts.sendResponses) > 0 {
				resp := ts.sendResponses[0]
				ts.sendResponses = ts.sendResponses[1:]
				return mcp.NewToolResultText(resp), nil
			}

			// Default response in Burp's toString format
			return mcp.NewToolResultText(
				`HttpRequestResponse{httpRequest=GET / HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>OK</html>, messageAnnotations=Annotations{}}`,
			), nil
		},
	)

	mcpServer.AddTool(
		mcp.NewTool("send_http2_request",
			mcp.WithDescription("Send HTTP/2 request"),
			mcp.WithObject("pseudoHeaders", mcp.Description("HTTP/2 pseudo-headers")),
			mcp.WithObject("headers", mcp.Description("HTTP/2 headers")),
			mcp.WithString("requestBody", mcp.Description("Request body")),
			mcp.WithString("targetHostname", mcp.Description("Target hostname")),
			mcp.WithNumber("targetPort", mcp.Description("Target port")),
			mcp.WithBoolean("usesHttps", mcp.Description("Use HTTPS")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ts.mu.Lock()
			defer ts.mu.Unlock()
			ts.toolCallLog = append(ts.toolCallLog, "send_http2_request")

			// Pop from sendResponses stack if available
			if len(ts.sendResponses) > 0 {
				resp := ts.sendResponses[0]
				ts.sendResponses = ts.sendResponses[1:]
				return mcp.NewToolResultText(resp), nil
			}

			return mcp.NewToolResultText(
				`HttpRequestResponse{httpRequest=GET / HTTP/2, httpResponse=HTTP/2 200 OK\r\nContent-Type: text/html\r\n\r\n<html>OK</html>, messageAnnotations=Annotations{}}`,
			), nil
		},
	)

	mcpServer.AddTool(
		mcp.NewTool("create_repeater_tab",
			mcp.WithDescription("Create Repeater tab"),
			mcp.WithString("content", mcp.Description("Raw HTTP request")),
			mcp.WithString("targetHostname", mcp.Description("Target hostname")),
			mcp.WithNumber("targetPort", mcp.Description("Target port")),
			mcp.WithBoolean("usesHttps", mcp.Description("Use HTTPS")),
			mcp.WithString("tabName", mcp.Description("Tab name")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ts.mu.Lock()
			defer ts.mu.Unlock()
			ts.toolCallLog = append(ts.toolCallLog, "create_repeater_tab")
			return mcp.NewToolResultText("Tab created"), nil
		},
	)

	mcpServer.AddTool(
		mcp.NewTool("set_proxy_intercept_state",
			mcp.WithDescription("Set proxy intercept state"),
			mcp.WithBoolean("intercepting", mcp.Description("Intercept state")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("Intercept state set"), nil
		},
	)

	mcpServer.AddTool(
		mcp.NewTool("output_project_options",
			mcp.WithDescription("Output project options"),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ts.mu.Lock()
			defer ts.mu.Unlock()

			opts := map[string]interface{}{
				"proxy": map[string]interface{}{
					"match_replace_rules":    ts.matchReplaceHTTP,
					"ws_match_replace_rules": ts.matchReplaceWS,
				},
			}
			data, _ := json.Marshal(opts)
			return mcp.NewToolResultText(string(data)), nil
		},
	)

	mcpServer.AddTool(
		mcp.NewTool("set_project_options",
			mcp.WithDescription("Set project options"),
			mcp.WithString("json", mcp.Description("JSON config")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ts.mu.Lock()
			defer ts.mu.Unlock()

			args := req.Params.Arguments.(map[string]any)
			jsonStr := args["json"].(string)

			var opts struct {
				Proxy struct {
					MatchReplaceRules   []testMatchReplaceRule `json:"match_replace_rules"`
					WSMatchReplaceRules []testMatchReplaceRule `json:"ws_match_replace_rules"`
				} `json:"proxy"`
			}
			if err := json.Unmarshal([]byte(jsonStr), &opts); err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("invalid JSON: %v", err)), nil
			}

			if opts.Proxy.MatchReplaceRules != nil {
				ts.matchReplaceHTTP = opts.Proxy.MatchReplaceRules
			}
			if opts.Proxy.WSMatchReplaceRules != nil {
				ts.matchReplaceWS = opts.Proxy.WSMatchReplaceRules
			}
			return mcp.NewToolResultText("Project configuration has been applied"), nil
		},
	)

	httpServer := mcpserver.NewTestServer(mcpServer)

	ts.HTTPServer = httpServer
	ts.MCPServer = mcpServer
	t.Cleanup(httpServer.Close)
	return ts
}

// URL returns the SSE endpoint URL for the test server.
func (t *TestMCPServer) URL() string {
	return t.HTTPServer.URL + "/sse"
}

// AddProxyEntry adds an entry to the mock proxy history.
func (t *TestMCPServer) AddProxyEntry(request, response, notes string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.proxyHistory = append(t.proxyHistory, testProxyEntry{
		Request:  request,
		Response: response,
		Notes:    notes,
	})
}

// AddProxyEntries adds multiple entries to the mock proxy history.
func (t *TestMCPServer) AddProxyEntries(entries ...testProxyEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.proxyHistory = append(t.proxyHistory, entries...)
}

// SetSendResponse sets the response for the next send_http1_request call.
func (t *TestMCPServer) SetSendResponse(response string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sendResponses = append(t.sendResponses, response)
}

// LastSentRequest returns the last raw request sent via send_http1_request.
func (t *TestMCPServer) LastSentRequest() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastSentRequest
}

// ClearProxyHistory clears all proxy history entries.
func (t *TestMCPServer) ClearProxyHistory() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.proxyHistory = nil
}

// ToolCallLog returns a copy of the ordered tool call log.
func (t *TestMCPServer) ToolCallLog() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.toolCallLog...)
}

// ClearToolCallLog resets the tool call log.
func (t *TestMCPServer) ClearToolCallLog() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.toolCallLog = nil
}

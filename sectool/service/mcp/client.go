package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/jentfoo/llm-security-toolbox/sectool/config"
)

const (
	// ClientName identifies sectool to the MCP server.
	ClientName = "sectool"

	// ProtocolVersion is the MCP protocol version we support.
	ProtocolVersion = "2024-11-05"

	// DefaultDialTimeout is the timeout for establishing a connection.
	DefaultDialTimeout = 30 * time.Second

	// endOfItemsMarker is returned by Burp MCP when pagination reaches the end.
	endOfItemsMarker = "Reached end of items"
)

// ErrNotConnected is returned when an operation is attempted without a connection.
var ErrNotConnected = errors.New("not connected to Burp MCP")

// BurpClient wraps the mcp-go SSE client to provide Burp-specific functionality.
type BurpClient struct {
	mcpClient  *client.Client
	url        string
	httpClient *http.Client
	connected  atomic.Bool
}

// Option configures the BurpClient.
type Option func(*BurpClient)

// WithHTTPClient sets a custom HTTP client for the connection.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *BurpClient) {
		c.httpClient = httpClient
	}
}

// New creates a new BurpClient but does not connect.
// Call Connect to establish the connection.
func New(url string, opts ...Option) *BurpClient {
	if url == "" {
		url = config.DefaultBurpMCPURL
	}
	c := &BurpClient{
		url: url,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Connect establishes the SSE connection and performs the MCP handshake.
func (c *BurpClient) Connect(ctx context.Context) error {
	if c.connected.Load() {
		return nil
	}

	// Close any stale client before reconnecting
	if c.mcpClient != nil {
		log.Printf("mcp: closing stale connection before reconnect")
		_ = c.mcpClient.Close()
		c.mcpClient = nil
	}

	log.Printf("mcp: connecting to %s", c.url)

	// Use provided HTTP client or create one suitable for SSE
	httpClient := c.httpClient
	if httpClient == nil {
		httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   DefaultDialTimeout,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: DefaultDialTimeout,
				IdleConnTimeout:       90 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return errors.New("redirect not allowed")
			},
		}
	}

	mcpClient, err := client.NewSSEMCPClient(c.url, transport.WithHTTPClient(httpClient))
	if err != nil {
		return fmt.Errorf("failed to create MCP client: %w", err)
	}

	// Use context.Background() for SSE stream - it needs to be long-lived
	// The passed ctx is only used for the initial connect timeout via httpClient
	if err := mcpClient.Start(context.Background()); err != nil {
		return fmt.Errorf("failed to connect to Burp MCP at %s: %w", c.url, err)
	}

	// Initialize MCP session
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = ProtocolVersion
	initReq.Params.ClientInfo = mcp.Implementation{
		Name:    ClientName,
		Version: config.Version,
	}
	initReq.Params.Capabilities = mcp.ClientCapabilities{}

	if _, err := mcpClient.Initialize(ctx, initReq); err != nil {
		_ = mcpClient.Close()
		return fmt.Errorf("MCP initialization failed: %w", err)
	}

	c.mcpClient = mcpClient
	c.connected.Store(true)
	log.Printf("mcp: session initialized successfully")
	return nil
}

// OnConnectionLost sets a handler to be called when the connection is lost.
func (c *BurpClient) OnConnectionLost(handler func(error)) {
	if c.mcpClient != nil {
		c.mcpClient.OnConnectionLost(func(err error) {
			c.connected.Store(false)
			if handler != nil {
				handler(err)
			}
		})
	}
}

func (c *BurpClient) URL() string {
	return c.url
}

func (c *BurpClient) Close() error {
	if c.mcpClient != nil {
		log.Printf("mcp: closing connection")
		err := c.mcpClient.Close()
		c.mcpClient = nil
		c.connected.Store(false)
		return err
	}
	return nil
}

func (c *BurpClient) IsConnected() bool {
	return c.connected.Load()
}

// GetProxyHistory retrieves proxy HTTP history entries.
// Returns up to count entries starting from offset.
func (c *BurpClient) GetProxyHistory(ctx context.Context, count, offset int) ([]ProxyHistoryEntry, error) {
	raw, err := c.GetProxyHistoryRaw(ctx, count, offset)
	if err != nil {
		return nil, err
	}
	return parseHistoryNDJSON(raw)
}

// GetProxyHistoryRaw retrieves proxy HTTP history as raw text (for debugging).
func (c *BurpClient) GetProxyHistoryRaw(ctx context.Context, count, offset int) (string, error) {
	if !c.connected.Load() {
		return "", ErrNotConnected
	}

	result, err := c.mcpClient.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "get_proxy_http_history",
			Arguments: map[string]interface{}{
				"count":  count,
				"offset": offset,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("get_proxy_http_history failed: %w", err)
	}

	if result.IsError {
		return "", fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
	}

	return extractTextContent(result.Content), nil
}

// GetProxyHistoryRegex retrieves filtered proxy HTTP history entries.
// The regex uses Java regex syntax and matches against full request+response.
func (c *BurpClient) GetProxyHistoryRegex(ctx context.Context, regex string, count, offset int) ([]ProxyHistoryEntry, error) {
	if !c.connected.Load() {
		return nil, ErrNotConnected
	}

	result, err := c.mcpClient.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "get_proxy_http_history_regex",
			Arguments: map[string]interface{}{
				"regex":  regex,
				"count":  count,
				"offset": offset,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("get_proxy_http_history_regex failed: %w", err)
	}

	if result.IsError {
		return nil, fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
	}

	return parseHistoryNDJSON(extractTextContent(result.Content))
}

// parseHistoryNDJSON parses NDJSON text from proxy history tools.
func parseHistoryNDJSON(text string) ([]ProxyHistoryEntry, error) {
	if text == "" || strings.TrimSpace(text) == endOfItemsMarker {
		return nil, nil
	}

	var entries []ProxyHistoryEntry
	scanner := bufio.NewScanner(strings.NewReader(text))
	// Large buffer for responses that can contain full request/response bodies (up to 10MB)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	var lineNum int
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line == endOfItemsMarker {
			continue
		} else if !strings.HasPrefix(line, "{") {
			continue
		}

		// Sanitize the JSON to handle Burp MCP bugs (truncation, invalid escapes)
		sanitized := sanitizeBurpJSON(line)

		var entry ProxyHistoryEntry
		if err := json.Unmarshal([]byte(sanitized), &entry); err != nil {
			return entries, fmt.Errorf("failed to parse history entry at line %d: %w", lineNum, err)
		}
		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan history response: %w", err)
	}

	return entries, nil
}

// sanitizeBurpJSON fixes known Burp MCP bugs in JSON output:
// 1. Invalid escape sequences from binary/path data (e.g., \. or \u00XX with non-hex)
// 2. Truncated JSON that doesn't close properly
func sanitizeBurpJSON(line string) string {
	// First fix invalid escape sequences
	line = fixInvalidEscapes(line)

	// Then repair truncation if needed
	line = repairTruncatedJSON(line)

	return line
}

// fixInvalidEscapes fixes malformed escape sequences in JSON strings.
// Burp MCP can embed raw binary or path-like data that creates invalid escapes.
// Valid JSON escapes: \", \\, \/, \b, \f, \n, \r, \t, \uXXXX
func fixInvalidEscapes(s string) string {
	// Fast path: no backslashes to process
	if !strings.Contains(s, "\\") {
		return s
	}

	var result strings.Builder
	result.Grow(len(s))

	var i int
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			next := s[i+1]
			switch next {
			case '\\', '"', '/', 'b', 'f', 'n', 'r', 't':
				// Valid simple escape - copy as-is
				result.WriteByte(s[i])
				result.WriteByte(next)
				i += 2
			case 'u':
				// Unicode escape - validate hex digits
				if i+5 < len(s) && isValidHexEscape(s[i+2:i+6]) {
					// Valid unicode escape, copy as-is
					result.WriteString(s[i : i+6])
					i += 6
				} else {
					// Invalid unicode escape - escape the backslash
					result.WriteString("\\\\u")
					i += 2
				}
			default:
				// Invalid escape sequence - escape the backslash to make it literal
				result.WriteString("\\\\")
				result.WriteByte(next)
				i += 2
			}
			continue
		}
		result.WriteByte(s[i])
		i++
	}

	return result.String()
}

func isValidHexEscape(s string) bool {
	if len(s) != 4 {
		return false
	}
	for _, c := range s {
		isDigit := c >= '0' && c <= '9'
		isLowerHex := c >= 'a' && c <= 'f'
		isUpperHex := c >= 'A' && c <= 'F'
		if !isDigit && !isLowerHex && !isUpperHex {
			return false
		}
	}
	return true
}

// repairTruncatedJSON closes JSON that was truncated mid-stream by Burp MCP.
// Expected format: {"request":"...","response":"...","notes":"..."}
func repairTruncatedJSON(s string) string {
	// Check if JSON is properly closed
	if strings.HasSuffix(s, "}") {
		return s
	}

	// JSON is truncated - find where we are and close it
	// The structure is always: {"request":"...","response":"...","notes":"..."}

	// Check if we're inside a string value (odd number of unescaped quotes after last field marker)
	// Simple heuristic: if it doesn't end with "} or ,"} or similar, we're mid-value

	// Find the last field we were in
	lastRequest := strings.LastIndex(s, `"request":"`)
	lastResponse := strings.LastIndex(s, `"response":"`)
	lastNotes := strings.LastIndex(s, `"notes":"`)

	var result strings.Builder
	result.WriteString(s)

	// Determine which field we're in based on last marker position
	if lastNotes > lastResponse && lastNotes > lastRequest {
		// We're in notes field - close it
		result.WriteString(`"}`)
	} else if lastResponse > lastRequest {
		// We're in response field - close it and add empty notes
		result.WriteString(`","notes":""}`)
	} else if lastRequest >= 0 {
		// We're in request field - close it and add empty response/notes
		result.WriteString(`","response":"","notes":""}`)
	} else {
		// Malformed from the start, just try to close
		result.WriteString(`"}`)
	}

	return result.String()
}

// SendHTTP1Request sends an HTTP/1.1 request through Burp and returns the response.
// Note: This bypasses the proxy (direct from Burp) and does NOT appear in proxy history.
func (c *BurpClient) SendHTTP1Request(ctx context.Context, params SendRequestParams) (string, error) {
	if !c.connected.Load() {
		return "", ErrNotConnected
	}

	result, err := c.mcpClient.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "send_http1_request",
			Arguments: map[string]interface{}{
				"content":        params.Content,
				"targetHostname": params.TargetHostname,
				"targetPort":     params.TargetPort,
				"usesHttps":      params.UsesHTTPS,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("send_http1_request failed: %w", err)
	}

	if result.IsError {
		return "", fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
	}

	// Response is a Kotlin toString() format, not JSON
	return extractTextContent(result.Content), nil
}

// CreateRepeaterTab creates a new Repeater tab in Burp with the specified request.
func (c *BurpClient) CreateRepeaterTab(ctx context.Context, params RepeaterTabParams) error {
	if !c.connected.Load() {
		return ErrNotConnected
	}

	args := map[string]interface{}{
		"content":        params.Content,
		"targetHostname": params.TargetHostname,
		"targetPort":     params.TargetPort,
		"usesHttps":      params.UsesHTTPS,
	}
	if params.TabName != "" {
		args["tabName"] = params.TabName
	}

	result, err := c.mcpClient.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "create_repeater_tab",
			Arguments: args,
		},
	})
	if err != nil {
		return fmt.Errorf("create_repeater_tab failed: %w", err)
	}

	if result.IsError {
		return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
	}

	return nil
}

// SetInterceptState enables or disables proxy intercept mode.
func (c *BurpClient) SetInterceptState(ctx context.Context, intercepting bool) error {
	if !c.connected.Load() {
		return ErrNotConnected
	}

	result, err := c.mcpClient.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "set_proxy_intercept_state",
			Arguments: map[string]interface{}{
				"intercepting": intercepting,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("set_proxy_intercept_state failed: %w", err)
	}

	if result.IsError {
		return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
	}

	return nil
}

// SendHTTP2Request sends an HTTP/2 request through Burp and returns the response.
// Note: This bypasses the proxy (direct from Burp) and does NOT appear in proxy history.
func (c *BurpClient) SendHTTP2Request(ctx context.Context, params SendHTTP2RequestParams) (string, error) {
	if !c.connected.Load() {
		return "", ErrNotConnected
	}

	args := map[string]interface{}{
		"targetHostname": params.TargetHostname,
		"targetPort":     params.TargetPort,
		"usesHttps":      params.UsesHTTPS,
		"requestBody":    params.RequestBody, // Required field, even if empty
	}
	if params.PseudoHeaders != nil {
		args["pseudoHeaders"] = params.PseudoHeaders
	}
	if params.Headers != nil {
		args["headers"] = params.Headers
	}

	result, err := c.mcpClient.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "send_http2_request",
			Arguments: args,
		},
	})
	if err != nil {
		return "", fmt.Errorf("send_http2_request failed: %w", err)
	}

	if result.IsError {
		return "", fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
	}

	return extractTextContent(result.Content), nil
}

// SendToIntruder creates a new Intruder tab with the specified HTTP request.
func (c *BurpClient) SendToIntruder(ctx context.Context, params IntruderParams) error {
	if !c.connected.Load() {
		return ErrNotConnected
	}

	args := map[string]interface{}{
		"content":        params.Content,
		"targetHostname": params.TargetHostname,
		"targetPort":     params.TargetPort,
		"usesHttps":      params.UsesHTTPS,
	}
	if params.TabName != "" {
		args["tabName"] = params.TabName
	}

	result, err := c.mcpClient.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "send_to_intruder",
			Arguments: args,
		},
	})
	if err != nil {
		return fmt.Errorf("send_to_intruder failed: %w", err)
	}

	if result.IsError {
		return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
	}

	return nil
}

// GetProxyWebsocketHistory retrieves proxy WebSocket history entries.
func (c *BurpClient) GetProxyWebsocketHistory(ctx context.Context, count, offset int) ([]WebSocketHistoryEntry, error) {
	raw, err := c.GetProxyWebsocketHistoryRaw(ctx, count, offset)
	if err != nil {
		return nil, err
	}
	return parseWebsocketHistoryNDJSON(raw)
}

// GetProxyWebsocketHistoryRaw retrieves proxy WebSocket history as raw text.
func (c *BurpClient) GetProxyWebsocketHistoryRaw(ctx context.Context, count, offset int) (string, error) {
	if !c.connected.Load() {
		return "", ErrNotConnected
	}

	result, err := c.mcpClient.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "get_proxy_websocket_history",
			Arguments: map[string]interface{}{
				"count":  count,
				"offset": offset,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("get_proxy_websocket_history failed: %w", err)
	}

	if result.IsError {
		return "", fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
	}

	return extractTextContent(result.Content), nil
}

// GetProxyWebsocketHistoryRegex retrieves filtered proxy WebSocket history entries.
func (c *BurpClient) GetProxyWebsocketHistoryRegex(ctx context.Context, regex string, count, offset int) ([]WebSocketHistoryEntry, error) {
	if !c.connected.Load() {
		return nil, ErrNotConnected
	}

	result, err := c.mcpClient.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "get_proxy_websocket_history_regex",
			Arguments: map[string]interface{}{
				"regex":  regex,
				"count":  count,
				"offset": offset,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("get_proxy_websocket_history_regex failed: %w", err)
	}

	if result.IsError {
		return nil, fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
	}

	return parseWebsocketHistoryNDJSON(extractTextContent(result.Content))
}

// parseWebsocketHistoryNDJSON parses NDJSON text from WebSocket history.
func parseWebsocketHistoryNDJSON(text string) ([]WebSocketHistoryEntry, error) {
	if text == "" || strings.TrimSpace(text) == endOfItemsMarker {
		return nil, nil
	}

	var entries []WebSocketHistoryEntry
	scanner := bufio.NewScanner(strings.NewReader(text))
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 10*1024*1024)

	var lineNum int
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line == endOfItemsMarker {
			continue
		} else if !strings.HasPrefix(line, "{") {
			continue
		}

		var entry WebSocketHistoryEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return entries, fmt.Errorf("failed to parse websocket entry at line %d: %w", lineNum, err)
		}
		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan websocket history: %w", err)
	}

	return entries, nil
}

// SetTaskExecutionEngineState starts or stops Burp's task execution engine.
// When running=true, tasks will execute; when running=false, tasks are paused.
func (c *BurpClient) SetTaskExecutionEngineState(ctx context.Context, running bool) error {
	if !c.connected.Load() {
		return ErrNotConnected
	}

	result, err := c.mcpClient.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "set_task_execution_engine_state",
			Arguments: map[string]interface{}{
				"running": running,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("set_task_execution_engine_state failed: %w", err)
	}

	if result.IsError {
		return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
	}

	return nil
}

// GetActiveEditorContents retrieves the contents of the user's active message editor.
func (c *BurpClient) GetActiveEditorContents(ctx context.Context) (string, error) {
	if !c.connected.Load() {
		return "", ErrNotConnected
	}

	result, err := c.mcpClient.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "get_active_editor_contents",
			Arguments: map[string]interface{}{},
		},
	})
	if err != nil {
		return "", fmt.Errorf("get_active_editor_contents failed: %w", err)
	}

	if result.IsError {
		return "", fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
	}

	return extractTextContent(result.Content), nil
}

// SetActiveEditorContents sets the contents of the user's active message editor.
func (c *BurpClient) SetActiveEditorContents(ctx context.Context, text string) error {
	if !c.connected.Load() {
		return ErrNotConnected
	}

	result, err := c.mcpClient.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "set_active_editor_contents",
			Arguments: map[string]interface{}{
				"text": text,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("set_active_editor_contents failed: %w", err)
	}

	if result.IsError {
		return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
	}

	return nil
}

func extractTextContent(content []mcp.Content) string {
	for _, item := range content {
		if textContent, ok := item.(mcp.TextContent); ok {
			return textContent.Text
		}
		if textContent, ok := item.(*mcp.TextContent); ok && textContent != nil {
			return textContent.Text
		}
	}
	return ""
}

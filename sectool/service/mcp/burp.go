package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/config"
)

const (
	// ClientName identifies sectool to the MCP server.
	ClientName = "sectool"

	// ProtocolVersion is the MCP protocol version we support.
	ProtocolVersion = "2024-11-05"

	// DefaultDialTimeout is the timeout for establishing a connection.
	DefaultDialTimeout = 10 * time.Second

	// healthCheckInterval is how often we ping the MCP connection
	healthCheckInterval = 4 * time.Second

	// healthCheckTimeout is the timeout for each ping
	healthCheckTimeout = 2 * time.Second

	// endOfItemsMarker is returned by Burp MCP when pagination reaches the end.
	endOfItemsMarker = "Reached end of items"
)

// ErrNotConnected is returned when an operation is attempted without a connection.
var ErrNotConnected = errors.New("not connected to Burp MCP")

// ErrClientClosed is returned when an operation is attempted on a closed client.
var ErrClientClosed = errors.New("client closed")

// BurpClient wraps the mcp-go SSE client to provide Burp-specific functionality.
// Thread-safe for concurrent use. All MCP operations are serialized via mutex.
type BurpClient struct {
	url        string
	httpClient *http.Client

	mu               sync.Mutex
	mcpClient        *client.Client
	onConnectionLost func(error)
	closed           bool
	done             chan struct{} // closed on Close() to signal health loop
}

// Option configures the BurpClient.
type Option func(*BurpClient)

// WithHTTPClient sets a custom HTTP client for the connection.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *BurpClient) {
		c.httpClient = httpClient
	}
}

// New creates a new BurpClient and starts the health monitoring loop.
// Call Connect to establish the connection, or let operations connect lazily.
func New(url string, opts ...Option) *BurpClient {
	if url == "" {
		url = config.DefaultBurpMCPURL
	}
	c := &BurpClient{
		url:  url,
		done: make(chan struct{}),
	}
	for _, opt := range opts {
		opt(c)
	}
	go c.healthLoop()
	return c
}

// Connect establishes the SSE connection and performs the MCP handshake.
// Safe to call multiple times - returns immediately if already connected.
func (c *BurpClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrClientClosed
	}
	if c.mcpClient != nil {
		return nil
	}
	return c.connectLocked(ctx)
}

// connectLocked performs the actual connection. Caller must hold c.mu.
func (c *BurpClient) connectLocked(ctx context.Context) error {
	// Use provided HTTP client or create one suitable for SSE
	httpClient := c.httpClient
	if httpClient == nil {
		httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   DefaultDialTimeout,
					KeepAlive: 20 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: DefaultDialTimeout,
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
	// The passed ctx is only used for the initialization timeout
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

	// Handle connection lost - clear state if still current, always close the dead client
	mcpClient.OnConnectionLost(func(err error) {
		log.Printf("mcp: connection lost: %v", err)

		go func() { // async to avoid deadlock risk with locking
			c.mu.Lock()
			if c.mcpClient == mcpClient {
				c.mcpClient = nil
			}
			c.mu.Unlock()
			_ = mcpClient.Close()
		}()
	})

	c.mcpClient = mcpClient
	return nil
}

// healthLoop periodically pings the MCP connection to detect failures early.
// Runs until Close() is called.
func (c *BurpClient) healthLoop() {
	ticker := time.NewTicker(healthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if notify := c.doHealthCheck(); notify != nil {
				notify()
			}
		}
	}
}

// doHealthCheck performs a single health check, returning a callback to invoke
// outside the lock if notification is needed.
func (c *BurpClient) doHealthCheck() func() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.mcpClient == nil {
		return nil
	}

	pingCtx, cancel := context.WithTimeout(context.Background(), healthCheckTimeout)
	err := c.mcpClient.Ping(pingCtx)
	cancel()

	if err != nil {
		log.Printf("mcp: health check failed: %v", err)
		_ = c.closeLocked()
		if handler := c.onConnectionLost; handler != nil {
			return func() { handler(err) }
		}
	}
	return nil
}

// OnConnectionLost sets a handler to be called when the connection is lost.
// Can be called at any time. The handler is called asynchronously.
func (c *BurpClient) OnConnectionLost(handler func(error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onConnectionLost = handler
}

func (c *BurpClient) URL() string {
	return c.url
}

// Close closes the client and stops the health loop.
// Safe to call multiple times.
func (c *BurpClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true
	close(c.done)
	return c.closeLocked()
}

// closeLocked closes the current connection. Caller must hold c.mu.
func (c *BurpClient) closeLocked() error {
	if c.mcpClient == nil {
		return nil
	}
	err := c.mcpClient.Close()
	c.mcpClient = nil
	return err
}

// IsConnected returns true if connected to the MCP server.
func (c *BurpClient) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mcpClient != nil
}

// withConn executes fn with a valid connection, reconnecting if needed.
// Holds lock for entire operation, serializing all MCP traffic.
// On connection error, reconnects and retries once with fresh context.
func (c *BurpClient) withConn(ctx context.Context, fn func(context.Context) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrClientClosed
	}

	if c.mcpClient == nil { // ensure connected
		if err := c.connectLocked(ctx); err != nil {
			return err
		}
	}

	// First attempt
	err := fn(ctx)
	if err == nil || !isConnectionError(err) {
		return err
	}

	// Connection error - close and reconnect
	log.Printf("mcp: operation failed with connection error, retrying: %v", err)
	_ = c.closeLocked()

	reconnCtx, reconnCancel := context.WithTimeout(ctx, DefaultDialTimeout)
	defer reconnCancel()

	if err := c.connectLocked(reconnCtx); err != nil {
		return fmt.Errorf("reconnection failed: %w", err)
	}

	return fn(ctx)
}

// isConnectionError checks if an error indicates a connection problem that warrants retry.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrNotConnected) {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "connection") ||
		strings.Contains(errStr, "transport") ||
		strings.Contains(errStr, "EOF")
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
	var raw string
	err := c.withConn(ctx, func(opCtx context.Context) error {
		result, err := c.mcpClient.CallTool(opCtx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name: "get_proxy_http_history",
				Arguments: map[string]interface{}{
					"count":  count,
					"offset": offset,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("get_proxy_http_history failed: %w", err)
		} else if result.IsError {
			return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
		}
		raw = extractTextContent(result.Content)
		return nil
	})
	return raw, err
}

// GetProxyHistoryRegex retrieves filtered proxy HTTP history entries.
// The regex uses Java regex syntax and matches against full request+response.
func (c *BurpClient) GetProxyHistoryRegex(ctx context.Context, regex string, count, offset int) ([]ProxyHistoryEntry, error) {
	var entries []ProxyHistoryEntry
	err := c.withConn(ctx, func(opCtx context.Context) error {
		result, err := c.mcpClient.CallTool(opCtx, mcp.CallToolRequest{
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
			return fmt.Errorf("get_proxy_http_history_regex failed: %w", err)
		} else if result.IsError {
			return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
		}
		var parseErr error
		entries, parseErr = parseHistoryNDJSON(extractTextContent(result.Content))
		return parseErr
	})
	return entries, err
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

	var sb bytes.Buffer
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
		sanitized := sanitizeBurpJSON(&sb, []byte(line))

		var entry ProxyHistoryEntry
		if err := json.Unmarshal(sanitized, &entry); err != nil {
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
func sanitizeBurpJSON(bb *bytes.Buffer, line []byte) []byte {
	// First fix invalid escape sequences
	line = fixInvalidEscapes(bb, line)

	// Then repair truncation if needed
	line = repairTruncatedJSON(bb, line)

	return line
}

var jsonEscapeBytes = []byte("\\")

// fixInvalidEscapes fixes malformed escape sequences in JSON strings.
// Burp MCP can embed raw binary or path-like data that creates invalid escapes.
// Valid JSON escapes: \", \\, \/, \b, \f, \n, \r, \t, \uXXXX
func fixInvalidEscapes(sb *bytes.Buffer, s []byte) []byte {
	if !bytes.Contains(s, jsonEscapeBytes) {
		return s // Fast path: no backslashes to process
	}

	sb.Reset()
	sb.Grow(len(s))
	var i int
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			next := s[i+1]
			switch next {
			case '\\', '"', '/', 'b', 'f', 'n', 'r', 't':
				// Valid simple escape - copy as-is
				sb.WriteByte(s[i])
				sb.WriteByte(next)
				i += 2
			case 'u':
				// Unicode escape - validate hex digits
				if i+5 < len(s) && isValidHexEscape(s[i+2:i+6]) {
					// Valid unicode escape, copy as-is
					sb.Write(s[i : i+6])
					i += 6
				} else {
					// Invalid unicode escape - escape the backslash
					sb.WriteString("\\\\u")
					i += 2
				}
			default:
				// Invalid escape sequence - escape the backslash to make it literal
				sb.WriteString("\\\\")
				sb.WriteByte(next)
				i += 2
			}
			continue
		}
		sb.WriteByte(s[i])
		i++
	}

	return sb.Bytes()
}

func isValidHexEscape(s []byte) bool {
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

var jsonCloseTagBytes = []byte("}")

// repairTruncatedJSON closes JSON that was truncated mid-stream by Burp MCP.
// Expected format: {"request":"...","response":"...","notes":"..."}
func repairTruncatedJSON(sb *bytes.Buffer, s []byte) []byte {
	// Check if JSON is properly closed
	s = bytes.TrimSpace(s)
	if bytes.HasSuffix(s, jsonCloseTagBytes) {
		return s
	}

	// JSON is truncated - find where we are and close it
	// The structure is always: {"request":"...","response":"...","notes":"..."}

	// Check if we're inside a string value (odd number of unescaped quotes after last field marker)
	// Simple heuristic: if it doesn't end with "}" or ,"}" or similar, we're mid-value

	// Find the last field we were in
	lastRequest := bytes.LastIndex(s, []byte(`"request":"`))
	lastResponse := bytes.LastIndex(s, []byte(`"response":"`))
	lastNotes := bytes.LastIndex(s, []byte(`"notes":"`))

	sb.Reset()
	sb.Write(s)

	// Determine which field we're in based on last marker position
	if lastNotes > lastResponse && lastNotes > lastRequest {
		// We're in notes field - close it
		sb.WriteString(`"}`)
	} else if lastResponse > lastRequest {
		// We're in response field - close it and add empty notes
		sb.WriteString(`","notes":""}`)
	} else if lastRequest >= 0 {
		// We're in request field - close it and add empty response/notes
		sb.WriteString(`","response":"","notes":""}`)
	} else {
		// Malformed from the start, just try to close
		sb.WriteString(`"}`)
	}

	return sb.Bytes()
}

// SendHTTP1Request sends an HTTP/1.1 request through Burp and returns the response.
// Note: This bypasses the proxy (direct from Burp) and does NOT appear in proxy history.
func (c *BurpClient) SendHTTP1Request(ctx context.Context, params SendRequestParams) (string, error) {
	var response string
	err := c.withConn(ctx, func(opCtx context.Context) error {
		result, err := c.mcpClient.CallTool(opCtx, mcp.CallToolRequest{
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
			return fmt.Errorf("send_http1_request failed: %w", err)
		} else if result.IsError {
			return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
		}
		response = extractTextContent(result.Content)
		return nil
	})
	return response, err
}

// CreateRepeaterTab creates a new Repeater tab in Burp with the specified request.
func (c *BurpClient) CreateRepeaterTab(ctx context.Context, params RepeaterTabParams) error {
	return c.withConn(ctx, func(opCtx context.Context) error {
		args := map[string]interface{}{
			"content":        params.Content,
			"targetHostname": params.TargetHostname,
			"targetPort":     params.TargetPort,
			"usesHttps":      params.UsesHTTPS,
		}
		if params.TabName != "" {
			args["tabName"] = params.TabName
		}

		result, err := c.mcpClient.CallTool(opCtx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name:      "create_repeater_tab",
				Arguments: args,
			},
		})
		if err != nil {
			return fmt.Errorf("create_repeater_tab failed: %w", err)
		} else if result.IsError {
			return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
		}
		return nil
	})
}

// SetInterceptState enables or disables proxy intercept mode.
func (c *BurpClient) SetInterceptState(ctx context.Context, intercepting bool) error {
	return c.withConn(ctx, func(opCtx context.Context) error {
		result, err := c.mcpClient.CallTool(opCtx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name: "set_proxy_intercept_state",
				Arguments: map[string]interface{}{
					"intercepting": intercepting,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("set_proxy_intercept_state failed: %w", err)
		} else if result.IsError {
			return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
		}
		return nil
	})
}

// SendHTTP2Request sends an HTTP/2 request through Burp and returns the response.
// Note: This bypasses the proxy (direct from Burp) and does NOT appear in proxy history.
func (c *BurpClient) SendHTTP2Request(ctx context.Context, params SendHTTP2RequestParams) (string, error) {
	var response string
	err := c.withConn(ctx, func(opCtx context.Context) error {
		args := map[string]interface{}{
			"targetHostname": params.TargetHostname,
			"targetPort":     params.TargetPort,
			"usesHttps":      params.UsesHTTPS,
			"requestBody":    params.RequestBody,
		}
		if params.PseudoHeaders != nil {
			args["pseudoHeaders"] = params.PseudoHeaders
		}
		if params.Headers != nil {
			args["headers"] = params.Headers
		}

		result, err := c.mcpClient.CallTool(opCtx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name:      "send_http2_request",
				Arguments: args,
			},
		})
		if err != nil {
			return fmt.Errorf("send_http2_request failed: %w", err)
		} else if result.IsError {
			return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
		}
		response = extractTextContent(result.Content)
		return nil
	})
	return response, err
}

// SendToIntruder creates a new Intruder tab with the specified HTTP request.
func (c *BurpClient) SendToIntruder(ctx context.Context, params IntruderParams) error {
	return c.withConn(ctx, func(opCtx context.Context) error {
		args := map[string]interface{}{
			"content":        params.Content,
			"targetHostname": params.TargetHostname,
			"targetPort":     params.TargetPort,
			"usesHttps":      params.UsesHTTPS,
		}
		if params.TabName != "" {
			args["tabName"] = params.TabName
		}

		result, err := c.mcpClient.CallTool(opCtx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name:      "send_to_intruder",
				Arguments: args,
			},
		})
		if err != nil {
			return fmt.Errorf("send_to_intruder failed: %w", err)
		} else if result.IsError {
			return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
		}
		return nil
	})
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
	var raw string
	err := c.withConn(ctx, func(opCtx context.Context) error {
		result, err := c.mcpClient.CallTool(opCtx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name: "get_proxy_websocket_history",
				Arguments: map[string]interface{}{
					"count":  count,
					"offset": offset,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("get_proxy_websocket_history failed: %w", err)
		} else if result.IsError {
			return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
		}
		raw = extractTextContent(result.Content)
		return nil
	})
	return raw, err
}

// GetProxyWebsocketHistoryRegex retrieves filtered proxy WebSocket history entries.
func (c *BurpClient) GetProxyWebsocketHistoryRegex(ctx context.Context, regex string, count, offset int) ([]WebSocketHistoryEntry, error) {
	var entries []WebSocketHistoryEntry
	err := c.withConn(ctx, func(opCtx context.Context) error {
		result, err := c.mcpClient.CallTool(opCtx, mcp.CallToolRequest{
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
			return fmt.Errorf("get_proxy_websocket_history_regex failed: %w", err)
		} else if result.IsError {
			return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
		}
		var parseErr error
		entries, parseErr = parseWebsocketHistoryNDJSON(extractTextContent(result.Content))
		return parseErr
	})
	return entries, err
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
	return c.withConn(ctx, func(opCtx context.Context) error {
		result, err := c.mcpClient.CallTool(opCtx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name: "set_task_execution_engine_state",
				Arguments: map[string]interface{}{
					"running": running,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("set_task_execution_engine_state failed: %w", err)
		} else if result.IsError {
			return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
		}
		return nil
	})
}

// GetActiveEditorContents retrieves the contents of the user's active message editor.
func (c *BurpClient) GetActiveEditorContents(ctx context.Context) (string, error) {
	var contents string
	err := c.withConn(ctx, func(opCtx context.Context) error {
		result, err := c.mcpClient.CallTool(opCtx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name:      "get_active_editor_contents",
				Arguments: map[string]interface{}{},
			},
		})
		if err != nil {
			return fmt.Errorf("get_active_editor_contents failed: %w", err)
		} else if result.IsError {
			return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
		}
		contents = extractTextContent(result.Content)
		return nil
	})
	return contents, err
}

// SetActiveEditorContents sets the contents of the user's active message editor.
func (c *BurpClient) SetActiveEditorContents(ctx context.Context, text string) error {
	return c.withConn(ctx, func(opCtx context.Context) error {
		result, err := c.mcpClient.CallTool(opCtx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name: "set_active_editor_contents",
				Arguments: map[string]interface{}{
					"text": text,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("set_active_editor_contents failed: %w", err)
		} else if result.IsError {
			return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
		}
		return nil
	})
}

// ErrConfigEditingDisabled is returned when Burp's MCP config editing is not enabled.
var ErrConfigEditingDisabled = errors.New("config editing disabled in Burp MCP settings")

// GetMatchReplaceRules retrieves HTTP match/replace rules from project options.
func (c *BurpClient) GetMatchReplaceRules(ctx context.Context) ([]MatchReplaceRule, error) {
	return c.getMatchReplaceRulesFromKey(ctx, "match_replace_rules")
}

// SetMatchReplaceRules sets HTTP match/replace rules in project options.
func (c *BurpClient) SetMatchReplaceRules(ctx context.Context, rules []MatchReplaceRule) error {
	return c.setMatchReplaceRulesToKey(ctx, "match_replace_rules", rules)
}

// GetWSMatchReplaceRules retrieves WebSocket match/replace rules from project options.
func (c *BurpClient) GetWSMatchReplaceRules(ctx context.Context) ([]MatchReplaceRule, error) {
	return c.getMatchReplaceRulesFromKey(ctx, "ws_match_replace_rules")
}

// SetWSMatchReplaceRules sets WebSocket match/replace rules in project options.
func (c *BurpClient) SetWSMatchReplaceRules(ctx context.Context, rules []MatchReplaceRule) error {
	return c.setMatchReplaceRulesToKey(ctx, "ws_match_replace_rules", rules)
}

func (c *BurpClient) getMatchReplaceRulesFromKey(ctx context.Context, key string) ([]MatchReplaceRule, error) {
	var rules []MatchReplaceRule
	err := c.withConn(ctx, func(opCtx context.Context) error {
		result, err := c.mcpClient.CallTool(opCtx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name:      "output_project_options",
				Arguments: map[string]interface{}{},
			},
		})
		if err != nil {
			return fmt.Errorf("output_project_options failed: %w", err)
		} else if result.IsError {
			return fmt.Errorf("MCP error: %s", extractTextContent(result.Content))
		}

		var config struct {
			Proxy map[string]json.RawMessage `json:"proxy"`
		}
		if err := json.Unmarshal([]byte(extractTextContent(result.Content)), &config); err != nil {
			return fmt.Errorf("parse project options: %w", err)
		}

		raw, ok := config.Proxy[key]
		if !ok {
			return nil // no rules configured
		} else if err := json.Unmarshal(raw, &rules); err != nil {
			return fmt.Errorf("parse %s: %w", key, err)
		}
		return nil
	})
	return rules, err
}

func (c *BurpClient) setMatchReplaceRulesToKey(ctx context.Context, key string, rules []MatchReplaceRule) error {
	return c.withConn(ctx, func(opCtx context.Context) error {
		config := map[string]interface{}{
			"proxy": map[string]interface{}{
				key: rules,
			},
		}
		configJSON, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("marshal config: %w", err)
		}

		result, err := c.mcpClient.CallTool(opCtx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{
				Name: "set_project_options",
				Arguments: map[string]interface{}{
					"json": string(configJSON),
				},
			},
		})
		if err != nil {
			return fmt.Errorf("set_project_options failed: %w", err)
		} else if result.IsError {
			msg := extractTextContent(result.Content)
			if strings.Contains(msg, "User has disabled configuration editing") {
				return ErrConfigEditingDisabled
			}
			return fmt.Errorf("MCP error: %s", msg)
		}
		return nil
	})
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

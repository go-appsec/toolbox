package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/jentfoo/llm-security-toolbox/sectool/service/mcp"
)

// BurpBackend implements HttpBackend using Burp Suite via MCP.
type BurpBackend struct {
	client *mcp.BurpClient
}

// Compile-time check that BurpBackend implements HttpBackend
var _ HttpBackend = (*BurpBackend)(nil)

// NewBurpBackend creates a new Burp HttpBackend with the given MCP URL.
func NewBurpBackend(url string, opts ...mcp.Option) *BurpBackend {
	return &BurpBackend{
		client: mcp.New(url, opts...),
	}
}

func (b *BurpBackend) Connect(ctx context.Context) error {
	log.Printf("burp: connecting to MCP at %s", b.client.URL())
	if err := b.client.Connect(ctx); err != nil {
		log.Printf("burp: connection failed: %v", err)
		return err
	}
	return nil
}

func (b *BurpBackend) Close() error {
	log.Printf("burp: closing connection")
	return b.client.Close()
}

func (b *BurpBackend) OnConnectionLost(handler func(error)) {
	b.client.OnConnectionLost(handler)
}

// ensureConnected checks if the client is connected and attempts reconnection if not.
// Uses a fresh context to avoid issues with already-cancelled parent context.
func (b *BurpBackend) ensureConnected(ctx context.Context) error {
	if b.client.IsConnected() {
		return nil
	}
	return b.forceReconnect()
}

// forceReconnect closes any existing connection and establishes a new one.
// Used when we know the connection is dead (e.g., after a connection error).
func (b *BurpBackend) forceReconnect() error {
	log.Printf("burp: connection lost, attempting reconnection...")

	// Close existing connection first to ensure clean state
	_ = b.client.Close()

	// Use a fresh context for reconnection - the original context may be cancelled
	// which would cause reconnection to fail immediately.
	reconnCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := b.client.Connect(reconnCtx); err != nil {
		return fmt.Errorf("reconnection failed: %w", err)
	}
	log.Printf("burp: reconnected successfully")
	return nil
}

// isConnectionError checks if an error indicates a connection problem that warrants retry.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, mcp.ErrNotConnected) {
		return true
	}
	// Check for common connection-related error patterns
	errStr := err.Error()
	return strings.Contains(errStr, "connection") ||
		strings.Contains(errStr, "transport") ||
		strings.Contains(errStr, "EOF") ||
		strings.Contains(errStr, "context canceled") ||
		strings.Contains(errStr, "deadline exceeded")
}

func (b *BurpBackend) GetProxyHistory(ctx context.Context, count int, offset uint32) ([]ProxyEntry, error) {
	// Ensure connected before operation
	if err := b.ensureConnected(ctx); err != nil {
		return nil, err
	}

	entries, err := b.client.GetProxyHistory(ctx, count, int(offset))
	if err != nil {
		// On connection error, force reconnection and retry once
		if isConnectionError(err) {
			log.Printf("burp: GetProxyHistory failed with connection error, retrying: %v", err)
			if reconnErr := b.forceReconnect(); reconnErr != nil {
				return nil, err // return original error
			}
			entries, err = b.client.GetProxyHistory(ctx, count, int(offset))
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	return convertMCPEntries(entries), nil
}

// convertMCPEntries converts MCP-specific entries to HttpBackend-agnostic form.
func convertMCPEntries(entries []mcp.ProxyHistoryEntry) []ProxyEntry {
	result := make([]ProxyEntry, len(entries))
	for i, e := range entries {
		result[i] = ProxyEntry{
			Request:  e.Request,
			Response: e.Response,
			Notes:    e.Notes,
		}
	}
	return result
}

func (b *BurpBackend) SendRequest(ctx context.Context, name string, req SendRequestInput) (*SendRequestResult, error) {
	scheme := schemeHTTP
	if req.Target.UsesHTTPS {
		scheme = schemeHTTPS
	}
	log.Printf("burp: sending request %s to %s://%s:%d (follow_redirects=%v)",
		name, scheme, req.Target.Hostname, req.Target.Port, req.FollowRedirects)

	// Ensure connected before operation
	if err := b.ensureConnected(ctx); err != nil {
		return nil, err
	}

	// Apply timeout if specified
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	result, err := b.doSendRequest(ctx, name, req)
	if err != nil && isConnectionError(err) {
		// Force reconnection and retry once
		log.Printf("burp: SendRequest failed with connection error, retrying: %v", err)
		if reconnErr := b.forceReconnect(); reconnErr != nil {
			return nil, err // return original error
		}
		return b.doSendRequest(ctx, name, req)
	}
	return result, err
}

// doSendRequest performs the actual request sending (without reconnection logic).
func (b *BurpBackend) doSendRequest(ctx context.Context, name string, req SendRequestInput) (*SendRequestResult, error) {
	err := b.client.CreateRepeaterTab(ctx, mcp.RepeaterTabParams{
		TabName:        name,
		Content:        string(req.RawRequest),
		TargetHostname: req.Target.Hostname,
		TargetPort:     req.Target.Port,
		UsesHTTPS:      req.Target.UsesHTTPS,
	})
	if err != nil {
		return nil, err
	}

	start := time.Now()

	// Handle redirects client-side if requested
	if req.FollowRedirects {
		return b.sendWithRedirects(ctx, req, start, 10) // max 10 redirects
	}

	return b.sendSingle(ctx, req, start)
}

// sendSingle sends a single request without following redirects.
func (b *BurpBackend) sendSingle(ctx context.Context, req SendRequestInput, start time.Time) (*SendRequestResult, error) {
	result, err := b.client.SendHTTP1Request(ctx, mcp.SendRequestParams{
		Content:        string(req.RawRequest),
		TargetHostname: req.Target.Hostname,
		TargetPort:     req.Target.Port,
		UsesHTTPS:      req.Target.UsesHTTPS,
	})
	if err != nil {
		return nil, err
	}

	headers, body, err := parseBurpResponse(result)
	if err != nil {
		// Return raw result if parsing fails
		return &SendRequestResult{
			Headers:  []byte(result),
			Body:     nil,
			Duration: time.Since(start),
		}, nil
	}

	return &SendRequestResult{
		Headers:  headers,
		Body:     body,
		Duration: time.Since(start),
	}, nil
}

// sendWithRedirects follows redirects up to maxRedirects times.
// Implements browser-like redirect behavior per RFC 7231.
func (b *BurpBackend) sendWithRedirects(ctx context.Context, req SendRequestInput, start time.Time, maxRedirects int) (*SendRequestResult, error) {
	currentReq := req
	currentPath := extractRequestPath(currentReq.RawRequest)

	for i := 0; i < maxRedirects; i++ {
		result, err := b.sendSingle(ctx, currentReq, start)
		if err != nil {
			return nil, err
		}

		resp, err := readResponseBytes(result.Headers)
		if err != nil {
			result.Duration = time.Since(start)
			return result, nil
		}
		_ = resp.Body.Close()

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			result.Duration = time.Since(start)
			return result, nil
		}

		location := resp.Header.Get("Location")
		if location == "" {
			result.Duration = time.Since(start)
			return result, nil
		}

		// Build redirect request with proper browser behavior
		newReq, newTarget, newPath, err := buildRedirectRequest(
			currentReq.RawRequest, location, currentReq.Target, currentPath, resp.StatusCode)
		if err != nil {
			result.Duration = time.Since(start)
			return result, nil
		}

		currentReq.RawRequest = newReq
		currentReq.Target = newTarget
		currentPath = newPath
	}

	return nil, errors.New("too many redirects")
}

// redirectBehavior describes how to handle a redirect based on status code.
type redirectBehavior struct {
	preserveMethod bool // 307, 308 preserve original method
	preserveBody   bool // 307, 308 preserve body
}

// getRedirectBehavior returns the appropriate behavior for a status code.
// Per RFC 7231: 307/308 preserve method and body; 301/302/303 become GET.
func getRedirectBehavior(status int) redirectBehavior {
	switch status {
	case 307, 308:
		return redirectBehavior{preserveMethod: true, preserveBody: true}
	default: // 301, 302, 303
		return redirectBehavior{preserveMethod: false, preserveBody: false}
	}
}

// buildRedirectRequest builds a new request for following a redirect.
// Implements browser-like behavior: preserves headers (including cookies),
// drops Authorization on cross-origin, handles method/body per status code.
func buildRedirectRequest(originalReq []byte, location string, currentTarget Target, currentPath string, status int) ([]byte, Target, string, error) {
	behavior := getRedirectBehavior(status)

	// Resolve location to new target and path
	newTarget, newPath, err := resolveRedirectLocation(location, currentTarget, currentPath)
	if err != nil {
		return nil, Target{}, "", err
	}

	// Determine if cross-origin (different hostname)
	isCrossOrigin := newTarget.Hostname != currentTarget.Hostname

	// Extract original method
	method := extractMethod(originalReq)
	if !behavior.preserveMethod {
		method = "GET"
	}

	// Extract original body (only keep for 307/308)
	var body []byte
	if behavior.preserveBody {
		_, body = splitHeadersBody(originalReq)
	}

	// Build new request
	var buf bytes.Buffer

	// Request line
	buf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, newPath))

	// Copy headers with appropriate modifications
	copyHeadersForRedirect(originalReq, &buf, newTarget, isCrossOrigin, behavior.preserveBody)

	// Update Content-Length if we have a body
	if len(body) > 0 {
		buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}

	buf.WriteString("\r\n")
	buf.Write(body)

	return buf.Bytes(), newTarget, newPath, nil
}

// resolveRedirectLocation resolves a Location header value to a target and path.
// Handles absolute URLs, protocol-relative URLs, absolute paths, and relative paths.
func resolveRedirectLocation(location string, currentTarget Target, currentPath string) (Target, string, error) {
	// Absolute URL (http:// or https://)
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		u, err := url.Parse(location)
		if err != nil {
			return Target{}, "", err
		}
		return targetFromURL(u), u.RequestURI(), nil
	}

	// Protocol-relative URL (//host/path)
	if strings.HasPrefix(location, "//") {
		scheme := "https"
		if !currentTarget.UsesHTTPS {
			scheme = "http"
		}
		u, err := url.Parse(scheme + ":" + location)
		if err != nil {
			return Target{}, "", err
		}
		return targetFromURL(u), u.RequestURI(), nil
	}

	// Absolute path (/path)
	if strings.HasPrefix(location, "/") {
		return currentTarget, location, nil
	}

	// Relative path - resolve against current path directory
	baseDir := path.Dir(currentPath)
	if baseDir == "." {
		baseDir = "/"
	}
	resolved := path.Join(baseDir, location)
	if !strings.HasPrefix(resolved, "/") {
		resolved = "/" + resolved
	}
	return currentTarget, resolved, nil
}

// targetFromURL extracts a Target from a parsed URL.
func targetFromURL(u *url.URL) Target {
	t := Target{
		Hostname:  u.Hostname(),
		UsesHTTPS: u.Scheme == "https",
	}

	if u.Port() != "" {
		t.Port, _ = strconv.Atoi(u.Port())
	} else if t.UsesHTTPS {
		t.Port = 443
	} else {
		t.Port = 80
	}

	return t
}

// copyHeadersForRedirect copies headers from original request to buffer,
// applying redirect-appropriate modifications.
func copyHeadersForRedirect(originalReq []byte, buf *bytes.Buffer, newTarget Target, isCrossOrigin, preserveBody bool) {
	headers, _ := splitHeadersBody(originalReq)

	// Format new Host header value
	newHost := newTarget.Hostname
	if (newTarget.UsesHTTPS && newTarget.Port != 443) || (!newTarget.UsesHTTPS && newTarget.Port != 80) {
		newHost = fmt.Sprintf("%s:%d", newTarget.Hostname, newTarget.Port)
	}

	// Headers to skip (we handle these specially)
	skipHeaders := map[string]bool{
		"host":           true, // We set this ourselves
		"content-length": true, // Recalculated based on body
	}

	// Skip content-related headers if not preserving body
	if !preserveBody {
		skipHeaders["content-type"] = true
		skipHeaders["content-encoding"] = true
		skipHeaders["transfer-encoding"] = true
	}

	// Write new Host header first
	_, _ = fmt.Fprintf(buf, "Host: %s\r\n", newHost)

	// Process each header line
	for _, line := range bytes.Split(headers, []byte("\r\n")) {
		if len(line) == 0 {
			continue
		}

		// Skip request line
		if bytes.HasPrefix(line, []byte("GET ")) || bytes.HasPrefix(line, []byte("POST ")) ||
			bytes.HasPrefix(line, []byte("PUT ")) || bytes.HasPrefix(line, []byte("DELETE ")) ||
			bytes.HasPrefix(line, []byte("PATCH ")) || bytes.HasPrefix(line, []byte("HEAD ")) ||
			bytes.HasPrefix(line, []byte("OPTIONS ")) || bytes.HasPrefix(line, []byte("TRACE ")) ||
			bytes.HasPrefix(line, []byte("CONNECT ")) {
			continue
		}

		// Parse header name
		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx < 0 {
			continue
		}
		name := strings.ToLower(string(bytes.TrimSpace(line[:colonIdx])))

		// Skip headers we handle specially
		if skipHeaders[name] {
			continue
		}

		// Drop Authorization on cross-origin (browser security behavior)
		if isCrossOrigin && name == "authorization" {
			continue
		}

		// Preserve all other headers (including Cookie for session continuity)
		buf.Write(line)
		buf.WriteString("\r\n")
	}
}

// extractMethod extracts the HTTP method from a raw request.
func extractMethod(raw []byte) string {
	lines := bytes.SplitN(raw, []byte("\r\n"), 2)
	if len(lines) == 0 {
		return "GET"
	}
	parts := bytes.SplitN(lines[0], []byte(" "), 2)
	if len(parts) == 0 {
		return "GET"
	}
	return string(parts[0])
}

// extractRequestPath extracts the path from a raw request's request line.
func extractRequestPath(raw []byte) string {
	lines := bytes.SplitN(raw, []byte("\r\n"), 2)
	if len(lines) == 0 {
		return "/"
	}
	parts := bytes.SplitN(lines[0], []byte(" "), 3)
	if len(parts) < 2 {
		return "/"
	}
	return string(parts[1])
}

// parseBurpResponse extracts HTTP response from Burp's toString format.
// Format: HttpRequestResponse{httpRequest=..., httpResponse=..., messageAnnotations=...}
func parseBurpResponse(raw string) (headers, body []byte, err error) {
	// Find httpResponse section
	start := strings.Index(raw, "httpResponse=")
	if start < 0 {
		return nil, nil, errors.New("httpResponse not found in Burp output")
	}
	start += len("httpResponse=")

	// Find the end - could be ", messageAnnotations=" or just "}"
	end := strings.Index(raw[start:], ", messageAnnotations=")
	if end < 0 {
		end = strings.LastIndex(raw[start:], "}")
	}
	if end < 0 {
		return nil, nil, errors.New("could not find end of httpResponse")
	}

	response := raw[start : start+end]

	// Convert escaped newlines to actual CRLF bytes
	responseBytes := bytes.ReplaceAll([]byte(response), []byte(`\r\n`), []byte("\r\n"))

	// Look for the HTTP/ prefix to validate we found the response
	if !bytes.Contains(responseBytes, []byte("HTTP/")) {
		return nil, nil, errors.New("invalid response format: no HTTP/ found")
	}

	headers, body = splitHeadersBody(responseBytes)
	return
}

// SetInterceptState exposes Burp-specific intercept control.
// This is not part of the HttpBackend interface as it's Burp-specific.
func (b *BurpBackend) SetInterceptState(ctx context.Context, intercepting bool) error {
	return b.client.SetInterceptState(ctx, intercepting)
}

// CreateRepeaterTab exposes Burp-specific Repeater functionality.
// This is not part of the HttpBackend interface as it's Burp-specific.
func (b *BurpBackend) CreateRepeaterTab(ctx context.Context, params mcp.RepeaterTabParams) error {
	return b.client.CreateRepeaterTab(ctx, params)
}

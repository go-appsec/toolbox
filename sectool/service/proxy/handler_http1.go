package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	protocolHTTP11 = "http/1.1"

	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

type http1Handler struct {
	history      *HistoryStore
	maxBodyBytes int
	ruleApplier  RuleApplier       // optional, nil means no rules applied
	wsHandler    *webSocketHandler // optional, for WebSocket upgrade handling
	timeouts     TimeoutConfig
}

// Handle processes HTTP/1.1 proxy requests with keep-alive support.
// Each request may target a different upstream server (proxy-form URLs).
func (h *http1Handler) Handle(ctx context.Context, clientConn net.Conn, clientReader *bufio.Reader) {
	// Close connection when context is cancelled to unblock blocking reads.
	go func() {
		<-ctx.Done()
		_ = clientConn.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !h.handleSinglePlainHTTP(ctx, clientConn, clientReader) {
			return
		}
	}
}

// handleSinglePlainHTTP processes one HTTP/1.1 proxy request.
// Returns true to continue processing more requests (keep-alive), false to close.
func (h *http1Handler) handleSinglePlainHTTP(ctx context.Context, clientConn net.Conn, clientReader *bufio.Reader) bool {
	startTime := time.Now()
	var buf bytes.Buffer

	req, err := parseRequest(clientReader)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, ErrEmptyRequest) {
			log.Printf("proxy: failed to parse request: %v", err)
			h.sendError(clientConn, 400, "Bad Request")
		}
		return false
	}

	// Apply request rules BEFORE routing decisions (target extraction, WebSocket detection)
	// This allows rules to affect Host header, Upgrade header, etc.
	if h.ruleApplier != nil {
		req = h.ruleApplier.ApplyRequestRules(req)
	}

	target, err := h.extractTarget(req)
	if err != nil {
		log.Printf("proxy: failed to extract target: %v", err)
		h.sendError(clientConn, 400, "Bad Request: "+err.Error())
		return false
	}

	// Rewrite proxy-form to origin-form
	h.rewriteToOriginForm(req, target)
	req.Protocol = protocolHTTP11

	if h.wsHandler != nil && isWebSocketUpgrade(req) {
		h.wsHandler.Handle(ctx, clientConn, clientReader, req, target)
		return false // WebSocket takes over
	}

	upstreamAddr := fmt.Sprintf("%s:%d", target.Hostname, target.Port)
	dialer := net.Dialer{Timeout: h.timeouts.DialTimeout}
	upstreamConn, err := dialer.DialContext(ctx, "tcp", upstreamAddr)
	if err != nil {
		log.Printf("proxy: failed to connect to %s: %v", upstreamAddr, err)
		if isTimeoutError(err) {
			h.sendError(clientConn, 504, "Gateway Timeout: connection timeout")
		} else {
			h.sendError(clientConn, 502, "Bad Gateway: connection refused")
		}
		h.storeEntry(req, nil, startTime)
		return false
	}
	defer func() { _ = upstreamConn.Close() }()

	if h.timeouts.WriteTimeout > 0 {
		_ = upstreamConn.SetWriteDeadline(time.Now().Add(h.timeouts.WriteTimeout))
	}

	// TODO - preserveChunked=false converts chunked to Content-Length
	//        future we should retain chunked encoding forfull wire fidelity
	if _, err := upstreamConn.Write(req.SerializeRaw(&buf, false)); err != nil {
		log.Printf("proxy: failed to send request to %s: %v", upstreamAddr, err)
		if isTimeoutError(err) {
			h.sendError(clientConn, 504, "Gateway Timeout: write timeout")
		} else {
			h.sendError(clientConn, 502, "Bad Gateway: failed to send request")
		}
		h.storeEntry(req, nil, startTime)
		return false
	}

	if h.timeouts.ReadTimeout > 0 {
		_ = upstreamConn.SetReadDeadline(time.Now().Add(h.timeouts.ReadTimeout))
	}

	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := parseResponse(upstreamReader, req.Method)
	if err != nil {
		log.Printf("proxy: failed to parse response from %s: %v", upstreamAddr, err)
		if isTimeoutError(err) {
			h.sendError(clientConn, 504, "Gateway Timeout: read timeout")
		} else {
			h.sendError(clientConn, 502, "Bad Gateway: malformed response")
		}
		h.storeEntry(req, nil, startTime)
		return false
	}

	if h.ruleApplier != nil {
		resp = h.ruleApplier.ApplyResponseRules(resp)
	}

	// Forward response to client
	if h.timeouts.WriteTimeout > 0 {
		_ = clientConn.SetWriteDeadline(time.Now().Add(h.timeouts.WriteTimeout))
	}
	if _, err := clientConn.Write(resp.SerializeRaw(&buf, false)); err != nil {
		log.Printf("proxy: failed to send response to client: %v", err)
		return false
	}

	// Truncate bodies before storing
	if h.maxBodyBytes > 0 && len(req.Body) > h.maxBodyBytes {
		req.Body = req.Body[:h.maxBodyBytes]
	}
	if h.maxBodyBytes > 0 && resp != nil && len(resp.Body) > h.maxBodyBytes {
		resp.Body = resp.Body[:h.maxBodyBytes]
	}

	h.storeEntry(req, resp, startTime)

	connHeader := strings.ToLower(resp.GetHeader("Connection"))
	return connHeader != "close"
}

// extractTarget determines the upstream server from the request.
func (h *http1Handler) extractTarget(req *RawHTTP1Request) (*Target, error) {
	// Check for proxy-form URL (absolute URI)
	if strings.HasPrefix(req.Path, schemeHTTP+"://") || strings.HasPrefix(req.Path, schemeHTTPS+"://") {
		return h.parseProxyFormURL(req.Path)
	}

	// Fallback to Host header
	host := req.GetHeader("Host")
	if host == "" {
		return nil, errors.New("no Host header and not a proxy-form request")
	}

	return h.parseHostPort(host, false)
}

// parseProxyFormURL parses an absolute URI like http://example.com:8080/path
func (h *http1Handler) parseProxyFormURL(rawURL string) (*Target, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy-form URL: %w", err)
	}

	usesHTTPS := u.Scheme == schemeHTTPS
	return h.parseHostPort(u.Host, usesHTTPS)
}

// parseHostPort parses host:port, defaulting port based on scheme.
// Handles IPv6 addresses with brackets (e.g., "[::1]:8080" or "[::1]").
func (h *http1Handler) parseHostPort(hostPort string, usesHTTPS bool) (*Target, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		// No port specified, use default
		// Handle IPv6 addresses with brackets but no port (e.g., "[::1]")
		host = strings.TrimSuffix(strings.TrimPrefix(hostPort, "["), "]")
		if usesHTTPS {
			portStr = "443"
		} else {
			portStr = "80"
		}
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %s", portStr)
	}

	return &Target{
		Hostname:  host,
		Port:      port,
		UsesHTTPS: usesHTTPS,
	}, nil
}

// rewriteToOriginForm converts proxy-form requests to origin-form.
func (h *http1Handler) rewriteToOriginForm(req *RawHTTP1Request, target *Target) {
	// If path is an absolute URI, extract just the path component
	if strings.HasPrefix(req.Path, schemeHTTP+"://") || strings.HasPrefix(req.Path, schemeHTTPS+"://") {
		u, err := url.Parse(req.Path)
		if err != nil {
			return
		}
		req.Path = u.Path
		if req.Path == "" {
			req.Path = "/"
		}
		// Query was already separated by parser
	}

	// Ensure Host header is set correctly
	hostHeader := target.Hostname
	if (target.UsesHTTPS && target.Port != 443) || (!target.UsesHTTPS && target.Port != 80) {
		hostHeader = fmt.Sprintf("%s:%d", target.Hostname, target.Port)
	}
	req.SetHeader("Host", hostHeader)
}

// isTimeoutError checks if the error is a network timeout.
func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// sendError writes an HTTP error response to the client.
func (h *http1Handler) sendError(conn net.Conn, code int, message string) {
	resp := &RawHTTP1Response{
		Version:    "HTTP/1.1",
		StatusCode: code,
		StatusText: message,
		Headers: []Header{
			{Name: "Content-Type", Value: "text/plain"},
			{Name: "Connection", Value: "close"},
		},
		Body: []byte(message + "\n"),
	}
	_, _ = conn.Write(resp.SerializeRaw(bytes.NewBuffer(nil), false))
}

// storeEntry saves the request/response pair to history.
func (h *http1Handler) storeEntry(req *RawHTTP1Request, resp *RawHTTP1Response, startTime time.Time) {
	entry := &HistoryEntry{
		Protocol:  protocolHTTP11,
		Request:   req,
		Response:  resp,
		Timestamp: startTime,
		Duration:  time.Since(startTime),
	}
	if !h.history.ShouldCapture(entry) {
		return
	}
	h.history.Store(entry)
}

// HandleTLS handles HTTP/1.1 traffic over already-established TLS connections.
// Used by CONNECT handler after TLS handshake is complete.
// Loops handling request/response pairs until connection closes.
// target is needed for WebSocket upgrade detection (wss://).
func (h *http1Handler) HandleTLS(ctx context.Context, clientConn, upstreamConn net.Conn, clientReader *bufio.Reader, upstreamReader *bufio.Reader, target *Target) {
	// Close connections when context is cancelled to unblock blocking reads.
	// parseRequest doesn't accept context, so closing is the only way to interrupt it.
	go func() {
		<-ctx.Done()
		_ = clientConn.Close()
		_ = upstreamConn.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !h.handleSingleTLS(ctx, clientConn, upstreamConn, clientReader, upstreamReader, target) {
			return
		}
	}
}

// handleSingleTLS handles a single HTTP/1.1 request/response exchange over TLS.
// Returns true to continue processing more requests, false to close connection.
func (h *http1Handler) handleSingleTLS(ctx context.Context, clientConn, upstreamConn net.Conn, clientReader, upstreamReader *bufio.Reader, target *Target) bool {
	startTime := time.Now()
	var buf bytes.Buffer

	req, err := parseRequest(clientReader)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, ErrEmptyRequest) {
			log.Printf("proxy: failed to parse TLS request: %v", err)
			h.sendError(clientConn, 400, "Bad Request")
		}
		return false
	}

	req.Protocol = protocolHTTP11

	// Apply request rules BEFORE WebSocket detection to affect Upgrade header
	if h.ruleApplier != nil {
		req = h.ruleApplier.ApplyRequestRules(req)
	}

	if h.wsHandler != nil && isWebSocketUpgrade(req) {
		// Reuse existing upstream connection to avoid race window
		h.wsHandler.HandleTLSWithUpstream(ctx, clientConn, clientReader, upstreamConn, upstreamReader, req)
		return false // WebSocket takes over, don't continue loop
	}

	if h.timeouts.WriteTimeout > 0 {
		_ = upstreamConn.SetWriteDeadline(time.Now().Add(h.timeouts.WriteTimeout))
	}

	if _, err := upstreamConn.Write(req.SerializeRaw(&buf, false)); err != nil {
		log.Printf("proxy: failed to send TLS request: %v", err)
		if isTimeoutError(err) {
			h.sendError(clientConn, 504, "Gateway Timeout: write timeout")
		} else {
			h.sendError(clientConn, 502, "Bad Gateway: failed to send request")
		}
		h.storeEntry(req, nil, startTime)
		return false
	}

	if h.timeouts.ReadTimeout > 0 {
		_ = upstreamConn.SetReadDeadline(time.Now().Add(h.timeouts.ReadTimeout))
	}

	resp, err := parseResponse(upstreamReader, req.Method)
	if err != nil {
		log.Printf("proxy: failed to parse TLS response: %v", err)
		if isTimeoutError(err) {
			h.sendError(clientConn, 504, "Gateway Timeout: read timeout")
		} else {
			h.sendError(clientConn, 502, "Bad Gateway: malformed response")
		}
		h.storeEntry(req, nil, startTime)
		return false
	}

	// Apply response rules
	if h.ruleApplier != nil {
		resp = h.ruleApplier.ApplyResponseRules(resp)
	}

	// Forward response to client
	if h.timeouts.WriteTimeout > 0 {
		_ = clientConn.SetWriteDeadline(time.Now().Add(h.timeouts.WriteTimeout))
	}
	if _, err := clientConn.Write(resp.SerializeRaw(&buf, false)); err != nil {
		log.Printf("proxy: failed to send TLS response to client: %v", err)
		return false
	}

	// Truncate bodies before storing in history
	if h.maxBodyBytes > 0 && len(req.Body) > h.maxBodyBytes {
		req.Body = req.Body[:h.maxBodyBytes]
	}
	if h.maxBodyBytes > 0 && len(resp.Body) > h.maxBodyBytes {
		resp.Body = resp.Body[:h.maxBodyBytes]
	}

	h.storeEntry(req, resp, startTime)

	connHeader := strings.ToLower(resp.GetHeader("Connection"))
	return connHeader != "close"
}

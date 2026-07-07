package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
)

const connectionClose = "close"

type http1Handler struct {
	history             *HistoryStore
	maxBodyBytes        int
	ruleApplier         types.RuleApplier   // optional, nil means no rules applied
	responseInterceptor ResponseInterceptor // optional, nil means no interception
	reg                 *protocol.Registry
	timeouts            TimeoutConfig
}

// Handle processes HTTP/1.1 proxy requests with keep-alive support.
// Each request may target a different upstream server (proxy-form URLs).
func (h *http1Handler) Handle(ctx context.Context, clientConn net.Conn, clientReader *bufio.Reader) {
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Close connection on cancel to unblock blocking reads
	go func() {
		<-connCtx.Done()
		_ = clientConn.Close()
	}()

	for {
		select {
		case <-connCtx.Done():
			return
		default:
		}

		if !h.handleSinglePlainHTTP(connCtx, clientConn, clientReader) {
			return
		}
	}
}

// handleSinglePlainHTTP processes one HTTP/1.1 proxy request.
// Returns true to continue processing more requests (keep-alive), false to close.
func (h *http1Handler) handleSinglePlainHTTP(ctx context.Context, clientConn net.Conn, clientReader *bufio.Reader) bool {
	startTime := time.Now()
	var buf bytes.Buffer

	req, err := ParseRequest(clientReader)
	if err != nil {
		if errors.Is(err, ErrInvalidRequest) {
			log.Printf("proxy: failed to parse request: %v", err)
			h.sendError(clientConn, 400, "Bad Request")
		}
		return false
	}

	target, err := h.extractTarget(req)
	if err != nil {
		log.Printf("proxy: failed to extract target: %v", err)
		h.sendError(clientConn, 400, "Bad Request: "+err.Error())
		return false
	}

	h.rewriteToOriginForm(req, target)
	req.Protocol = types.ProtocolHTTP11

	// Response interception before rules and upstream dial
	if h.responseInterceptor != nil {
		if intercepted := h.responseInterceptor.InterceptRequest(
			target.Hostname, target.Port, PathWithoutQuery(req.Path), req.Method,
		); intercepted != nil {
			resp := BuildInterceptedH1Response(intercepted)
			_, _ = clientConn.Write(resp.SerializeRaw(&buf))
			if h.maxBodyBytes > 0 && len(req.Body) > h.maxBodyBytes {
				req.SetBody(req.Body[:h.maxBodyBytes])
			}
			h.storeEntry(target, req, resp, nil, startTime)
			return strings.ToLower(resp.GetHeader("Connection")) != connectionClose
		}
	}

	// Apply request rules before upgrade detection to affect the Upgrade header
	if h.ruleApplier != nil {
		req = h.ruleApplier.ApplyRequestRules(req)
	}

	uc := &protocol.UpgradeClaimCtx{Req: req, Target: target, Signal: "http_101"}
	if a, ok := h.reg.ClaimUpgrade(uc); ok {
		a.ServeUpgrade(ctx, uc, protocol.UpgradeConns{ClientConn: clientConn, ClientReader: clientReader})
		return false // adapter takes over
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
		h.storeEntry(target, req, nil, nil, startTime)
		return false
	}
	defer func() { _ = upstreamConn.Close() }()

	if h.timeouts.WriteTimeout > 0 {
		_ = upstreamConn.SetWriteDeadline(time.Now().Add(h.timeouts.WriteTimeout))
	}

	if _, err := upstreamConn.Write(req.SerializeRaw(&buf)); err != nil {
		log.Printf("proxy: failed to send request to %s: %v", upstreamAddr, err)
		if isTimeoutError(err) {
			h.sendError(clientConn, 504, "Gateway Timeout: write timeout")
		} else {
			h.sendError(clientConn, 502, "Bad Gateway: failed to send request")
		}
		h.storeEntry(target, req, nil, nil, startTime)
		return false
	}

	if h.timeouts.ReadTimeout > 0 {
		_ = upstreamConn.SetReadDeadline(time.Now().Add(h.timeouts.ReadTimeout))
	}

	upstreamReader := bufio.NewReader(upstreamConn)
	interim, resp, err := readFinalResponse(upstreamReader, req.Method, func(ir *types.RawHTTP1Response) error {
		return h.forwardInterim(clientConn, ir)
	})
	if err != nil {
		log.Printf("proxy: failed to parse response from %s: %v", upstreamAddr, err)
		// Skip the synthetic error if interim responses already started the wire stream
		if len(interim) == 0 {
			if isTimeoutError(err) {
				h.sendError(clientConn, 504, "Gateway Timeout: read timeout")
			} else {
				h.sendError(clientConn, 502, "Bad Gateway: malformed response")
			}
		}
		h.storeEntry(target, req, nil, interim, startTime)
		return false
	}

	if h.ruleApplier != nil {
		resp = h.ruleApplier.ApplyResponseRules(resp)
	}

	// Serialize response before storage so truncation doesn't affect the wire copy
	respBytes := resp.SerializeRaw(&buf)

	// Truncate bodies before storing
	if h.maxBodyBytes > 0 && len(req.Body) > h.maxBodyBytes {
		req.SetBody(req.Body[:h.maxBodyBytes])
	}
	if h.maxBodyBytes > 0 && resp != nil && len(resp.Body) > h.maxBodyBytes {
		resp.SetBody(resp.Body[:h.maxBodyBytes])
	}

	// Store before forwarding so history is visible by the time the client sees the response
	// Avoids a race with query history after the response arrives but before storeEntry
	h.storeEntry(target, req, resp, interim, startTime)

	// Forward response to client
	if h.timeouts.WriteTimeout > 0 {
		_ = clientConn.SetWriteDeadline(time.Now().Add(h.timeouts.WriteTimeout))
	}
	if _, err := clientConn.Write(respBytes); err != nil {
		log.Printf("proxy: failed to send response to client: %v", err)
		return false
	}

	if resp.CloseDelimited {
		return false // mirror the origin's connection-close framing
	}
	connHeader := strings.ToLower(resp.GetHeader("Connection"))
	return connHeader != connectionClose
}

// extractTarget determines the upstream server from the request.
func (h *http1Handler) extractTarget(req *types.RawHTTP1Request) (*types.Target, error) {
	// Check for proxy-form URL (absolute URI)
	if strings.HasPrefix(req.Path, types.SchemeHTTP+"://") || strings.HasPrefix(req.Path, types.SchemeHTTPS+"://") {
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
func (h *http1Handler) parseProxyFormURL(rawURL string) (*types.Target, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy-form URL: %w", err)
	}

	usesHTTPS := u.Scheme == types.SchemeHTTPS
	return h.parseHostPort(u.Host, usesHTTPS)
}

// parseHostPort parses host:port, defaulting port based on scheme.
// Handles IPv6 addresses with brackets (e.g., "[::1]:8080" or "[::1]").
func (h *http1Handler) parseHostPort(hostPort string, usesHTTPS bool) (*types.Target, error) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		// No port specified, use default
		// Handle bracketed IPv6 with no port ("[::1]")
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

	return &types.Target{
		Hostname:  host,
		Port:      port,
		UsesHTTPS: usesHTTPS,
	}, nil
}

// rewriteToOriginForm converts proxy-form requests to origin-form.
func (h *http1Handler) rewriteToOriginForm(req *types.RawHTTP1Request, target *types.Target) {
	// If path is an absolute URI, extract just the path component
	if strings.HasPrefix(req.Path, types.SchemeHTTP+"://") || strings.HasPrefix(req.Path, types.SchemeHTTPS+"://") {
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
	body := []byte(message + "\n")
	resp := &types.RawHTTP1Response{
		Version:    "HTTP/1.1",
		StatusCode: code,
		StatusText: message,
		Headers: []types.Header{
			{Name: "Content-Type", Value: "text/plain"},
			{Name: "Content-Length", Value: strconv.Itoa(len(body))},
			{Name: "Connection", Value: "close"},
		},
		Body: body,
	}
	_, _ = conn.Write(resp.SerializeRaw(bytes.NewBuffer(nil)))
}

// forwardInterim writes an interim 1xx response to the client as-is (no rules applied).
func (h *http1Handler) forwardInterim(clientConn net.Conn, ir *types.RawHTTP1Response) error {
	var buf bytes.Buffer
	if h.timeouts.WriteTimeout > 0 {
		_ = clientConn.SetWriteDeadline(time.Now().Add(h.timeouts.WriteTimeout))
	}
	_, err := clientConn.Write(ir.SerializeRaw(&buf))
	return err
}

// storeEntry saves the request/response pair, plus any interim 1xx responses, to history.
func (h *http1Handler) storeEntry(target *types.Target, req *types.RawHTTP1Request, resp *types.RawHTTP1Response, interim []*types.RawHTTP1Response, startTime time.Time) {
	flow := &types.Flow{
		Adapter:     types.ProtocolHTTP11,
		ProtocolTag: types.ProtocolHTTP11,
		Scheme:      target.Scheme(),
		Port:        target.Port,
		Request:     types.RequestToMessage(req),
		StartedAt:   startTime,
		CompletedAt: time.Now(),
	}
	if resp != nil {
		flow.Response = types.ResponseToMessage(resp)
	}
	for _, ir := range interim {
		flow.InterimResponses = append(flow.InterimResponses, types.ResponseToMessage(ir))
	}
	if !h.history.ShouldCapture(flow) {
		return
	}
	h.history.Store(flow)
}

// HandleTLS handles HTTP/1.1 traffic over already-established TLS connections.
// Used by CONNECT handler after TLS handshake is complete.
// Loops handling request/response pairs until connection closes.
// target is needed for WebSocket upgrade detection (wss://).
func (h *http1Handler) HandleTLS(ctx context.Context, clientConn, upstreamConn net.Conn, clientReader *bufio.Reader, upstreamReader *bufio.Reader, target *types.Target) {
	connCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Close connections on cancel to unblock blocking reads
	// parseRequest doesn't accept context, so closing is the only way to interrupt it
	go func() {
		<-connCtx.Done()
		_ = clientConn.Close()
		_ = upstreamConn.Close()
	}()

	for {
		select {
		case <-connCtx.Done():
			return
		default:
		}

		if !h.handleSingleTLS(connCtx, clientConn, upstreamConn, clientReader, upstreamReader, target) {
			return
		}
	}
}

// handleSingleTLS handles a single HTTP/1.1 request/response exchange over TLS.
// Returns true to continue processing more requests, false to close connection.
func (h *http1Handler) handleSingleTLS(ctx context.Context, clientConn, upstreamConn net.Conn, clientReader, upstreamReader *bufio.Reader, target *types.Target) bool {
	startTime := time.Now()
	var buf bytes.Buffer

	req, err := ParseRequest(clientReader)
	if err != nil {
		if errors.Is(err, ErrInvalidRequest) {
			// Don't log - browsers routinely send non-HTTP data on TLS connections
			// during connection lifecycle management (preconnect, idle cleanup)
			h.sendError(clientConn, 400, "Bad Request")
		}
		return false
	}

	req.Protocol = types.ProtocolHTTP11

	// Check for response interception before rules and upstream send
	if h.responseInterceptor != nil {
		if intercepted := h.responseInterceptor.InterceptRequest(
			target.Hostname, target.Port, PathWithoutQuery(req.Path), req.Method,
		); intercepted != nil {
			resp := BuildInterceptedH1Response(intercepted)
			if h.timeouts.WriteTimeout > 0 {
				_ = clientConn.SetWriteDeadline(time.Now().Add(h.timeouts.WriteTimeout))
			}
			_, _ = clientConn.Write(resp.SerializeRaw(&buf))
			if h.maxBodyBytes > 0 && len(req.Body) > h.maxBodyBytes {
				req.SetBody(req.Body[:h.maxBodyBytes])
			}
			h.storeEntry(target, req, resp, nil, startTime)
			return strings.ToLower(resp.GetHeader("Connection")) != connectionClose
		}
	}

	// Apply request rules BEFORE WebSocket detection to affect Upgrade header
	if h.ruleApplier != nil {
		req = h.ruleApplier.ApplyRequestRules(req)
	}

	uc := &protocol.UpgradeClaimCtx{Req: req, Target: target, Signal: "http_101"}
	if a, ok := h.reg.ClaimUpgrade(uc); ok {
		a.ServeUpgrade(ctx, uc, protocol.UpgradeConns{
			ClientConn:     clientConn,
			ClientReader:   clientReader,
			UpstreamConn:   upstreamConn,
			UpstreamReader: upstreamReader,
		})
		return false // adapter takes over
	}

	if h.timeouts.WriteTimeout > 0 {
		_ = upstreamConn.SetWriteDeadline(time.Now().Add(h.timeouts.WriteTimeout))
	}

	if _, err := upstreamConn.Write(req.SerializeRaw(&buf)); err != nil {
		log.Printf("proxy: failed to send TLS request: %v", err)
		if isTimeoutError(err) {
			h.sendError(clientConn, 504, "Gateway Timeout: write timeout")
		} else {
			h.sendError(clientConn, 502, "Bad Gateway: failed to send request")
		}
		h.storeEntry(target, req, nil, nil, startTime)
		return false
	}

	if h.timeouts.ReadTimeout > 0 {
		_ = upstreamConn.SetReadDeadline(time.Now().Add(h.timeouts.ReadTimeout))
	}

	interim, resp, err := readFinalResponse(upstreamReader, req.Method, func(ir *types.RawHTTP1Response) error {
		return h.forwardInterim(clientConn, ir)
	})
	if err != nil {
		log.Printf("proxy: failed to parse TLS response: %v", err)
		// Skip the synthetic error if interim responses already started the wire stream
		if len(interim) == 0 {
			if isTimeoutError(err) {
				h.sendError(clientConn, 504, "Gateway Timeout: read timeout")
			} else {
				h.sendError(clientConn, 502, "Bad Gateway: malformed response")
			}
		}
		h.storeEntry(target, req, nil, interim, startTime)
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
	if _, err := clientConn.Write(resp.SerializeRaw(&buf)); err != nil {
		log.Printf("proxy: failed to send TLS response to client: %v", err)
		return false
	}

	// Truncate bodies before storing in history
	if h.maxBodyBytes > 0 && len(req.Body) > h.maxBodyBytes {
		req.SetBody(req.Body[:h.maxBodyBytes])
	}
	if h.maxBodyBytes > 0 && len(resp.Body) > h.maxBodyBytes {
		resp.SetBody(resp.Body[:h.maxBodyBytes])
	}

	h.storeEntry(target, req, resp, interim, startTime)

	if resp.CloseDelimited {
		return false // mirror the origin's connection-close framing
	}
	connHeader := strings.ToLower(resp.GetHeader("Connection"))
	return connHeader != connectionClose
}

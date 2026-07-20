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

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
)

const (
	connectionClose = "close"
	versionHTTP11   = "HTTP/1.1"
)

type http1Handler struct {
	history             *HistoryStore
	maxBodyBytes        int
	ruleApplier         types.RuleApplier   // optional, nil means no rules applied
	responseInterceptor ResponseInterceptor // optional, nil means no interception
	reg                 *protocol.Registry
	timeouts            TimeoutConfig
	fullBuffer          bool // buffer whole bodies for rules instead of per-chunk streaming
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

		if !h.handleExchange(connCtx, clientConn, clientReader, h1Exchange{logParseErrors: true}) {
			return
		}
	}
}

// upstreamPair is an already-open upstream conn and its reader.
type upstreamPair struct {
	conn   net.Conn
	reader *bufio.Reader
}

// h1Exchange parameterizes one HTTP/1.1 exchange across the plain proxy path and the
// TLS-MITM tunnel path. target and upstream are preset on the TLS path; nil on the plain
// path, where the target is derived from the request and the upstream is dialed.
type h1Exchange struct {
	logParseErrors bool          // plain logs parse failures; TLS suppresses browser idle noise
	target         *types.Target // nil on plain path
	upstream       *upstreamPair // nil on plain path
}

// handleExchange processes one HTTP/1.1 request/response pair. Returns true to keep the
// client connection alive for another request, false to close.
func (h *http1Handler) handleExchange(ctx context.Context, clientConn net.Conn, clientReader *bufio.Reader, x h1Exchange) bool {
	startTime := time.Now()
	var buf bytes.Buffer

	req, headBareLF, headBareCR, err := parseRequestHead(clientReader)
	if err != nil {
		if errors.Is(err, ErrInvalidRequest) {
			if x.logParseErrors {
				log.Printf("proxy: failed to parse request: %v", err)
			}
			sendError(clientConn, 400, "Bad Request")
		}
		return false
	}

	// answer the expectation before the client sends its body
	var contResp *types.RawHTTP1Response
	if expectsContinue(req) {
		contResp = newContinueResponse(headBareLF)
		if werr := h.forwardInterim(clientConn, contResp); werr != nil {
			log.Printf("proxy: failed to send 100 Continue to client: %v", werr)
			return false
		}
		if perr := h.awaitBodyStart(clientConn, clientReader); perr != nil {
			if x.logParseErrors {
				log.Printf("proxy: client sent no body after 100 Continue: %v", perr)
			}
			return false
		}
	}
	if err = readRequestBodyInto(clientReader, req, false, headBareLF, headBareCR); err != nil {
		if x.logParseErrors {
			log.Printf("proxy: failed to read request body: %v", err)
		}
		return false
	}

	target := x.target
	if target == nil {
		if target, err = h.extractTarget(req); err != nil {
			log.Printf("proxy: failed to extract target: %v", err)
			sendError(clientConn, 400, "Bad Request: "+err.Error())
			return false
		}
		h.rewriteToOriginForm(req, target)
	}
	req.Protocol = types.ProtocolHTTP11

	// response interception before rules and upstream send
	if h.responseInterceptor != nil {
		if intercepted := h.responseInterceptor.InterceptRequest(
			strings.ToLower(target.Hostname), target.Port, PathWithoutQuery(req.Path), req.Method,
		); intercepted != nil {
			resp := BuildInterceptedH1Response(intercepted)
			if h.maxBodyBytes > 0 && len(req.Body) > h.maxBodyBytes {
				req.SetBody(req.Body[:h.maxBodyBytes])
			}
			h.storeEntry(target, req, resp, localInterim(contResp), startTime) // store before forward
			if h.timeouts.WriteTimeout > 0 {
				_ = clientConn.SetWriteDeadline(time.Now().Add(h.timeouts.WriteTimeout))
			}
			_, _ = clientConn.Write(resp.SerializeRaw(&buf))
			return strings.ToLower(resp.GetHeader("Connection")) != connectionClose
		}
	}

	// apply request rules before upgrade detection to affect the Upgrade header
	if h.ruleApplier != nil {
		req = h.ruleApplier.ApplyRequestRules(req)
	}

	uc := &protocol.UpgradeClaimCtx{Req: req, Target: target, Signal: "http_101"}
	if a, ok := h.reg.ClaimUpgrade(uc); ok {
		conns := protocol.UpgradeConns{ClientConn: clientConn, ClientReader: clientReader}
		if x.upstream != nil {
			conns.UpstreamConn = x.upstream.conn
			conns.UpstreamReader = x.upstream.reader
		}
		a.ServeUpgrade(ctx, uc, conns)
		return false // adapter takes over
	}

	// dial on the plain path; the TLS path reuses the pre-dialed tunnel upstream
	up := x.upstream
	if up == nil {
		upstreamAddr := fmt.Sprintf("%s:%d", target.Hostname, target.Port)
		dialer := net.Dialer{Timeout: h.timeouts.DialTimeout}
		upstreamConn, derr := dialer.DialContext(ctx, "tcp", upstreamAddr)
		if derr != nil {
			log.Printf("proxy: failed to connect to %s: %v", upstreamAddr, derr)
			if isTimeoutError(derr) {
				sendError(clientConn, 504, "Gateway Timeout: connection timeout")
			} else {
				sendError(clientConn, 502, "Bad Gateway: connection refused")
			}
			h.storeEntry(target, req, nil, localInterim(contResp), startTime)
			return false
		}
		defer func() { _ = upstreamConn.Close() }() // only close the conn we dialed
		up = &upstreamPair{conn: upstreamConn, reader: bufio.NewReader(upstreamConn)}
	}

	if h.timeouts.WriteTimeout > 0 {
		_ = up.conn.SetWriteDeadline(time.Now().Add(h.timeouts.WriteTimeout))
	}

	if _, err := up.conn.Write(req.SerializeRaw(&buf)); err != nil {
		log.Printf("proxy: failed to send request to %s: %v", target.Hostname, err)
		if isTimeoutError(err) {
			sendError(clientConn, 504, "Gateway Timeout: write timeout")
		} else {
			sendError(clientConn, 502, "Bad Gateway: failed to send request")
		}
		h.storeEntry(target, req, nil, localInterim(contResp), startTime)
		return false
	}

	if h.timeouts.ReadTimeout > 0 {
		_ = up.conn.SetReadDeadline(time.Now().Add(h.timeouts.ReadTimeout))
	}

	return h.streamResponse(clientConn, up.conn, up.reader, req, target, startTime, contResp)
}

// expectsContinue reports whether the client asked for an interim 100 Continue
// before sending a framed request body.
func expectsContinue(req *types.RawHTTP1Request) bool {
	if req.Version != versionHTTP11 || !hasExpectContinue(req.GetHeader("Expect")) {
		return false // RFC 9110: never send 100 to an HTTP/1.0 client
	} else if strings.Contains(strings.ToLower(req.GetHeader("Transfer-Encoding")), "chunked") {
		return true
	}
	cl, err := strconv.ParseInt(req.GetHeader("Content-Length"), 10, 64)
	return err == nil && cl > 0
}

// hasExpectContinue reports whether an Expect header value carries the
// 100-continue expectation among its comma-separated tokens.
func hasExpectContinue(expect string) bool {
	for token := range strings.SplitSeq(expect, ",") {
		if strings.EqualFold(strings.TrimSpace(token), "100-continue") {
			return true
		}
	}
	return false
}

// newContinueResponse builds the interim 100 Continue sent to the client,
// speaking bare LF when the client's request head did.
func newContinueResponse(bareLF bool) *types.RawHTTP1Response {
	resp := &types.RawHTTP1Response{Version: versionHTTP11, StatusCode: 100, StatusText: "Continue"}
	if bareLF {
		resp.StatusLineEnding = types.EndingBareLF
		resp.HeaderBlockEnding = types.EndingBareLF
	}
	return resp
}

// awaitBodyStart blocks for the first request-body byte, bounded by ReadTimeout
// (unbounded when 0), and returns the read error. Transfer duration stays
// unbounded once bytes flow.
func (h *http1Handler) awaitBodyStart(clientConn net.Conn, clientReader *bufio.Reader) error {
	if h.timeouts.ReadTimeout > 0 {
		_ = clientConn.SetReadDeadline(time.Now().Add(h.timeouts.ReadTimeout))
		defer func() { _ = clientConn.SetReadDeadline(time.Time{}) }()
	}
	_, err := clientReader.Peek(1)
	return err
}

// localInterim records the proxy-generated interim, or nil when resp is nil.
func localInterim(resp *types.RawHTTP1Response) []*types.InterimResponse {
	if resp == nil {
		return nil
	}
	return []*types.InterimResponse{{
		Message: types.ResponseToMessage(resp),
		Source:  types.InterimSourceProxy,
		Relayed: true,
	}}
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
func (h *http1Handler) storeEntry(target *types.Target, req *types.RawHTTP1Request, resp *types.RawHTTP1Response, interim []*types.InterimResponse, startTime time.Time) {
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
	flow.InterimResponses = interim
	if !h.history.ShouldCapture(flow) {
		return
	}
	h.history.Store(flow)
}

// streamResponse reads the upstream response head, then forwards the body to the
// client, buffering when body rules need the whole body and streaming per unit
// otherwise. The flow is persisted at head time and grown as the body arrives.
// contResp is the 100 Continue already sent to the client, or nil.
// Returns whether the client connection may be kept alive.
func (h *http1Handler) streamResponse(clientConn, upstreamConn net.Conn, upstreamReader *bufio.Reader, req *types.RawHTTP1Request, target *types.Target, startTime time.Time, contResp *types.RawHTTP1Response) bool {
	var upInterim []*types.InterimResponse
	var relayed bool // an upstream interim reached the client
	_, resp, bodyExpected, headBareLF, headBareCR, err := readFinalResponseHead(upstreamReader, req.Method, func(ir *types.RawHTTP1Response) error {
		var werr error
		var sent bool
		if contResp == nil || ir.StatusCode != 100 { // suppress a duplicate of the local 100
			werr = h.forwardInterim(clientConn, ir)
			sent = werr == nil
			relayed = relayed || sent
		}
		upInterim = append(upInterim, &types.InterimResponse{
			Message: types.ResponseToMessage(ir),
			Source:  types.InterimSourceOrigin,
			Relayed: sent,
		})
		return werr
	})
	interim := append(localInterim(contResp), upInterim...)
	if err != nil {
		log.Printf("proxy: failed to parse response from %s: %v", target.Hostname, err)
		// Skip the synthetic error if upstream interims already started the wire stream
		if !relayed {
			if isTimeoutError(err) {
				sendError(clientConn, 504, "Gateway Timeout: read timeout")
			} else {
				sendError(clientConn, 502, "Bad Gateway: malformed response")
			}
		}
		h.storeEntry(target, req, nil, interim, startTime)
		return false
	}

	hasBodyRules := h.ruleApplier != nil && h.ruleApplier.HasBodyRules(false)
	// Buffer when body rules need the whole body: full_buffer, or a framing where
	// per-unit mutation is unsafe (compressed, or Content-Length pinned on the wire).
	if !bodyExpected || (hasBodyRules && (h.fullBuffer || mustBufferResponse(resp))) {
		return h.forwardBuffered(clientConn, upstreamReader, resp, interim, req, target, startTime, bodyExpected, headBareLF, headBareCR)
	}
	return h.forwardStreaming(clientConn, upstreamConn, upstreamReader, resp, interim, req, target, startTime, hasBodyRules, headBareLF, headBareCR)
}

// mustBufferResponse reports whether a response with body rules must be fully
// buffered because per-unit rule application would be wrong: a compressed body
// (no fragment is independently decodable) or a Content-Length-framed body
// (whose length is already committed to the wire).
func mustBufferResponse(resp *types.RawHTTP1Response) bool {
	if resp.GetHeader("Content-Encoding") != "" {
		return true
	} else if strings.Contains(strings.ToLower(resp.GetHeader("Transfer-Encoding")), "chunked") {
		return false
	}
	cl := resp.GetHeader("Content-Length")
	if cl == "" {
		return false // close-delimited: length not pinned
	}
	n, perr := strconv.ParseInt(cl, 10, 64)
	return perr == nil && n >= 0
}

// forwardBuffered reads the whole response body, applies response rules, and
// forwards and stores it in one shot. Also handles bodyExpected=false (no body).
func (h *http1Handler) forwardBuffered(clientConn net.Conn, upstreamReader *bufio.Reader, resp *types.RawHTTP1Response, interim []*types.InterimResponse, req *types.RawHTTP1Request, target *types.Target, startTime time.Time, bodyExpected, usedBareLF, usedBareCR bool) bool {
	var wasChunked bool
	if bodyExpected {
		var trailersBareLF, trailersBareCR bool
		var rerr error
		if resp.Body, resp.Trailers, wasChunked, resp.Chunks, trailersBareLF, trailersBareCR, rerr = readResponseBodyWithWire(upstreamReader, resp, nil); rerr != nil && !errors.Is(rerr, io.EOF) {
			log.Printf("proxy: failed to read response body from %s: %v", target.Hostname, rerr)
			h.storeEntry(target, req, nil, interim, startTime)
			return false
		}
		chunksBareLF, chunksBareCR := chunksBareFlags(resp.Chunks)
		usedBareLF = usedBareLF || chunksBareLF || trailersBareLF
		usedBareCR = usedBareCR || chunksBareCR || trailersBareCR
	}
	if usedBareLF || usedBareCR || wasChunked {
		resp.Wire = &types.WireFormat{WasChunked: wasChunked, UsedBareLF: usedBareLF, UsedBareCR: usedBareCR}
	}

	if h.ruleApplier != nil {
		resp = h.ruleApplier.ApplyResponseRules(resp)
	}

	// Serialize before truncation so the stored cap doesn't affect the wire copy
	var buf bytes.Buffer
	respBytes := resp.SerializeRaw(&buf)

	h.capBody(req)
	if h.maxBodyBytes > 0 && len(resp.Body) > h.maxBodyBytes {
		resp.SetBody(resp.Body[:h.maxBodyBytes])
	}
	h.storeEntry(target, req, resp, interim, startTime)

	if h.timeouts.WriteTimeout > 0 {
		_ = clientConn.SetWriteDeadline(time.Now().Add(h.timeouts.WriteTimeout))
	}
	if _, werr := clientConn.Write(respBytes); werr != nil {
		log.Printf("proxy: failed to send response to client: %v", werr)
		return false
	}

	if resp.CloseDelimited {
		return false // mirror the origin's connection-close framing
	}
	return strings.ToLower(resp.GetHeader("Connection")) != connectionClose
}

// forwardStreaming writes the response head, then streams each body unit to the
// client while growing the stored flow. Body rules apply per unit (uncompressed
// chunked/close-delimited only). Returns whether keep-alive may continue.
func (h *http1Handler) forwardStreaming(clientConn, upstreamConn net.Conn, upstreamReader *bufio.Reader, resp *types.RawHTTP1Response, interim []*types.InterimResponse, req *types.RawHTTP1Request, target *types.Target, startTime time.Time, hasBodyRules, headBareLF, headBareCR bool) bool {
	if h.ruleApplier != nil {
		resp.Headers = h.ruleApplier.ApplyResponseHeaderOnlyRules(resp.Headers)
	}

	isChunked := strings.Contains(strings.ToLower(resp.GetHeader("Transfer-Encoding")), "chunked")
	if headBareLF || headBareCR || isChunked {
		resp.Wire = &types.WireFormat{WasChunked: isChunked, UsedBareLF: headBareLF, UsedBareCR: headBareCR}
	}

	// Store the head first so history is visible before the client sees bytes
	h.capBody(req)
	flowID, captured := h.storeStreamHead(target, req, resp, interim, startTime)

	// Forward the head to the client
	var headBuf bytes.Buffer
	if h.timeouts.WriteTimeout > 0 {
		_ = clientConn.SetWriteDeadline(time.Now().Add(h.timeouts.WriteTimeout))
	}
	if _, werr := clientConn.Write(resp.SerializeHead(&headBuf)); werr != nil {
		log.Printf("proxy: failed to send response head to client: %v", werr)
		if captured {
			h.completeStreamFlow(flowID, resp, nil, time.Now(), map[string]any{annStreamTruncated: true, annStreamReason: reasonClientDisconnect})
		}
		return false
	}

	var histBody bytes.Buffer
	var truncated bool
	throttle := newFlushThrottle()
	// client write failure; preferred over readErr to classify a disconnect
	var clientErr error

	onUnit := func(decoded, wire []byte) error {
		out := decoded
		if hasBodyRules {
			out = h.ruleApplier.ApplyResponseBodyOnlyRules(decoded, resp.Headers)
		}

		var toWrite []byte
		if isChunked {
			if hasBodyRules {
				var cbuf bytes.Buffer
				types.WriteChunk(&cbuf, out, "\r\n") // re-frame mutated data
				toWrite = cbuf.Bytes()
			} else {
				toWrite = wire // verbatim frame
			}
		} else {
			toWrite = out
		}

		if h.timeouts.WriteTimeout > 0 {
			_ = clientConn.SetWriteDeadline(time.Now().Add(h.timeouts.WriteTimeout))
		}
		if _, werr := clientConn.Write(toWrite); werr != nil {
			clientErr = werr
			return werr
		}

		// Refresh the upstream idle deadline per unit for long-lived streams
		if h.timeouts.ReadTimeout > 0 {
			_ = upstreamConn.SetReadDeadline(time.Now().Add(h.timeouts.ReadTimeout))
		}

		appendCapped(&histBody, out, h.maxBodyBytes, &truncated)
		if captured {
			now := time.Now()
			if throttle.should(histBody.Len(), now) {
				h.completeStreamFlow(flowID, resp, histBody.Bytes(), time.Time{}, nil)
				throttle.mark(histBody.Len(), now)
			}
		}
		return nil
	}

	_, trailers, _, chunks, _, _, readErr := readResponseBodyWithWire(upstreamReader, resp, onUnit)

	// Forward the chunked terminator (0-chunk + trailers)
	if isChunked && clientErr == nil {
		var tbuf bytes.Buffer
		if !hasBodyRules {
			if last := lastChunkFrame(chunks); last != nil {
				tbuf.Write(last.SizeLine)
				tbuf.WriteString(last.SizeEnding.Bytes())
				tbuf.Write(trailers)
				tbuf.WriteString(last.DataEnding.Bytes())
			} else {
				types.WriteLastChunk(&tbuf, trailers, "\r\n")
			}
		} else {
			types.WriteLastChunk(&tbuf, trailers, "\r\n")
		}
		if h.timeouts.WriteTimeout > 0 {
			_ = clientConn.SetWriteDeadline(time.Now().Add(h.timeouts.WriteTimeout))
		}
		if _, werr := clientConn.Write(tbuf.Bytes()); werr != nil {
			clientErr = werr
		}
	}

	if captured {
		resp.Trailers = trailers
		h.completeStreamFlow(flowID, resp, histBody.Bytes(), time.Now(), streamAnnotations(clientErr, readErr, truncated))
	}

	if clientErr != nil || resp.CloseDelimited {
		return false
	}
	return strings.ToLower(resp.GetHeader("Connection")) != connectionClose
}

// storeStreamHead persists the request and response head as an in-progress flow
// (zero CompletedAt), returning its flow_id and whether it was captured.
func (h *http1Handler) storeStreamHead(target *types.Target, req *types.RawHTTP1Request, resp *types.RawHTTP1Response, interim []*types.InterimResponse, startTime time.Time) (string, bool) {
	flow := &types.Flow{
		Adapter:     types.ProtocolHTTP11,
		ProtocolTag: types.ProtocolHTTP11,
		Scheme:      target.Scheme(),
		Port:        target.Port,
		Request:     types.RequestToMessage(req),
		Response:    types.ResponseToMessage(resp),
		StartedAt:   startTime,

		InterimResponses: interim,
	}
	if !h.history.ShouldCapture(flow) {
		return "", false
	}
	return h.history.Store(flow), true
}

// completeStreamFlow updates a stored streaming flow with the accumulated body.
// A non-zero completedAt marks the stream finished; nil body leaves it empty.
func (h *http1Handler) completeStreamFlow(flowID string, resp *types.RawHTTP1Response, body []byte, completedAt time.Time, annotations map[string]any) {
	msg := types.ResponseToMessage(resp)
	msg.Body = body
	msg.Chunks = nil // per-chunk framing is not retained for streamed bodies
	h.history.Complete(flowID, msg, completedAt, annotations)
}

// capBody truncates the stored request body to maxBodyBytes.
func (h *http1Handler) capBody(req *types.RawHTTP1Request) {
	if h.maxBodyBytes > 0 && len(req.Body) > h.maxBodyBytes {
		req.SetBody(req.Body[:h.maxBodyBytes])
	}
}

// appendCapped appends data to buf up to maxBytes, setting truncated when the cap
// is reached. maxBytes <= 0 means no limit.
func appendCapped(buf *bytes.Buffer, data []byte, maxBytes int, truncated *bool) {
	if maxBytes <= 0 {
		buf.Write(data)
		return
	}
	room := maxBytes - buf.Len()
	if room <= 0 {
		*truncated = true
		return
	}
	if len(data) > room {
		buf.Write(data[:room])
		*truncated = true
		return
	}
	buf.Write(data)
}

// lastChunkFrame returns the final recorded chunk frame, or nil when none.
func lastChunkFrame(chunks []types.ChunkFrame) *types.ChunkFrame {
	if len(chunks) == 0 {
		return nil
	}
	return &chunks[len(chunks)-1]
}

// streamAnnotations builds finalize-time annotations describing truncation.
func streamAnnotations(clientErr, readErr error, truncated bool) map[string]any {
	var reason string
	if clientErr != nil {
		reason = reasonClientDisconnect
	} else if readErr != nil && !errors.Is(readErr, io.EOF) {
		reason = reasonUpstreamError
	}
	return truncationAnnotations(reason, truncated)
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

		if !h.handleExchange(connCtx, clientConn, clientReader, h1Exchange{
			target:   target,
			upstream: &upstreamPair{conn: upstreamConn, reader: upstreamReader},
		}) {
			return
		}
	}
}

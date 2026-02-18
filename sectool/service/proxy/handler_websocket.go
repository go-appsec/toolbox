package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const maxWebSocketFrameSize = 100 * 1024 * 1024 // 100 MB

// webSocketHandler handles WebSocket proxying for both ws:// and wss://.
type webSocketHandler struct {
	history     *HistoryStore
	ruleApplier RuleApplier
	certManager *CertManager
	timeouts    TimeoutConfig
}

// newWebSocketHandler creates a new WebSocket handler.
func newWebSocketHandler(history *HistoryStore, certManager *CertManager, timeouts TimeoutConfig) *webSocketHandler {
	return &webSocketHandler{
		history:     history,
		certManager: certManager,
		timeouts:    timeouts,
	}
}

// SetRuleApplier sets the rule applier for WebSocket rules.
func (h *webSocketHandler) SetRuleApplier(applier RuleApplier) {
	h.ruleApplier = applier
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade.
func isWebSocketUpgrade(req *RawHTTP1Request) bool {
	upgrade := req.GetHeader("Upgrade")
	connection := req.GetHeader("Connection")
	return strings.EqualFold(upgrade, "websocket") &&
		strings.Contains(strings.ToLower(connection), "upgrade")
}

// Handle proxies a WebSocket connection (plain HTTP).
func (h *webSocketHandler) Handle(
	ctx context.Context,
	clientConn net.Conn,
	clientReader *bufio.Reader,
	req *RawHTTP1Request,
	target *Target,
) {
	startTime := time.Now()

	// Strip compression extensions so rules can be applied to uncompressed text
	h.stripExtensions(req)

	upstreamAddr := fmt.Sprintf("%s:%d", target.Hostname, target.Port)
	dialer := net.Dialer{Timeout: h.timeouts.DialTimeout}
	upstreamConn, err := dialer.DialContext(ctx, "tcp", upstreamAddr)
	if err != nil {
		log.Printf("proxy: websocket dial failed: %v", err)
		h.sendError(clientConn, 502, "Bad Gateway: connection refused")
		return
	}

	h.proxyWebSocket(ctx, clientConn, clientReader, upstreamConn, req, startTime)
}

// HandleTLS proxies a WebSocket connection over TLS by creating a new upstream connection.
// Use HandleTLSWithUpstream when an upstream connection already exists.
func (h *webSocketHandler) HandleTLS(
	ctx context.Context,
	clientConn net.Conn,
	clientReader *bufio.Reader,
	req *RawHTTP1Request,
	target *Target,
) {
	startTime := time.Now()

	h.stripExtensions(req)

	upstreamAddr := fmt.Sprintf("%s:%d", target.Hostname, target.Port)
	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: h.timeouts.DialTimeout},
		Config: &tls.Config{
			ServerName:         target.Hostname,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		},
	}
	upstreamConn, err := tlsDialer.DialContext(ctx, "tcp", upstreamAddr)
	if err != nil {
		log.Printf("proxy: websocket TLS dial failed: %v", err)
		h.sendError(clientConn, 502, "Bad Gateway: connection refused")
		return
	}

	h.proxyWebSocket(ctx, clientConn, clientReader, upstreamConn, req, startTime)
}

// HandleTLSWithUpstream proxies a WebSocket connection using an existing upstream TLS connection.
// This avoids the race window of closing and reopening the upstream connection.
func (h *webSocketHandler) HandleTLSWithUpstream(
	ctx context.Context,
	clientConn net.Conn,
	clientReader *bufio.Reader,
	upstreamConn net.Conn,
	upstreamReader *bufio.Reader,
	req *RawHTTP1Request,
) {
	startTime := time.Now()

	h.stripExtensions(req)

	h.proxyWebSocketWithReader(ctx, clientConn, clientReader, upstreamConn, upstreamReader, req, startTime)
}

// proxyWebSocket handles the WebSocket upgrade and frame proxying.
// Creates its own upstream reader.
func (h *webSocketHandler) proxyWebSocket(
	ctx context.Context,
	clientConn net.Conn,
	clientReader *bufio.Reader,
	upstreamConn net.Conn,
	req *RawHTTP1Request,
	startTime time.Time,
) {
	upstreamReader := bufio.NewReader(upstreamConn)
	h.proxyWebSocketWithReader(ctx, clientConn, clientReader, upstreamConn, upstreamReader, req, startTime)
}

// proxyWebSocketWithReader handles WebSocket upgrade and frame proxying with existing readers.
func (h *webSocketHandler) proxyWebSocketWithReader(
	ctx context.Context,
	clientConn net.Conn,
	clientReader *bufio.Reader,
	upstreamConn net.Conn,
	upstreamReader *bufio.Reader,
	req *RawHTTP1Request,
	startTime time.Time,
) {
	defer func() { _ = upstreamConn.Close() }()

	var buf bytes.Buffer

	// Forward upgrade request to upstream
	if _, err := upstreamConn.Write(req.SerializeRaw(&buf, false)); err != nil {
		log.Printf("proxy: websocket upgrade send failed: %v", err)
		h.sendError(clientConn, 502, "Bad Gateway: failed to send upgrade")
		return
	}

	// Read upstream response
	resp, err := parseResponse(upstreamReader, req.Method)
	if err != nil {
		log.Printf("proxy: websocket upgrade response parse failed: %v", err)
		h.sendError(clientConn, 502, "Bad Gateway: malformed response")
		return
	}

	// Check for 101 Switching Protocols
	if resp.StatusCode != 101 {
		// Apply response rules to error response
		if h.ruleApplier != nil {
			resp = h.ruleApplier.ApplyResponseRules(resp)
		}
		// Forward error response to client
		if _, err := clientConn.Write(resp.SerializeRaw(&buf, false)); err != nil {
			log.Printf("proxy: failed to send websocket error response: %v", err)
		}
		// Store failed upgrade in history
		h.storeHandshake(req, resp, startTime)
		return
	}

	// Apply response rules before stripping extensions
	if h.ruleApplier != nil {
		resp = h.ruleApplier.ApplyResponseRules(resp)
	}

	// Strip extensions from response (after rules, to ensure no compression)
	h.stripResponseExtensions(resp)

	// Store upgrade handshake in history and get reference for frame storage
	historyEntry := h.storeHandshake(req, resp, startTime)

	// Send 101 to client
	if _, err := clientConn.Write(resp.SerializeRaw(&buf, false)); err != nil {
		log.Printf("proxy: failed to send websocket upgrade response: %v", err)
		return
	}

	// Start bidirectional frame proxy
	proxy := &wsProxy{
		handler:      h,
		historyEntry: historyEntry,
		clientConn:   clientConn,
		clientBuf:    clientReader,
		upstreamConn: upstreamConn,
		upstreamBuf:  upstreamReader,
		done:         make(chan struct{}),
	}
	proxy.run()
}

// stripExtensions removes Sec-WebSocket-Extensions header to disable compression.
func (h *webSocketHandler) stripExtensions(req *RawHTTP1Request) {
	req.RemoveHeader("Sec-WebSocket-Extensions")
}

// stripResponseExtensions removes Sec-WebSocket-Extensions from response.
func (h *webSocketHandler) stripResponseExtensions(resp *RawHTTP1Response) {
	resp.RemoveHeader("Sec-WebSocket-Extensions")
}

// sendError writes an HTTP error response.
func (h *webSocketHandler) sendError(conn net.Conn, code int, message string) {
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

// storeHandshake stores the WebSocket upgrade handshake in history.
// Returns the entry so frames can be appended to it, or nil if filtered.
func (h *webSocketHandler) storeHandshake(req *RawHTTP1Request, resp *RawHTTP1Response, startTime time.Time) *HistoryEntry {
	entry := &HistoryEntry{
		Protocol:  "websocket",
		Request:   req,
		Response:  resp,
		Timestamp: startTime,
		Duration:  time.Since(startTime),
	}
	if !h.history.ShouldCapture(entry) {
		return nil
	}
	h.history.Store(entry)
	return entry
}

// =============================================================================
// WebSocket Frame Proxy
// =============================================================================

// wsProxy handles bidirectional WebSocket frame proxying.
type wsProxy struct {
	handler      *webSocketHandler
	historyEntry *HistoryEntry // handshake entry where frames are appended
	entryMu      sync.Mutex    // protects historyEntry.WSFrames
	clientConn   net.Conn
	clientBuf    *bufio.Reader
	upstreamConn net.Conn
	upstreamBuf  *bufio.Reader
	closeOnce    sync.Once
	done         chan struct{}
}

func (p *wsProxy) run() {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client → Upstream: proxy acts as client, MUST mask per RFC 6455 §5.1
	go func() {
		defer wg.Done()
		p.proxyFrames(p.clientBuf, p.upstreamConn, "ws:to-server", true)
	}()

	// Upstream → Client: proxy acts as server, MUST NOT mask per RFC 6455 §5.1
	go func() {
		defer wg.Done()
		p.proxyFrames(p.upstreamBuf, p.clientConn, "ws:to-client", false)
	}()

	wg.Wait()
	p.close()
}

// proxyFrames reads frames from src and writes to dst.
// outputMasked controls masking per RFC 6455 (true for client→upstream, false for server→client).
// Rules apply only to complete, uncompressed text frames (opcode=1, fin=true, rsv=0).
func (p *wsProxy) proxyFrames(src *bufio.Reader, dst net.Conn, direction string, outputMasked bool) {
	for {
		select {
		case <-p.done:
			return
		default:
		}

		frame, err := readWSFrame(src)
		if err != nil {
			p.close()
			return
		}

		// Apply rules only to complete, uncompressed text frames
		if frame.opcode == 1 && frame.fin && frame.rsv == 0 {
			if p.handler.ruleApplier != nil {
				frame.payload = p.handler.ruleApplier.ApplyWSRules(frame.payload, direction)
			}
		}

		// Store frame in history
		p.storeFrame(frame, direction)

		// Set masking for output per RFC 6455
		frame.masked = outputMasked
		if outputMasked {
			// Generate fresh random mask for outgoing masked frames
			if _, err := io.ReadFull(rand.Reader, frame.mask[:]); err != nil {
				p.close()
				return
			}
		}

		encoded := encodeWSFrame(frame)
		if _, err := dst.Write(encoded); err != nil {
			p.close()
			return
		}

		// Handle close frame (opcode 8)
		if frame.opcode == 8 {
			p.close()
			return
		}
	}
}

// storeFrame appends a WebSocket frame to the handshake's history entry.
func (p *wsProxy) storeFrame(frame *wsFrame, direction string) {
	if p.historyEntry == nil {
		return
	}

	// Strip "ws:" prefix from direction for storage (e.g., "ws:to-server" → "to-server")
	dir := direction
	if len(dir) > 3 && dir[:3] == "ws:" {
		dir = dir[3:]
	}

	wsFrame := WSFrame{
		Direction: dir,
		Opcode:    frame.opcode,
		Payload:   frame.payload,
		Timestamp: time.Now(),
	}

	p.entryMu.Lock()
	p.historyEntry.WSFrames = append(p.historyEntry.WSFrames, wsFrame)
	// Update while holding lock to prevent concurrent reads during marshaling
	p.handler.history.Update(p.historyEntry)
	p.entryMu.Unlock()
}

func (p *wsProxy) close() {
	p.closeOnce.Do(func() {
		close(p.done)
		_ = p.clientConn.Close()
		_ = p.upstreamConn.Close()
	})
}

// =============================================================================
// WebSocket Frame Types
// =============================================================================

// wsFrame represents a WebSocket frame.
type wsFrame struct {
	fin     bool
	rsv     byte // RSV1, RSV2, RSV3 bits
	opcode  byte
	masked  bool
	mask    [4]byte
	payload []byte
}

// readWSFrame reads a single WebSocket frame from the reader.
func readWSFrame(r io.Reader) (*wsFrame, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	frame := &wsFrame{
		fin:    header[0]&0x80 != 0,
		rsv:    (header[0] >> 4) & 0x07,
		opcode: header[0] & 0x0F,
		masked: header[1]&0x80 != 0,
	}

	length := uint64(header[1] & 0x7F)
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		length = binary.BigEndian.Uint64(ext)
	}

	if length > maxWebSocketFrameSize {
		return nil, fmt.Errorf("frame payload too large: %d bytes (max %d)", length, maxWebSocketFrameSize)
	}

	if frame.masked {
		if _, err := io.ReadFull(r, frame.mask[:]); err != nil {
			return nil, err
		}
	}

	frame.payload = make([]byte, length)
	if _, err := io.ReadFull(r, frame.payload); err != nil {
		return nil, err
	}

	// Unmask payload
	if frame.masked {
		for i := range frame.payload {
			frame.payload[i] ^= frame.mask[i%4]
		}
	}

	return frame, nil
}

// encodeWSFrame encodes a WebSocket frame to bytes.
func encodeWSFrame(frame *wsFrame) []byte {
	var buf bytes.Buffer

	// First byte: FIN + RSV + opcode
	firstByte := frame.opcode | (frame.rsv << 4)
	if frame.fin {
		firstByte |= 0x80
	}
	buf.WriteByte(firstByte)

	// Second byte: mask flag + length
	length := len(frame.payload)
	var secondByte byte
	if frame.masked {
		secondByte |= 0x80
	}

	if length <= 125 {
		secondByte |= byte(length)
		buf.WriteByte(secondByte)
	} else if length <= 65535 {
		secondByte |= 126
		buf.WriteByte(secondByte)
		_ = binary.Write(&buf, binary.BigEndian, uint16(length))
	} else {
		secondByte |= 127
		buf.WriteByte(secondByte)
		_ = binary.Write(&buf, binary.BigEndian, uint64(length))
	}

	// Mask key and masked payload (if masked)
	if frame.masked {
		buf.Write(frame.mask[:])
		masked := make([]byte, length)
		for i := range frame.payload {
			masked[i] = frame.payload[i] ^ frame.mask[i%4]
		}
		buf.Write(masked)
	} else {
		buf.Write(frame.payload)
	}

	return buf.Bytes()
}

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-analyze/bulk"
	"golang.org/x/net/http2"
)

const (
	// protocolH2 is the protocol string for HTTP/2
	protocolH2 = "h2"

	// initialWindowSize is the HTTP/2 default window (64KB)
	initialWindowSize = 65535
	streamIdleTimeout = 5 * time.Minute
	cleanupInterval   = 1 * time.Minute
	h2Preface         = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
)

// streamState represents the state of an HTTP/2 stream
type streamState int

const (
	streamOpen streamState = iota
	streamHalfClosedLocal
	streamHalfClosedRemote
	streamClosed
)

// http2Handler handles HTTP/2 MITM interception.
type http2Handler struct {
	history      *HistoryStore
	ruleApplier  RuleApplier
	maxBodyBytes int
	timeouts     TimeoutConfig
}

// newHTTP2Handler creates a new HTTP/2 handler.
func newHTTP2Handler(history *HistoryStore, maxBodyBytes int, timeouts TimeoutConfig) *http2Handler {
	return &http2Handler{
		history:      history,
		maxBodyBytes: maxBodyBytes,
		timeouts:     timeouts,
	}
}

// SetRuleApplier sets the rule applier for header and body modifications.
func (h *http2Handler) SetRuleApplier(applier RuleApplier) {
	h.ruleApplier = applier
}

// h2Stream tracks the state of a single HTTP/2 stream.
// All mutable fields are protected by mu to prevent data races.
type h2Stream struct {
	mu sync.Mutex
	id uint32

	state streamState

	// Request data accumulated from HEADERS + DATA frames
	method     string
	scheme     string
	authority  string
	path       string
	reqHeaders Headers
	reqBody    bytes.Buffer // history capture (limited to maxBodyBytes)

	// Response data
	statusCode  int
	respHeaders Headers
	respBody    bytes.Buffer // history capture (limited to maxBodyBytes)

	// Full body buffers for body rule application (when rules exist)
	// These hold the complete body (up to maxBodyBytes) for modification
	reqBodyFull  bytes.Buffer
	respBodyFull bytes.Buffer

	// Overflow flags: set when body exceeds maxBodyBytes, triggering
	// fallback to streaming passthrough (body rules skipped, no truncation)
	reqBodyOverflow  bool
	respBodyOverflow bool

	// Timing
	startTime    time.Time
	lastActivity time.Time

	// Flow control
	window int32

	// Buffering for body rules
	reqBodyComplete  bool
	respBodyComplete bool
}

// markEndStream updates stream state for END_STREAM flag.
// Returns true if stream is now fully closed. Caller must hold stream.mu.
func (s *h2Stream) markEndStream(fromClient bool) bool {
	if fromClient {
		s.reqBodyComplete = true
		if s.state == streamHalfClosedRemote {
			s.state = streamClosed
		} else {
			s.state = streamHalfClosedLocal
		}
	} else {
		s.respBodyComplete = true
		if s.state == streamHalfClosedLocal {
			s.state = streamClosed
		} else {
			s.state = streamHalfClosedRemote
		}
	}
	return s.state == streamClosed
}

// h2StreamTracker provides thread-safe stream management.
type h2StreamTracker struct {
	mu      sync.RWMutex
	streams map[uint32]*h2Stream
}

func newStreamTracker() *h2StreamTracker {
	return &h2StreamTracker{
		streams: make(map[uint32]*h2Stream),
	}
}

func (t *h2StreamTracker) get(id uint32) (*h2Stream, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	s, ok := t.streams[id]
	return s, ok
}

func (t *h2StreamTracker) getOrCreate(id uint32) *h2Stream {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s, ok := t.streams[id]; ok {
		return s
	}
	s := &h2Stream{
		id:           id,
		state:        streamOpen,
		startTime:    time.Now(),
		lastActivity: time.Now(),
		window:       initialWindowSize,
	}
	t.streams[id] = s
	return s
}

func (t *h2StreamTracker) remove(id uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.streams, id)
}

func (t *h2StreamTracker) all() []*h2Stream {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return bulk.MapValuesSlice(t.streams)
}

// h2Proxy manages the HTTP/2 proxying between client and upstream.
type h2Proxy struct {
	handler  *http2Handler
	client   *h2Conn
	upstream *h2Conn
	streams  *h2StreamTracker
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	// Header block accumulation for CONTINUATION frames (HEADERS)
	clientHeaderBuf         bytes.Buffer
	clientHeaderStream      uint32
	clientHeaderEndStream   bool // END_STREAM flag from HEADERS frame
	upstreamHeaderBuf       bytes.Buffer
	upstreamHeaderStream    uint32
	upstreamHeaderEndStream bool // END_STREAM flag from HEADERS frame

	// PUSH_PROMISE accumulation (upstream only; decode to maintain HPACK state)
	upstreamPushBuf       bytes.Buffer
	upstreamPushStream    uint32 // originating stream ID for CONTINUATION
	upstreamPushPromiseID uint32 // promised stream ID
	upstreamPushActive    bool   // true if accumulating PUSH_PROMISE headers
}

// Handle proxies HTTP/2 traffic between client and upstream connections.
func (h *http2Handler) Handle(ctx context.Context, clientConn, upstreamConn *tls.Conn) {
	proxyCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Close connections when context is cancelled to unblock blocking reads.
	// ReadFrame doesn't accept context, so closing is the only way to interrupt it.
	go func() {
		<-ctx.Done()
		_ = clientConn.Close()
		_ = upstreamConn.Close()
	}()

	proxy := &h2Proxy{
		handler:  h,
		client:   newH2Conn(clientConn),
		upstream: newH2Conn(upstreamConn),
		streams:  newStreamTracker(),
		ctx:      proxyCtx,
		cancel:   cancel,
	}

	// Read and validate client preface
	preface := make([]byte, len(h2Preface))
	if _, err := io.ReadFull(clientConn, preface); err != nil {
		log.Printf("h2: failed to read client preface: %v", err)
		return
	}
	if string(preface) != h2Preface {
		log.Printf("h2: invalid client preface")
		return
	}

	// Send preface to upstream
	if _, err := upstreamConn.Write([]byte(h2Preface)); err != nil {
		log.Printf("h2: failed to send upstream preface: %v", err)
		return
	}

	// Exchange SETTINGS frames
	if err := proxy.exchangeSettings(); err != nil {
		log.Printf("h2: SETTINGS exchange failed: %v", err)
		return
	}

	// Start frame processing goroutines
	proxy.wg.Add(4)
	go proxy.readFrames(true) // read from client
	go proxy.writeFrames(proxy.client, clientConn)
	go proxy.readFrames(false) // read from upstream
	go proxy.writeFrames(proxy.upstream, upstreamConn)

	// Start cleanup goroutine
	go proxy.cleanupStaleStreams()

	// Wait for completion
	proxy.wg.Wait()
}

// exchangeSettings performs the initial SETTINGS exchange.
// Send SETTINGS to upstream before reading to avoid deadlock (some servers
// won't send SETTINGS until they receive client's SETTINGS).
func (p *h2Proxy) exchangeSettings() error {
	// Read client SETTINGS (client sends immediately after preface)
	clientSettings, clientGotSettings, err := p.readSettingsFrame(p.client)
	if err != nil {
		return err
	}
	if clientGotSettings {
		p.client.updateSettings(clientSettings)
		for _, s := range clientSettings {
			if s.ID == http2.SettingInitialWindowSize {
				p.client.updateSendWindowFromSettings(s.Val)
				break
			}
		}
	}

	// Send our SETTINGS to upstream BEFORE reading upstream SETTINGS
	// This prevents deadlock when server waits for client SETTINGS before sending its own
	ourSettings := []http2.Setting{
		{ID: http2.SettingMaxHeaderListSize, Val: maxHeaderListSize},
		{ID: http2.SettingInitialWindowSize, Val: initialWindowSize},
		{ID: http2.SettingEnablePush, Val: 0}, // disable server push
	}
	var buf bytes.Buffer
	if err := p.writeSettingsFrame(&buf, p.upstream.conn, ourSettings); err != nil {
		return err
	}

	// Now safe to read upstream SETTINGS (server has received our SETTINGS)
	upstreamSettings, upstreamGotSettings, err := p.readSettingsFrame(p.upstream)
	if err != nil {
		return err
	}
	if upstreamGotSettings {
		p.upstream.updateSettings(upstreamSettings)
		for _, s := range upstreamSettings {
			if s.ID == http2.SettingInitialWindowSize {
				p.upstream.updateSendWindowFromSettings(s.Val)
				break
			}
		}
	}

	// Send our SETTINGS to client (endpoint model: never relay peer SETTINGS across hops)
	if err := p.writeSettingsFrame(&buf, p.client.conn, ourSettings); err != nil {
		return err
	}

	// Send SETTINGS ACKs only if we received SETTINGS (per RFC 9113 Section 6.5)
	if clientGotSettings {
		if err := p.writeSettingsAck(&buf, p.client.conn); err != nil {
			return err
		}
	}
	if upstreamGotSettings {
		if err := p.writeSettingsAck(&buf, p.upstream.conn); err != nil {
			return err
		}
	}

	return nil
}

// readSettingsFrame reads the first SETTINGS frame from a connection.
// Returns the settings, whether a SETTINGS frame was received, and any error.
func (p *h2Proxy) readSettingsFrame(h *h2Conn) ([]http2.Setting, bool, error) {
	frame, err := h.framer.ReadFrame()
	if err != nil {
		return nil, false, err
	}

	sf, ok := frame.(*http2.SettingsFrame)
	if !ok {
		// First frame should be SETTINGS, but be tolerant
		log.Printf("h2: expected SETTINGS frame, got %T", frame)
		return nil, false, nil
	}

	if sf.IsAck() {
		return nil, false, nil
	}

	settings := make([]http2.Setting, 0, sf.NumSettings())
	_ = sf.ForeachSetting(func(s http2.Setting) error {
		settings = append(settings, s)
		return nil
	})

	return settings, true, nil
}

// writeSettingsFrame writes a SETTINGS frame.
func (p *h2Proxy) writeSettingsFrame(buf *bytes.Buffer, conn net.Conn, settings []http2.Setting) error {
	buf.Reset()
	framer := http2.NewFramer(buf, nil)

	if err := framer.WriteSettings(settings...); err != nil {
		return err
	}

	_, err := conn.Write(buf.Bytes())
	return err
}

// writeSettingsAck writes a SETTINGS ACK frame.
func (p *h2Proxy) writeSettingsAck(buf *bytes.Buffer, conn net.Conn) error {
	buf.Reset()
	framer := http2.NewFramer(buf, nil)

	if err := framer.WriteSettingsAck(); err != nil {
		return err
	}

	_, err := conn.Write(buf.Bytes())
	return err
}

// readFrames reads frames from one side and processes them.
func (p *h2Proxy) readFrames(fromClient bool) {
	defer p.wg.Done()
	defer p.cancel()

	var src, dst *h2Conn
	var headerBuf *bytes.Buffer
	var headerStream *uint32
	var headerEndStream *bool

	if fromClient {
		src = p.client
		dst = p.upstream
		headerBuf = &p.clientHeaderBuf
		headerStream = &p.clientHeaderStream
		headerEndStream = &p.clientHeaderEndStream
	} else {
		src = p.upstream
		dst = p.client
		headerBuf = &p.upstreamHeaderBuf
		headerStream = &p.upstreamHeaderStream
		headerEndStream = &p.upstreamHeaderEndStream
	}

	var buf bytes.Buffer
	for {
		select {
		case <-p.ctx.Done():
			return
		default:
		}

		// Release large buffers to avoid holding memory for connection lifetime
		if buf.Cap() > 64*1024 {
			buf = bytes.Buffer{}
		}

		frame, err := src.framer.ReadFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("h2: read frame error (%v): %v", fromClient, err)
			}
			return
		}

		switch f := frame.(type) {
		case *http2.HeadersFrame:
			p.handleHeadersFrame(&buf, f, src, dst, fromClient, headerBuf, headerStream, headerEndStream)

		case *http2.ContinuationFrame:
			p.handleContinuationFrame(&buf, f, src, dst, fromClient, headerBuf, headerStream, headerEndStream)

		case *http2.DataFrame:
			p.handleDataFrame(&buf, f, src, dst, fromClient)

		case *http2.SettingsFrame:
			p.handleSettingsFrame(&buf, f, src, dst)

		case *http2.WindowUpdateFrame:
			p.handleWindowUpdate(f, src)

		case *http2.PingFrame:
			p.handlePingFrame(&buf, f, src, dst)

		case *http2.GoAwayFrame:
			p.handleGoAwayFrame(&buf, f, dst)
			return

		case *http2.RSTStreamFrame:
			p.handleRSTStreamFrame(&buf, f, dst)

		case *http2.PriorityFrame:
			p.forwardPriorityFrame(&buf, f, dst)

		case *http2.PushPromiseFrame:
			// Server push disabled; decode HPACK block to maintain compression state
			if !fromClient {
				p.handlePushPromiseFrame(f, src)
			}

		default:
			// Forward unknown/extension frames transparently
			p.forwardUnknownFrame(&buf, frame, dst)
		}
	}
}

// handleHeadersFrame processes a HEADERS frame.
func (p *h2Proxy) handleHeadersFrame(buf *bytes.Buffer, f *http2.HeadersFrame, src, dst *h2Conn, fromClient bool, headerBuf *bytes.Buffer, headerStream *uint32, headerEndStream *bool) {
	streamID := f.StreamID

	// Start accumulating header block
	headerBuf.Reset()
	headerBuf.Write(f.HeaderBlockFragment())
	*headerStream = streamID
	*headerEndStream = f.StreamEnded() // Save END_STREAM flag for CONTINUATION

	// Check size limit (also enforced in handleContinuationFrame for accumulated blocks)
	if headerBuf.Len() > maxHeaderBlockSize {
		log.Printf("h2: header block too large (%d bytes), sending GOAWAY to offending peer", headerBuf.Len())
		// Send GOAWAY to the source (peer that sent invalid data), then close both
		p.sendGoAway(src, 0, http2.ErrCodeEnhanceYourCalm, "header block too large")
		p.cancel()
		return
	}

	if f.HeadersEnded() {
		p.processHeaders(buf, streamID, headerBuf.Bytes(), src, dst, fromClient, *headerEndStream)
		headerBuf.Reset()
	}
}

// handleContinuationFrame processes a CONTINUATION frame.
func (p *h2Proxy) handleContinuationFrame(buf *bytes.Buffer, f *http2.ContinuationFrame, src, dst *h2Conn, fromClient bool, headerBuf *bytes.Buffer, headerStream *uint32, headerEndStream *bool) {
	// Check if this CONTINUATION is for a PUSH_PROMISE (upstream only)
	if !fromClient && p.upstreamPushActive && f.StreamID == p.upstreamPushStream {
		// This is a PUSH_PROMISE continuation
		p.upstreamPushBuf.Write(f.HeaderBlockFragment())

		// Check size limit
		if p.upstreamPushBuf.Len() > maxHeaderBlockSize {
			log.Printf("h2: PUSH_PROMISE header block too large (%d bytes), dropping", p.upstreamPushBuf.Len())
			p.upstreamPushBuf.Reset()
			p.upstreamPushActive = false
			return
		}

		if f.HeadersEnded() {
			// Complete - decode to maintain HPACK state
			p.decodePushPromise(src)
		}
		return
	}

	// Regular HEADERS continuation
	if f.StreamID != *headerStream {
		// Stream mismatch is a connection error per RFC 9113 Section 4.3.
		// HPACK state would become desynchronized if we continue.
		log.Printf("h2: CONTINUATION stream mismatch: expected %d, got %d, sending GOAWAY", *headerStream, f.StreamID)
		p.sendGoAway(src, 0, http2.ErrCodeProtocol, "CONTINUATION stream mismatch")
		p.cancel()
		return
	}

	headerBuf.Write(f.HeaderBlockFragment())

	// Check size limit
	if headerBuf.Len() > maxHeaderBlockSize {
		log.Printf("h2: header block too large (%d bytes), sending GOAWAY to offending peer", headerBuf.Len())
		// Send GOAWAY to the source (peer that sent invalid data), then close both
		p.sendGoAway(src, 0, http2.ErrCodeEnhanceYourCalm, "header block too large")
		p.cancel()
		return
	}

	if f.HeadersEnded() {
		// Use the END_STREAM flag saved from the HEADERS frame
		p.processHeaders(buf, *headerStream, headerBuf.Bytes(), src, dst, fromClient, *headerEndStream)
		headerBuf.Reset()
	}
}

// processHeaders decodes, applies rules, re-encodes, and forwards headers.
func (p *h2Proxy) processHeaders(buf *bytes.Buffer, streamID uint32, block []byte, src, dst *h2Conn, fromClient bool, endStream bool) {
	// Decode HPACK
	pseudos, headers, err := src.decodeHeaders(block)
	if err != nil {
		log.Printf("h2: HPACK decode error: %v, sending GOAWAY to offending peer", err)
		// Send GOAWAY to the source (peer that sent corrupted HPACK), then close both
		p.sendGoAway(src, 0, http2.ErrCodeCompression, "HPACK decode error")
		p.cancel()
		return
	}

	// Enforce maxHeaderListSize after decode (per RFC 7541 Section 4.1)
	listSize := headerListSize(pseudos, headers)
	if listSize > maxHeaderListSize {
		log.Printf("h2: header list size %d exceeds max %d, sending GOAWAY", listSize, maxHeaderListSize)
		p.sendGoAway(src, 0, http2.ErrCodeEnhanceYourCalm, "header list too large")
		p.cancel()
		return
	}

	// Track stream state
	stream := p.streams.getOrCreate(streamID)

	// Detect trailer HEADERS: no pseudo-headers means these are trailers
	// Trailers come after the message body and should be appended, not overwrite
	isTrailer := len(pseudos) == 0

	// Lock stream for all modifications
	stream.mu.Lock()
	stream.lastActivity = time.Now()

	if fromClient {
		if isTrailer {
			// Trailer headers: append to existing request headers, don't overwrite pseudo-headers
			stream.reqHeaders = append(stream.reqHeaders, headers...)
		} else {
			// Initial request headers: store pseudo-headers
			stream.method = pseudos[":method"]
			stream.scheme = pseudos[":scheme"]
			stream.authority = pseudos[":authority"]
			stream.path = pseudos[":path"]

			// Apply request header rules
			if p.handler.ruleApplier != nil {
				// Convert to RawHTTP1Request for rule application
				pathPart, queryPart, _ := strings.Cut(stream.path, "?")
				req := &RawHTTP1Request{
					Method:  stream.method,
					Path:    pathPart,
					Query:   queryPart,
					Headers: headers,
				}
				req = p.handler.ruleApplier.ApplyRequestRules(req)
				headers = req.Headers
			}

			// Strip content-length if body rules may modify payload length
			if !endStream && p.handler.ruleApplier != nil && p.handler.ruleApplier.HasBodyRules(true) {
				headers.Remove("content-length")
			}

			// Store post-rule headers for history
			stream.reqHeaders = headers
		}
	} else {
		if isTrailer {
			// Trailer headers: append to existing response headers, don't overwrite status
			stream.respHeaders = append(stream.respHeaders, headers...)
		} else {
			// Initial response headers: store status
			if status, ok := pseudos[":status"]; ok {
				stream.statusCode, _ = strconv.Atoi(status)
			}

			// Apply response header rules
			if p.handler.ruleApplier != nil {
				resp := &RawHTTP1Response{
					StatusCode: stream.statusCode,
					Headers:    headers,
				}
				resp = p.handler.ruleApplier.ApplyResponseRules(resp)
				headers = resp.Headers
			}

			// Strip content-length if body rules may modify payload length
			if !endStream && p.handler.ruleApplier != nil && p.handler.ruleApplier.HasBodyRules(false) {
				headers.Remove("content-length")
			}

			// Store post-rule headers for history
			stream.respHeaders = headers
		}
	}

	// Flush buffered body before trailers (handles gRPC where END_STREAM is on trailers)
	if isTrailer && endStream {
		hasBodyRules := p.handler.ruleApplier != nil && p.handler.ruleApplier.HasBodyRules(fromClient)
		if hasBodyRules {
			var bufferedBody []byte
			if fromClient && stream.reqBodyFull.Len() > 0 && !stream.reqBodyOverflow {
				bufferedBody = stream.reqBodyFull.Bytes()
			} else if !fromClient && stream.respBodyFull.Len() > 0 && !stream.respBodyOverflow {
				bufferedBody = stream.respBodyFull.Bytes()
			}

			if len(bufferedBody) > 0 {
				// Release lock for I/O operations
				stream.mu.Unlock()
				body, err := p.applyBodyRules(stream, bufferedBody, fromClient)
				if err != nil {
					log.Printf("h2: body rule application failed: %v", err)
					// Send RST_STREAM to destination to signal error
					p.sendRSTStream(buf, dst, streamID, http2.ErrCodeInternal)
					p.cleanupStream(streamID)
					return
				}
				p.writeDataFrame(buf, dst, streamID, body, false) // trailers carry END_STREAM, not DATA
				stream.mu.Lock()
				p.updateHistoryWithModifiedBodyLocked(stream, body, fromClient)
			}
		}
	}

	// Update stream state for END_STREAM
	var isStreamClosed bool
	if endStream {
		isStreamClosed = stream.markEndStream(fromClient)
	}
	stream.mu.Unlock()

	// Re-encode headers
	encoded, err := dst.encodeHeaders(pseudos, headers)
	if err != nil {
		log.Printf("h2: HPACK encode error: %v", err)
		return
	}

	// Write HEADERS frame
	p.writeHeadersFrame(buf, dst, streamID, encoded, endStream)

	// Check if stream is complete (after unlock to avoid holding lock during history store)
	if isStreamClosed {
		p.storeStreamInHistory(stream)
		p.cleanupStream(streamID)
	}
}

// handleDataFrame processes a DATA frame.
func (p *h2Proxy) handleDataFrame(buf *bytes.Buffer, f *http2.DataFrame, src, dst *h2Conn, fromClient bool) {
	streamID := f.StreamID
	data := f.Data()
	endStream := f.StreamEnded()

	// Consume receive window; check for flow control violations per RFC 9113 §6.9
	dataLen := len(data)
	if err := src.consumeRecvWindow(streamID, dataLen); err != nil {
		var fcErr *flowControlError
		if errors.As(err, &fcErr) {
			if fcErr.StreamID == 0 {
				// Connection-level violation: send GOAWAY and close
				log.Printf("h2: flow control error (connection): %v", err)
				p.sendGoAway(src, 0, http2.ErrCodeFlowControl, "flow control window exceeded")
				p.cancel()
			} else {
				// Stream-level violation: send RST_STREAM
				log.Printf("h2: flow control error (stream %d): %v", streamID, err)
				buf.Reset()
				framer := http2.NewFramer(buf, nil)
				_ = framer.WriteRSTStream(streamID, http2.ErrCodeFlowControl)
				src.enqueueWrite(p.ctx, buf.Bytes())
				p.cleanupStream(streamID)
			}
		}
		return
	}

	// Check if we need to send WINDOW_UPDATE back to sender to keep data flowing
	// This is critical when buffering for body rules - sender needs window credits
	if connUpdate, streamUpdate := src.needsWindowUpdate(streamID); connUpdate > 0 || streamUpdate > 0 {
		p.sendWindowUpdates(buf, src, streamID, connUpdate, streamUpdate)
	}

	stream, exists := p.streams.get(streamID)
	if !exists {
		// Unknown stream, forward anyway
		p.writeDataFrame(buf, dst, streamID, data, endStream)
		return
	}

	// Check if body rules require buffering (outside lock - doesn't access stream state)
	hasBodyRules := p.handler.ruleApplier != nil && p.handler.ruleApplier.HasBodyRules(fromClient)

	// Lock stream for all state access
	stream.mu.Lock()
	stream.lastActivity = time.Now()

	// Copy to history buffer (limited to maxBodyBytes for storage)
	p.copyToHistoryBufferLocked(stream, data, fromClient)

	// Determine if this stream has already overflowed (switched to streaming)
	var isOverflow bool
	if fromClient {
		isOverflow = stream.reqBodyOverflow
	} else {
		isOverflow = stream.respBodyOverflow
	}

	// Capture data needed outside the lock for write operations
	var writeData, flushBuffered, bodyForRules []byte
	var writeEndStream, applyRules bool

	if hasBodyRules && !isOverflow {
		// Buffer mode: accumulate full body for rule application
		overflow := p.copyToFullBufferLocked(stream, data, fromClient)

		if overflow {
			// Body too large for rule application - fall back to streaming.
			// Flush what we have buffered and forward this frame.
			if fromClient {
				if stream.reqBodyFull.Len() > 0 {
					flushBuffered = stream.reqBodyFull.Bytes()
					stream.reqBodyFull.Reset()
				}
			} else {
				if stream.respBodyFull.Len() > 0 {
					flushBuffered = stream.respBodyFull.Bytes()
					stream.respBodyFull.Reset()
				}
			}
			writeData = data
			writeEndStream = endStream
		} else if endStream {
			// Complete body received - apply rules and forward
			if fromClient {
				bodyForRules = stream.reqBodyFull.Bytes()
			} else {
				bodyForRules = stream.respBodyFull.Bytes()
			}
			applyRules = true
		}
		// Don't forward DATA frames until we have the complete body (or overflow)
	} else {
		// Streaming mode: forward immediately (no body rules or overflow)
		writeData = data
		writeEndStream = endStream
	}

	// Update stream state
	var isStreamClosed bool
	if endStream {
		isStreamClosed = stream.markEndStream(fromClient)
	}
	stream.mu.Unlock()

	// Perform write operations outside the lock
	if len(flushBuffered) > 0 {
		p.writeDataFrame(buf, dst, streamID, flushBuffered, false)
	}

	if applyRules {
		// Apply body rules (may call ruleApplier which shouldn't hold stream lock)
		body, err := p.applyBodyRules(stream, bodyForRules, fromClient)
		if err != nil {
			log.Printf("h2: body rule application failed: %v", err)
			// Send RST_STREAM to destination to signal error
			p.sendRSTStream(buf, dst, streamID, http2.ErrCodeInternal)
			p.cleanupStream(streamID)
			return
		}

		// Update history buffer with modified body (needs lock)
		stream.mu.Lock()
		p.updateHistoryWithModifiedBodyLocked(stream, body, fromClient)
		stream.mu.Unlock()

		// Send modified body
		p.writeDataFrame(buf, dst, streamID, body, true)
	} else if writeData != nil {
		p.writeDataFrame(buf, dst, streamID, writeData, writeEndStream)
	}

	if isStreamClosed {
		p.storeStreamInHistory(stream)
		p.cleanupStream(streamID)
	}
}

// copyToHistoryBufferLocked copies data to the history buffer (limited to maxBodyBytes).
// Caller must hold stream.mu.
func (p *h2Proxy) copyToHistoryBufferLocked(stream *h2Stream, data []byte, fromClient bool) {
	maxBytes := p.handler.maxBodyBytes
	if maxBytes <= 0 {
		// No limit
		if fromClient {
			stream.reqBody.Write(data)
		} else {
			stream.respBody.Write(data)
		}
		return
	}

	var buf *bytes.Buffer
	if fromClient {
		buf = &stream.reqBody
	} else {
		buf = &stream.respBody
	}

	if buf.Len() >= maxBytes {
		return // already at limit
	}

	remaining := maxBytes - buf.Len()
	if len(data) <= remaining {
		buf.Write(data)
	} else {
		buf.Write(data[:remaining])
	}
}

// copyToFullBufferLocked copies data to the full body buffer for rule application.
// Returns true if the buffer exceeds maxBodyBytes (overflow).
// If maxBodyBytes is zero or negative, no limit is applied.
// Caller must hold stream.mu.
func (p *h2Proxy) copyToFullBufferLocked(stream *h2Stream, data []byte, fromClient bool) bool {
	var buf *bytes.Buffer
	var overflow *bool
	if fromClient {
		buf = &stream.reqBodyFull
		overflow = &stream.reqBodyOverflow
	} else {
		buf = &stream.respBodyFull
		overflow = &stream.respBodyOverflow
	}

	if *overflow {
		return true // already overflowed
	}

	maxBytes := p.handler.maxBodyBytes
	if maxBytes > 0 && buf.Len()+len(data) > maxBytes {
		*overflow = true
		return true
	}

	buf.Write(data)
	return false
}

// applyBodyRules applies body rules and returns the modified body.
// Uses the body-only rule methods to avoid re-applying header rules.
// Both request and response paths need headers for Content-Encoding detection.
// Returns error if recompression fails (caller should reset stream).
func (p *h2Proxy) applyBodyRules(stream *h2Stream, body []byte, fromClient bool) ([]byte, error) {
	if p.handler.ruleApplier == nil {
		return body, nil
	}

	if fromClient {
		// Request body rules need headers for Content-Encoding detection
		stream.mu.Lock()
		headers := stream.reqHeaders
		stream.mu.Unlock()

		return p.handler.ruleApplier.ApplyRequestBodyOnlyRules(body, headers)
	}

	// Response body rules need headers for Content-Encoding detection
	stream.mu.Lock()
	headers := stream.respHeaders
	stream.mu.Unlock()

	return p.handler.ruleApplier.ApplyResponseBodyOnlyRules(body, headers), nil
}

// updateHistoryWithModifiedBodyLocked updates the history buffer with the modified body.
// Caller must hold stream.mu.
func (p *h2Proxy) updateHistoryWithModifiedBodyLocked(stream *h2Stream, body []byte, fromClient bool) {
	maxBytes := p.handler.maxBodyBytes
	if maxBytes <= 0 {
		maxBytes = len(body) // no limit
	}

	if fromClient {
		stream.reqBody.Reset()
		if len(body) <= maxBytes {
			stream.reqBody.Write(body)
		} else {
			stream.reqBody.Write(body[:maxBytes])
		}
	} else {
		stream.respBody.Reset()
		if len(body) <= maxBytes {
			stream.respBody.Write(body)
		} else {
			stream.respBody.Write(body[:maxBytes])
		}
	}
}

// handleSettingsFrame processes a SETTINGS frame.
// Uses endpoint model: SETTINGS are hop-by-hop, not forwarded across connections.
func (p *h2Proxy) handleSettingsFrame(buf *bytes.Buffer, f *http2.SettingsFrame, src, dst *h2Conn) {
	if f.IsAck() {
		// Absorb ACK - it acknowledges SETTINGS we sent to this peer.
		return
	}

	// Process settings locally - do NOT forward to other connection
	// Each connection has independent HPACK state and flow control
	_ = f.ForeachSetting(func(s http2.Setting) error {
		// When peer changes INITIAL_WINDOW_SIZE, update our send windows for that peer
		if s.ID == http2.SettingInitialWindowSize {
			src.updateSendWindowFromSettings(s.Val)
		}
		return nil
	})

	// Update local cache for this connection only
	settings := make([]http2.Setting, 0, f.NumSettings())
	_ = f.ForeachSetting(func(s http2.Setting) error {
		settings = append(settings, s)
		return nil
	})
	src.updateSettings(settings)

	// Send ACK back to source (don't forward SETTINGS to other connection)
	p.enqueueSettingsAck(buf, src)
}

// enqueueSettingsAck enqueues a SETTINGS ACK frame to be written.
func (p *h2Proxy) enqueueSettingsAck(buf *bytes.Buffer, dst *h2Conn) {
	buf.Reset()
	framer := http2.NewFramer(buf, nil)
	_ = framer.WriteSettingsAck()
	dst.enqueueWrite(p.ctx, buf.Bytes())
}

// cleanupStream removes a stream and its associated flow control state.
func (p *h2Proxy) cleanupStream(streamID uint32) {
	p.streams.remove(streamID)
	p.client.removeStreamWindow(streamID)
	p.upstream.removeStreamWindow(streamID)
}

// sendWindowUpdates sends WINDOW_UPDATE frames back to sender to replenish receive windows.
func (p *h2Proxy) sendWindowUpdates(buf *bytes.Buffer, dst *h2Conn, streamID uint32, connIncrement, streamIncrement uint32) {
	buf.Reset()
	framer := http2.NewFramer(buf, nil)

	// Connection-level WINDOW_UPDATE (stream ID 0)
	if connIncrement > 0 {
		_ = framer.WriteWindowUpdate(0, connIncrement)
		dst.enqueueWrite(p.ctx, buf.Bytes())
		buf.Reset()
	}

	// Stream-level WINDOW_UPDATE
	if streamIncrement > 0 {
		_ = framer.WriteWindowUpdate(streamID, streamIncrement)
		dst.enqueueWrite(p.ctx, buf.Bytes())
	}
}

// handleWindowUpdate processes a WINDOW_UPDATE frame (endpoint model: not forwarded).
// Uses endpoint model: WINDOW_UPDATE is hop-by-hop, not forwarded across connections.
// The peer is telling us their receive window increased, so we can send more to them.
// Each connection has independent flow control - client's window is unrelated to upstream's.
func (p *h2Proxy) handleWindowUpdate(f *http2.WindowUpdateFrame, src *h2Conn) {
	// Update OUR send window for the SOURCE connection (the peer that sent WINDOW_UPDATE)
	// This tracks how much data we can send to that peer
	// Do NOT forward to other connection - flow control is per-hop
	src.updateSendWindow(f.StreamID, f.Increment)

	// Update stream tracking if stream-level
	if f.StreamID != 0 {
		if stream, exists := p.streams.get(f.StreamID); exists {
			stream.mu.Lock()
			stream.window += int32(f.Increment)
			stream.mu.Unlock()
		}
	}
}

// handlePingFrame handles PING frames per Phase 5 spec.
// The proxy terminates all PINGs locally:
// - Non-ACK PINGs: respond with ACK to the sender using same payload
// - ACK PINGs: absorb (they're responses to PINGs we already echoed)
// This maintains correct end-to-end semantics without protocol errors.
func (p *h2Proxy) handlePingFrame(buf *bytes.Buffer, f *http2.PingFrame, src, dst *h2Conn) {
	if f.IsAck() {
		// ACK PINGs are responses to PINGs we already echoed locally.
		// Absorb them - forwarding would cause unsolicited ACKs.
		return
	}

	// Echo back with ACK flag set using same payload (per spec)
	buf.Reset()
	framer := http2.NewFramer(buf, nil)
	_ = framer.WritePing(true, f.Data)
	src.enqueueWrite(p.ctx, buf.Bytes())
}

// handleGoAwayFrame forwards GOAWAY and initiates shutdown.
func (p *h2Proxy) handleGoAwayFrame(buf *bytes.Buffer, f *http2.GoAwayFrame, dst *h2Conn) {
	buf.Reset()
	framer := http2.NewFramer(buf, nil)
	_ = framer.WriteGoAway(f.LastStreamID, f.ErrCode, f.DebugData())
	dst.enqueueWrite(p.ctx, buf.Bytes())
}

// handleRSTStreamFrame forwards RST_STREAM and cleans up stream.
func (p *h2Proxy) handleRSTStreamFrame(buf *bytes.Buffer, f *http2.RSTStreamFrame, dst *h2Conn) {
	buf.Reset()
	framer := http2.NewFramer(buf, nil)
	_ = framer.WriteRSTStream(f.StreamID, f.ErrCode)
	dst.enqueueWrite(p.ctx, buf.Bytes())

	// Clean up stream
	p.cleanupStream(f.StreamID)
}

// forwardPriorityFrame forwards a PRIORITY frame.
func (p *h2Proxy) forwardPriorityFrame(buf *bytes.Buffer, f *http2.PriorityFrame, dst *h2Conn) {
	buf.Reset()
	framer := http2.NewFramer(buf, nil)
	_ = framer.WritePriority(f.StreamID, f.PriorityParam)
	dst.enqueueWrite(p.ctx, buf.Bytes())
}

// forwardUnknownFrame forwards an unknown frame type transparently.
// HTTP/2 extensions use frame types 0x0A-0xFF which arrive as UnknownFrame.
func (p *h2Proxy) forwardUnknownFrame(buf *bytes.Buffer, f http2.Frame, dst *h2Conn) {
	hdr := f.Header()

	// Reconstruct raw frame bytes
	// Frame format: 9-byte header + payload
	// Header: Length (3) + Type (1) + Flags (1) + StreamID (4)
	buf.Reset()

	length := hdr.Length
	buf.WriteByte(byte(length >> 16))
	buf.WriteByte(byte(length >> 8))
	buf.WriteByte(byte(length))
	buf.WriteByte(byte(hdr.Type))
	buf.WriteByte(byte(hdr.Flags))
	buf.WriteByte(byte(hdr.StreamID >> 24))
	buf.WriteByte(byte(hdr.StreamID >> 16))
	buf.WriteByte(byte(hdr.StreamID >> 8))
	buf.WriteByte(byte(hdr.StreamID))

	// Append payload for UnknownFrame
	if uf, ok := f.(*http2.UnknownFrame); ok {
		buf.Write(uf.Payload())
	}

	dst.enqueueWrite(p.ctx, buf.Bytes())
}

// handlePushPromiseFrame handles PUSH_PROMISE by accumulating and decoding for HPACK state.
// Server push is disabled via SETTINGS_ENABLE_PUSH=0, so we drop the frame but maintain HPACK.
func (p *h2Proxy) handlePushPromiseFrame(f *http2.PushPromiseFrame, src *h2Conn) {
	// Start accumulating header block
	p.upstreamPushBuf.Reset()
	p.upstreamPushBuf.Write(f.HeaderBlockFragment())
	p.upstreamPushStream = f.StreamID
	p.upstreamPushPromiseID = f.PromiseID
	p.upstreamPushActive = true

	if f.HeadersEnded() {
		// Complete - decode to maintain HPACK state
		p.decodePushPromise(src)
	}
}

// decodePushPromise decodes accumulated PUSH_PROMISE headers to maintain HPACK state.
func (p *h2Proxy) decodePushPromise(src *h2Conn) {
	if !p.upstreamPushActive {
		return
	}

	// Decode using source's HPACK state to maintain compression synchronization.
	// We don't forward, but HPACK state must be updated.
	_, _, err := src.decodeHeaders(p.upstreamPushBuf.Bytes())
	if err != nil {
		log.Printf("h2: failed to decode PUSH_PROMISE headers (dropped): %v", err)
	} else {
		log.Printf("h2: dropped PUSH_PROMISE (stream=%d, promise=%d) - server push disabled",
			p.upstreamPushStream, p.upstreamPushPromiseID)
	}

	// Clear accumulation state
	p.upstreamPushBuf.Reset()
	p.upstreamPushActive = false
}

// writeFrames writes frames from the write channel to the connection.
func (p *h2Proxy) writeFrames(h *h2Conn, conn net.Conn) {
	defer p.wg.Done()
	defer p.cancel() // cancel context when writer exits to signal shutdown
	defer h.close()  // close the connection's close channel to unblock enqueueWrite

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-h.closeCh:
			return
		case data, ok := <-h.writeCh:
			if !ok {
				return
			}
			if p.handler.timeouts.WriteTimeout > 0 {
				_ = conn.SetWriteDeadline(time.Now().Add(p.handler.timeouts.WriteTimeout))
			}
			if _, err := conn.Write(data); err != nil {
				log.Printf("h2: write error: %v", err)
				return
			}
		}
	}
}

// writeHeadersFrame writes a HEADERS frame via the connection's write channel.
// Splits into HEADERS + CONTINUATION frames if block exceeds max frame size.
// The entire header block sequence is built into a single buffer and enqueued
// atomically to prevent interleaving with other frames (RFC 9113 §4.3).
func (p *h2Proxy) writeHeadersFrame(buf *bytes.Buffer, dst *h2Conn, streamID uint32, block []byte, endStream bool) {
	maxFrame := int(dst.getMaxFrameSize())
	if maxFrame == 0 {
		maxFrame = 16384 // HTTP/2 default
	}

	// Build entire HEADERS + CONTINUATION sequence into one buffer
	buf.Reset()
	framer := http2.NewFramer(buf, nil)

	// First chunk goes in HEADERS frame
	first := block
	if len(first) > maxFrame {
		first = block[:maxFrame]
		block = block[maxFrame:]
	} else {
		block = nil
	}

	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: first,
		EndStream:     endStream,
		EndHeaders:    len(block) == 0,
	}); err != nil {
		log.Printf("h2: WriteHeaders error: %v", err)
		return
	}

	// Remaining chunks go in CONTINUATION frames (same buffer)
	for len(block) > 0 {
		chunk := block
		if len(chunk) > maxFrame {
			chunk = block[:maxFrame]
			block = block[maxFrame:]
		} else {
			block = nil
		}

		if err := framer.WriteContinuation(streamID, len(block) == 0, chunk); err != nil {
			log.Printf("h2: WriteContinuation error: %v", err)
			return
		}
	}

	// Enqueue entire sequence atomically to prevent interleaving
	dst.enqueueWrite(p.ctx, buf.Bytes())
}

// flowControlTimeout is the maximum time to wait for flow control to unblock
const flowControlTimeout = 30 * time.Second

// writeDataFrame writes a DATA frame, splitting if necessary.
// Uses the destination h2Conn's max frame size setting and respects flow control.
// Waits for WINDOW_UPDATE when flow control is blocked (never truncates data).
func (p *h2Proxy) writeDataFrame(buf *bytes.Buffer, dst *h2Conn, streamID uint32, data []byte, endStream bool) {
	maxFrame := int(dst.getMaxFrameSize())
	if maxFrame == 0 {
		maxFrame = 16384 // HTTP/2 default
	}

	// Initialize stream send window if needed
	dst.initStreamSendWindow(streamID)

	// Set up timeout for flow control waiting
	timeout := time.NewTimer(flowControlTimeout)
	defer timeout.Stop()

	for len(data) > 0 || endStream {
		// Check available send window
		available := dst.getAvailableSendWindow(streamID)

		// If blocked on flow control, wait for WINDOW_UPDATE (never truncate)
		if available == 0 && len(data) > 0 {
			// Get channel that will be signaled when window updates
			flowCh := dst.flowCtrlWait()

			select {
			case <-p.ctx.Done():
				return
			case <-dst.closeCh:
				return
			case <-timeout.C:
				log.Printf("h2: flow control timeout for stream %d after %v, %d bytes remaining",
					streamID, flowControlTimeout, len(data))
				return
			case <-flowCh:
				// Window updated, loop back to check available window
				continue
			}
		}

		chunk := data
		// Limit by frame size
		if len(chunk) > maxFrame {
			chunk = data[:maxFrame]
		}
		// Limit by flow control window
		if len(chunk) > available {
			chunk = data[:available]
		}

		// Atomically consume send window - if this fails (window changed between
		// getAvailableSendWindow and now), loop back and retry
		if len(chunk) > 0 {
			if !dst.consumeSendWindow(streamID, len(chunk)) {
				// Window was consumed by concurrent operation, retry
				continue
			}
		}

		data = data[len(chunk):]

		buf.Reset()
		framer := http2.NewFramer(buf, nil)

		isLast := len(data) == 0 && endStream
		_ = framer.WriteData(streamID, isLast, chunk)
		dst.enqueueWrite(p.ctx, buf.Bytes())

		if isLast {
			break
		}
	}
}

// sendGoAway sends a GOAWAY frame via the connection's write channel.
func (p *h2Proxy) sendGoAway(dst *h2Conn, lastStreamID uint32, code http2.ErrCode, debug string) {
	var buf bytes.Buffer
	framer := http2.NewFramer(&buf, nil)
	_ = framer.WriteGoAway(lastStreamID, code, []byte(debug))
	dst.enqueueWrite(p.ctx, buf.Bytes())
}

// sendRSTStream sends a RST_STREAM frame to reset a stream with an error.
func (p *h2Proxy) sendRSTStream(buf *bytes.Buffer, dst *h2Conn, streamID uint32, code http2.ErrCode) {
	buf.Reset()
	framer := http2.NewFramer(buf, nil)
	_ = framer.WriteRSTStream(streamID, code)
	dst.enqueueWrite(p.ctx, buf.Bytes())
}

// storeStreamInHistory stores a completed stream in history.
func (p *h2Proxy) storeStreamInHistory(stream *h2Stream) {
	// Lock stream while reading all data for history
	stream.mu.Lock()
	entry := &HistoryEntry{
		Protocol:   protocolH2,
		H2StreamID: stream.id,
		H2Request: &H2RequestData{
			Method:    stream.method,
			Scheme:    stream.scheme,
			Authority: stream.authority,
			Path:      stream.path,
			Headers:   stream.reqHeaders,
			Body:      append([]byte(nil), stream.reqBody.Bytes()...), // copy to avoid holding reference
		},
		H2Response: &H2ResponseData{
			StatusCode: stream.statusCode,
			Headers:    stream.respHeaders,
			Body:       append([]byte(nil), stream.respBody.Bytes()...), // copy to avoid holding reference
		},
		Timestamp: stream.startTime,
		Duration:  time.Since(stream.startTime),
	}
	stream.mu.Unlock()

	if !p.handler.history.ShouldCapture(entry) {
		return
	}
	p.handler.history.Store(entry)
}

// cleanupStaleStreams periodically removes streams that haven't had activity.
func (p *h2Proxy) cleanupStaleStreams() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			for _, stream := range p.streams.all() {
				// Check lastActivity under lock
				stream.mu.Lock()
				lastActivity := stream.lastActivity
				streamID := stream.id
				stream.mu.Unlock()

				if now.Sub(lastActivity) > streamIdleTimeout {
					log.Printf("h2: cleaning up stale stream %d", streamID)

					// Send RST_STREAM to both sides via write channels
					var buf bytes.Buffer
					framer := http2.NewFramer(&buf, nil)
					_ = framer.WriteRSTStream(streamID, http2.ErrCodeCancel)

					p.client.enqueueWrite(p.ctx, buf.Bytes())

					buf.Reset()
					_ = framer.WriteRSTStream(streamID, http2.ErrCodeCancel)
					p.upstream.enqueueWrite(p.ctx, buf.Bytes())

					p.cleanupStream(streamID)
				}
			}
		}
	}
}

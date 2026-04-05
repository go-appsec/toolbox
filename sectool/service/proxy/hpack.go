package proxy

import (
	"bytes"
	"context"
	"net"
	"slices"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// h2ForbiddenHeaders are connection-specific headers that MUST NOT be used in HTTP/2.
// Per RFC 9113 Section 8.2.2.
var h2ForbiddenHeaders = map[string]bool{
	"connection":        true,
	"proxy-connection":  true,
	"keep-alive":        true,
	"transfer-encoding": true,
	"upgrade":           true,
}

const (
	// hpackDynamicTableSize is the HPACK dynamic table size (4KB per RFC 7541)
	hpackDynamicTableSize = 4096

	// maxHeaderListSize is advertised in SETTINGS (16KB)
	maxHeaderListSize = 16384

	// maxHeaderBlockSize is absolute limit before GOAWAY (1MB)
	maxHeaderBlockSize = 1 << 20

	// localInitialWindow is the initial receive window we advertise to peers.
	// This is what we send in SETTINGS_INITIAL_WINDOW_SIZE.
	// Used for tracking our receive windows (not peer's send window).
	localInitialWindow = 65535
)

// h2Conn wraps a single HTTP/2 connection with its frame and HPACK state.
// HPACK state is connection-scoped - each connection needs independent encoder/decoder.
type h2Conn struct {
	conn   net.Conn
	framer *http2.Framer

	// HPACK encoder/decoder (connection-scoped)
	hpackDec *hpack.Decoder
	hpackEnc *hpack.Encoder
	hpackBuf bytes.Buffer // encoder output buffer
	hpackMu  sync.Mutex   // protects hpackEnc and hpackBuf

	// Write channel for serialized frame output
	writeCh chan []byte

	// Close channel signals connection shutdown
	closeCh   chan struct{}
	closeOnce sync.Once // ensures closeCh is only closed once

	// Settings received from peer
	maxFrameSize         uint32
	maxHeaderListSize    uint32
	initialWindowSize    uint32
	headerTableSize      uint32
	enablePush           bool
	maxConcurrentStreams uint32
	settingsMu           sync.RWMutex

	// Flow control: receive windows (how much data we can receive)
	// These track our local receive window for this connection/stream
	recvWindowConn   int32            // connection-level receive window
	recvWindowStream map[uint32]int32 // per-stream receive windows

	// Flow control: send windows (how much data we can send to peer)
	// These track the peer's receive window, which limits our sending
	sendWindowConn   int32            // connection-level send window
	sendWindowStream map[uint32]int32 // per-stream send windows

	// Flow control notification: closed when send window increases
	// Waiters should select on this channel; when closed, check window and re-wait if needed
	flowCtrlCh chan struct{}

	flowMu sync.Mutex // protects all flow control state including flowCtrlCh
}

// newH2Conn creates a new HTTP/2 connection wrapper.
func newH2Conn(conn net.Conn) *h2Conn {
	framer := http2.NewFramer(nil, conn)
	framer.ReadMetaHeaders = nil // We decode HPACK ourselves

	h := &h2Conn{
		conn:                 conn,
		framer:               framer,
		writeCh:              make(chan []byte, 256),
		closeCh:              make(chan struct{}),
		maxFrameSize:         16384, // HTTP/2 default
		maxHeaderListSize:    maxHeaderListSize,
		initialWindowSize:    65535, // HTTP/2 default (peer's window for send logic)
		headerTableSize:      hpackDynamicTableSize,
		maxConcurrentStreams: 100,                // reasonable default
		recvWindowConn:       localInitialWindow, // our advertised receive window
		recvWindowStream:     make(map[uint32]int32),
		sendWindowConn:       65535, // HTTP/2 default (peer's receive window)
		sendWindowStream:     make(map[uint32]int32),
		flowCtrlCh:           make(chan struct{}),
	}

	h.hpackDec = hpack.NewDecoder(hpackDynamicTableSize, nil)
	h.hpackEnc = hpack.NewEncoder(&h.hpackBuf)
	h.hpackEnc.SetMaxDynamicTableSize(hpackDynamicTableSize)

	return h
}

// decodeHeaders decodes an HPACK-compressed header block.
// Returns pseudo-headers and regular headers separately.
func (h *h2Conn) decodeHeaders(block []byte) (pseudos map[string]string, headers Headers, err error) {
	pseudos = make(map[string]string)

	fields, err := h.hpackDec.DecodeFull(block)
	if err != nil {
		return nil, nil, err
	}

	for _, f := range fields {
		if len(f.Name) > 0 && f.Name[0] == ':' {
			// Pseudo-header
			pseudos[f.Name] = f.Value
		} else {
			headers = append(headers, Header{Name: f.Name, Value: f.Value})
		}
	}

	return pseudos, headers, nil
}

// headerListSize calculates the header list size per RFC 7541 Section 4.1.
// Size = sum of (name length + value length + 32) for each field.
func headerListSize(pseudos map[string]string, headers Headers) int {
	var size int
	for name, value := range pseudos {
		size += len(name) + len(value) + 32
	}
	for _, h := range headers {
		size += len(h.Name) + len(h.Value) + 32
	}
	return size
}

// encodeHeaders encodes pseudo-headers and regular headers into HPACK.
// Pseudo-headers must be written first per HTTP/2 spec.
// Header names are lowercased and connection-specific headers are filtered per RFC 9113.
func (h *h2Conn) encodeHeaders(pseudos map[string]string, headers Headers) ([]byte, error) {
	h.hpackMu.Lock()
	defer h.hpackMu.Unlock()

	h.hpackBuf.Reset()

	// Encode pseudo-headers first (order matters per spec)
	// Canonical order: :method, :scheme, :authority, :path for requests
	// :status for responses
	pseudoOrder := []string{":method", ":scheme", ":authority", ":path", ":status"}
	for _, name := range pseudoOrder {
		if value, ok := pseudos[name]; ok {
			if err := h.hpackEnc.WriteField(hpack.HeaderField{Name: name, Value: value}); err != nil {
				return nil, err
			}
		}
	}

	// Encode any remaining pseudo-headers not in canonical order
	for name, value := range pseudos {
		if !slices.Contains(pseudoOrder, name) {
			if err := h.hpackEnc.WriteField(hpack.HeaderField{Name: name, Value: value}); err != nil {
				return nil, err
			}
		}
	}

	// Encode regular headers
	// HTTP/2 requires lowercase header names and forbids connection-specific headers
	for _, hdr := range headers {
		lowerName := strings.ToLower(hdr.Name)

		// Skip connection-specific headers forbidden in HTTP/2
		if h2ForbiddenHeaders[lowerName] {
			continue
		}

		// TE header is only allowed with value "trailers"
		if lowerName == "te" && strings.ToLower(hdr.Value) != "trailers" {
			continue
		}

		// Host header is redundant in HTTP/2 (:authority is the authority).
		// Strip it to avoid odd upstream behavior if it differs from :authority.
		if lowerName == "host" {
			continue
		}

		if err := h.hpackEnc.WriteField(hpack.HeaderField{Name: lowerName, Value: hdr.Value}); err != nil {
			return nil, err
		}
	}

	return slices.Clone(h.hpackBuf.Bytes()), nil
}

// updateSettings updates cached settings from peer (except INITIAL_WINDOW_SIZE).
// Note: INITIAL_WINDOW_SIZE is handled by updateSendWindowFromSettings() under flowMu
// to avoid data races with flow control logic that reads initialWindowSize.
func (h *h2Conn) updateSettings(settings []http2.Setting) {
	h.settingsMu.Lock()
	defer h.settingsMu.Unlock()

	for _, s := range settings {
		switch s.ID {
		case http2.SettingMaxFrameSize:
			h.maxFrameSize = s.Val
		case http2.SettingMaxHeaderListSize:
			h.maxHeaderListSize = s.Val
		case http2.SettingInitialWindowSize:
			// Handled by updateSendWindowFromSettings() under flowMu - skip here to avoid race
		case http2.SettingHeaderTableSize:
			// Peer's SETTINGS_HEADER_TABLE_SIZE constrains our encoder, not decoder
			tableSize := s.Val
			if tableSize > hpackDynamicTableSize {
				tableSize = hpackDynamicTableSize
			}
			h.headerTableSize = tableSize
			h.hpackMu.Lock()
			h.hpackEnc.SetMaxDynamicTableSize(tableSize)
			h.hpackMu.Unlock()
		case http2.SettingEnablePush:
			h.enablePush = s.Val == 1
		case http2.SettingMaxConcurrentStreams:
			h.maxConcurrentStreams = s.Val
		}
	}
}

// getMaxFrameSize returns the peer's max frame size setting.
func (h *h2Conn) getMaxFrameSize() uint32 {
	h.settingsMu.RLock()
	defer h.settingsMu.RUnlock()
	return h.maxFrameSize
}

// close closes the connection's close channel to signal shutdown.
// Safe to call multiple times.
func (h *h2Conn) close() {
	h.closeOnce.Do(func() {
		close(h.closeCh)
	})
}

// flowControlError indicates a flow control violation by the peer.
type flowControlError struct {
	StreamID uint32 // 0 for connection-level violation
	Message  string
}

func (e *flowControlError) Error() string {
	return e.Message
}

// consumeRecvWindow deducts from receive windows when data is received.
// Returns an error if the peer violated flow control (sent more than allowed).
// Per RFC 9113 section 6.9, exceeding the window is a connection/stream error.
func (h *h2Conn) consumeRecvWindow(streamID uint32, size int) error {
	h.flowMu.Lock()
	defer h.flowMu.Unlock()

	// Check connection-level window
	if size > int(h.recvWindowConn) {
		return &flowControlError{
			StreamID: 0,
			Message:  "connection flow control window exceeded",
		}
	}

	// Check stream-level window
	streamWindow, ok := h.recvWindowStream[streamID]
	if !ok {
		streamWindow = localInitialWindow
	}
	if size > int(streamWindow) {
		return &flowControlError{
			StreamID: streamID,
			Message:  "stream flow control window exceeded",
		}
	}

	// Deduct from both windows
	h.recvWindowConn -= int32(size)
	h.recvWindowStream[streamID] = streamWindow - int32(size)

	return nil
}

// needsWindowUpdate returns true if we should send WINDOW_UPDATE to keep data flowing.
// Uses localInitialWindow (what we advertise) to determine when to replenish receive windows.
// Sends update when window drops below 50% of our advertised initial window.
func (h *h2Conn) needsWindowUpdate(streamID uint32) (connUpdate, streamUpdate uint32) {
	h.flowMu.Lock()
	defer h.flowMu.Unlock()

	// Use localInitialWindow (what we advertise), not h.initialWindowSize (peer's window)
	const initial int32 = localInitialWindow
	threshold := initial / 2 // send update when window drops below 50%

	// Check connection-level window
	if h.recvWindowConn < threshold {
		connUpdate = uint32(initial - h.recvWindowConn)
		h.recvWindowConn = initial
	}

	// Check stream-level window
	streamWindow, ok := h.recvWindowStream[streamID]
	if !ok {
		return
	}
	if streamWindow < threshold {
		streamUpdate = uint32(initial - streamWindow)
		h.recvWindowStream[streamID] = initial
	}

	return
}

// removeStreamWindow removes a stream from window tracking.
func (h *h2Conn) removeStreamWindow(streamID uint32) {
	h.flowMu.Lock()
	defer h.flowMu.Unlock()
	delete(h.recvWindowStream, streamID)
	delete(h.sendWindowStream, streamID)
}

// updateSendWindow updates send window when receiving WINDOW_UPDATE from peer.
// streamID 0 updates connection-level window, otherwise stream-level.
// Signals any goroutines waiting on flow control.
func (h *h2Conn) updateSendWindow(streamID uint32, increment uint32) {
	h.flowMu.Lock()
	defer h.flowMu.Unlock()

	if streamID == 0 {
		h.sendWindowConn += int32(increment)
	} else {
		window, ok := h.sendWindowStream[streamID]
		if !ok {
			window = int32(h.initialWindowSize)
		}
		h.sendWindowStream[streamID] = window + int32(increment)
	}

	// Signal waiters by closing and replacing the channel
	close(h.flowCtrlCh)
	h.flowCtrlCh = make(chan struct{})
}

// consumeSendWindow deducts from send windows when sending DATA.
// Returns true if there was enough credit, false if blocked.
func (h *h2Conn) consumeSendWindow(streamID uint32, size int) bool {
	h.flowMu.Lock()
	defer h.flowMu.Unlock()

	// Check connection-level window
	if int(h.sendWindowConn) < size {
		return false
	}

	// Check stream-level window
	streamWindow, ok := h.sendWindowStream[streamID]
	if !ok {
		streamWindow = int32(h.initialWindowSize)
		h.sendWindowStream[streamID] = streamWindow
	}
	if int(streamWindow) < size {
		return false
	}

	// Deduct from both windows
	h.sendWindowConn -= int32(size)
	h.sendWindowStream[streamID] = streamWindow - int32(size)
	return true
}

// getAvailableSendWindow returns how many bytes can be sent (min of conn and stream windows).
func (h *h2Conn) getAvailableSendWindow(streamID uint32) int {
	h.flowMu.Lock()
	defer h.flowMu.Unlock()

	connWindow := int(h.sendWindowConn)
	if connWindow < 0 {
		connWindow = 0
	}

	streamWindow, ok := h.sendWindowStream[streamID]
	if !ok {
		streamWindow = int32(h.initialWindowSize)
	}
	if streamWindow < 0 {
		streamWindow = 0
	}

	if connWindow < int(streamWindow) {
		return connWindow
	}
	return int(streamWindow)
}

// initStreamSendWindow initializes send window for a new stream.
func (h *h2Conn) initStreamSendWindow(streamID uint32) {
	h.flowMu.Lock()
	defer h.flowMu.Unlock()
	if _, ok := h.sendWindowStream[streamID]; !ok {
		h.sendWindowStream[streamID] = int32(h.initialWindowSize)
	}
}

// updateSendWindowFromSettings updates all stream send windows when SETTINGS changes initial window.
// Also stores the new initial window size under flowMu for consistent access.
// Signals any goroutines waiting on flow control if windows increased.
func (h *h2Conn) updateSendWindowFromSettings(newInitial uint32) {
	h.flowMu.Lock()
	defer h.flowMu.Unlock()

	oldInitial := h.initialWindowSize
	delta := int32(newInitial) - int32(oldInitial)

	// Store new initial window size under flowMu (all flow control reads use flowMu)
	h.initialWindowSize = newInitial

	// Update all stream windows by the delta
	for streamID, window := range h.sendWindowStream {
		h.sendWindowStream[streamID] = window + delta
	}

	// Signal waiters if window increased
	if delta > 0 {
		close(h.flowCtrlCh)
		h.flowCtrlCh = make(chan struct{})
	}
}

// flowCtrlWait returns a channel that will be closed when the send window increases.
// Callers should re-check the window after the channel closes and call again if still blocked.
func (h *h2Conn) flowCtrlWait() <-chan struct{} {
	h.flowMu.Lock()
	defer h.flowMu.Unlock()
	return h.flowCtrlCh
}

// enqueueWrite sends data to be written by the writer goroutine.
// Returns false if the connection is closed, shutting down, or context is cancelled.
func (h *h2Conn) enqueueWrite(ctx context.Context, data []byte) bool {
	select {
	case <-ctx.Done():
		return false
	case <-h.closeCh:
		return false
	case h.writeCh <- slices.Clone(data):
		return true
	}
}

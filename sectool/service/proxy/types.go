package proxy

import (
	"strings"
	"time"

	"github.com/go-analyze/bulk"
)

// Header represents a single HTTP header preserving original formatting.
type Header struct {
	// Name preserves original casing and whitespace anomalies
	// (e.g., "Content-Type", "content-type", or "Header " with trailing space)
	Name string `json:"name" msgpack:"n"`

	// Value is the header value with leading/trailing whitespace trimmed
	Value string `json:"value" msgpack:"v"`

	// RawLine contains the original wire bytes for this header (excluding line ending).
	// Used by SerializeRaw() to preserve exact wire format including obs-fold.
	// nil when header was programmatically created or Wire format not tracked.
	RawLine []byte `json:"raw_line,omitempty" msgpack:"rl,omitempty"`
}

// WireFormat stores metadata about the original wire encoding.
type WireFormat struct {
	// WasChunked indicates the body was received with chunked transfer encoding.
	// When true, SerializeRaw can optionally re-emit chunked encoding.
	WasChunked bool `json:"was_chunked,omitempty" msgpack:"wc,omitempty"`

	// UsedBareLF indicates the message used bare LF (\n) instead of CRLF (\r\n).
	// When true, SerializeRaw uses bare LF for line endings.
	UsedBareLF bool `json:"used_bare_lf,omitempty" msgpack:"lf,omitempty"`
}

// Headers is a slice of Header with helper methods for case-insensitive access.
// JSON serializes as an array, same as []Header.
type Headers []Header

// Get returns the first header value with the given name (case-insensitive).
// Returns empty string if not found.
func (h *Headers) Get(name string) string {
	for _, hdr := range *h {
		if strings.EqualFold(hdr.Name, name) {
			return hdr.Value
		}
	}
	return ""
}

// Set sets or replaces the first header with the given name (case-insensitive).
// If not found, appends a new header.
// Clears RawLine since the programmatic value no longer matches the original wire bytes.
func (h *Headers) Set(name, value string) {
	for i, hdr := range *h {
		if strings.EqualFold(hdr.Name, name) {
			(*h)[i].Value = value
			(*h)[i].RawLine = nil // Clear RawLine since value changed
			return
		}
	}
	*h = append(*h, Header{Name: name, Value: value})
}

// Remove removes all headers with the given name (case-insensitive).
func (h *Headers) Remove(name string) {
	*h = bulk.SliceFilterInPlace(func(hdr Header) bool {
		return !strings.EqualFold(hdr.Name, name)
	}, *h)
}

// RawHTTP1Request represents a parsed HTTP/1.1 request with wire-level fidelity.
// The SerializeRaw() method reconstructs wire bytes from the stored components.
type RawHTTP1Request struct {
	// Request line components
	Method  string `json:"method" msgpack:"m"`                    // "GET", "POST", etc.
	Path    string `json:"path" msgpack:"p"`                      // path without query string, e.g., "/path"
	Query   string `json:"query,omitempty" msgpack:"q,omitempty"` // query string without leading ?, e.g., "foo=bar"
	Version string `json:"version" msgpack:"v"`                   // "HTTP/1.1" or "HTTP/1.0"

	// Headers preserves order and original name casing/whitespace
	Headers Headers `json:"headers" msgpack:"h"`

	// Body is the request body (decoded if chunked, raw otherwise)
	// For chunked encoding, this contains the reassembled body without chunk framing
	Body []byte `json:"body,omitempty" msgpack:"b,omitempty"`

	// Trailers for chunked encoding (raw bytes, rare but must preserve)
	// TODO - FUTURE - Parse trailers into []Header if trailer rules are needed
	Trailers []byte `json:"trailers,omitempty" msgpack:"t,omitempty"`

	// Protocol metadata for replay fidelity
	Protocol string `json:"protocol" msgpack:"pr"` // "http/1.1" - stored for history/replay

	// Wire contains metadata about the original wire encoding.
	// Used by SerializeRaw() to preserve exact wire format.
	Wire *WireFormat `json:"wire,omitempty" msgpack:"w,omitempty"`
}

// RawHTTP1Response represents a parsed HTTP/1.1 response with wire-level fidelity.
type RawHTTP1Response struct {
	// Status line components
	Version    string `json:"version" msgpack:"v"`                          // "HTTP/1.1" or "HTTP/1.0"
	StatusCode int    `json:"status_code" msgpack:"sc"`                     // 200, 404, etc.
	StatusText string `json:"status_text,omitempty" msgpack:"st,omitempty"` // "OK", "Not Found", etc.

	// Headers preserves order and original name casing
	Headers Headers `json:"headers" msgpack:"h"`

	// Body is the response body (decoded if chunked, raw otherwise)
	Body []byte `json:"body,omitempty" msgpack:"b,omitempty"`

	// Trailers for chunked encoding (raw bytes)
	// TODO - FUTURE - Parse trailers into []Header if trailer rules are needed
	Trailers []byte `json:"trailers,omitempty" msgpack:"t,omitempty"`

	// Wire contains metadata about the original wire encoding.
	// Used by SerializeRaw() to preserve exact wire format.
	Wire *WireFormat `json:"wire,omitempty" msgpack:"w,omitempty"`
}

// GetHeader returns the first header value with the given name (case-insensitive).
func (r *RawHTTP1Request) GetHeader(name string) string { return r.Headers.Get(name) }

// SetHeader sets or replaces the first header with the given name (case-insensitive).
func (r *RawHTTP1Request) SetHeader(name, value string) { r.Headers.Set(name, value) }

// RemoveHeader removes all headers with the given name (case-insensitive).
func (r *RawHTTP1Request) RemoveHeader(name string) { r.Headers.Remove(name) }

// GetHeader returns the first header value with the given name (case-insensitive).
func (r *RawHTTP1Response) GetHeader(name string) string { return r.Headers.Get(name) }

// SetHeader sets or replaces the first header with the given name (case-insensitive).
func (r *RawHTTP1Response) SetHeader(name, value string) { r.Headers.Set(name, value) }

// RemoveHeader removes all headers with the given name (case-insensitive).
func (r *RawHTTP1Response) RemoveHeader(name string) { r.Headers.Remove(name) }

// HistoryEntry represents a stored request/response pair.
// Embeds the parsed types directly for memory efficiency.
// The SerializeRaw() methods on Request/Response reconstruct wire bytes on demand.
type HistoryEntry struct {
	// Offset is the monotonic history index
	Offset uint32 `json:"offset" msgpack:"o"`

	// Protocol identifies the HTTP version: "http/1.1", "h2", or "websocket"
	Protocol string `json:"protocol" msgpack:"pr"`

	// HTTP/1.1 request/response (nil for HTTP/2)
	Request  *RawHTTP1Request  `json:"request,omitempty" msgpack:"rq,omitempty"`
	Response *RawHTTP1Response `json:"response,omitempty" msgpack:"rs,omitempty"`

	// HTTP/2 request/response (nil for HTTP/1.1)
	H2Request  *H2RequestData  `json:"h2_request,omitempty" msgpack:"h2q,omitempty"`
	H2Response *H2ResponseData `json:"h2_response,omitempty" msgpack:"h2r,omitempty"`
	H2StreamID uint32          `json:"h2_stream_id,omitempty" msgpack:"h2s,omitempty"` // for debugging/correlation

	// WSFrames contains WebSocket frames for Protocol="websocket" entries.
	// The handshake is stored in Request/Response; frames are appended here.
	WSFrames []WSFrame `json:"ws_frames,omitempty" msgpack:"ws,omitempty"`

	// Timing metadata
	Timestamp time.Time     `json:"timestamp" msgpack:"ts"`
	Duration  time.Duration `json:"duration" msgpack:"d"`
}

// WSFrame represents a single WebSocket frame stored in history.
type WSFrame struct {
	// Direction is "to-server" or "to-client"
	Direction string `json:"direction" msgpack:"dr"`

	// Opcode is the WebSocket opcode (1=text, 2=binary, 8=close, 9=ping, 10=pong)
	Opcode byte `json:"opcode" msgpack:"op"`

	// Payload is the frame payload (unmasked)
	Payload []byte `json:"payload,omitempty" msgpack:"pl,omitempty"`

	// Timestamp when the frame was captured
	Timestamp time.Time `json:"timestamp" msgpack:"ts"`
}

// H2RequestData represents an HTTP/2 request for history storage.
type H2RequestData struct {
	// Pseudo-headers
	Method    string `json:"method" msgpack:"m"`    // from :method
	Scheme    string `json:"scheme" msgpack:"s"`    // from :scheme
	Authority string `json:"authority" msgpack:"a"` // from :authority
	Path      string `json:"path" msgpack:"p"`      // from :path

	// Regular headers (not pseudo-headers)
	Headers Headers `json:"headers" msgpack:"h"`

	// Body is the request body
	Body []byte `json:"body,omitempty" msgpack:"b,omitempty"`
}

// H2ResponseData represents an HTTP/2 response for history storage.
type H2ResponseData struct {
	// StatusCode from :status pseudo-header
	StatusCode int `json:"status_code" msgpack:"sc"`

	// Regular headers (not pseudo-headers)
	Headers Headers `json:"headers" msgpack:"h"`

	// Body is the response body
	Body []byte `json:"body,omitempty" msgpack:"b,omitempty"`
}

// GetHeader returns the first header value with the given name (case-insensitive).
func (r *H2RequestData) GetHeader(name string) string { return r.Headers.Get(name) }

// SetHeader sets or replaces the first header with the given name (case-insensitive).
func (r *H2RequestData) SetHeader(name, value string) { r.Headers.Set(name, value) }

// GetHeader returns the first header value with the given name (case-insensitive).
func (r *H2ResponseData) GetHeader(name string) string { return r.Headers.Get(name) }

// SetHeader sets or replaces the first header with the given name (case-insensitive).
func (r *H2ResponseData) SetHeader(name, value string) { r.Headers.Set(name, value) }

// HistoryMeta holds lightweight metadata extracted at store time.
// Used by summary/list paths to avoid deserializing full request/response bodies.
type HistoryMeta struct {
	Offset      uint32        `msgpack:"o"`
	Protocol    string        `msgpack:"pr"`
	Method      string        `msgpack:"m"`
	Host        string        `msgpack:"h"`
	Path        string        `msgpack:"p"` // includes query string
	Status      int           `msgpack:"s"`
	ContentType string        `msgpack:"ct"`
	RespLen     int           `msgpack:"rl"`
	H2StreamID  uint32        `msgpack:"h2,omitempty"`
	Timestamp   time.Time     `msgpack:"ts"`
	Duration    time.Duration `msgpack:"d"`
}

// Target specifies where to send a request.
type Target struct {
	Hostname  string
	Port      int
	UsesHTTPS bool
}

// RuleApplier applies match/replace rules to requests and responses.
// Implemented by the service layer (NativeProxyBackend).
// Rules are applied in the order they were added (list order).
type RuleApplier interface {
	// ApplyRequestRules applies request header and body rules.
	// Returns the modified request (may be same instance if no changes).
	ApplyRequestRules(req *RawHTTP1Request) *RawHTTP1Request

	// ApplyResponseRules applies response header and body rules.
	// Handles decompression/recompression for body rules.
	ApplyResponseRules(resp *RawHTTP1Response) *RawHTTP1Response

	// ApplyRequestBodyOnlyRules applies only body rules to a request body.
	// Used by HTTP/2 where headers are sent separately before body.
	// Requires headers for Content-Encoding detection (compression-aware).
	// Does not apply header rules.
	// Returns error if recompression fails (caller should reset stream).
	ApplyRequestBodyOnlyRules(body []byte, headers Headers) ([]byte, error)

	// ApplyResponseBodyOnlyRules applies only body rules to a response body.
	// Used by HTTP/2 where headers are sent separately before body.
	// Requires headers for Content-Encoding detection (compression-aware).
	// Does not apply header rules.
	ApplyResponseBodyOnlyRules(body []byte, headers Headers) []byte

	// ApplyWSRules applies WebSocket rules to frame payload.
	// direction is "ws:to-server" or "ws:to-client".
	ApplyWSRules(payload []byte, direction string) []byte

	// HasBodyRules returns true if there are body rules for request or response.
	// Used by HTTP/2 handler to decide whether to buffer full bodies.
	// isRequest=true checks for request_body rules, false checks for response_body rules.
	HasBodyRules(isRequest bool) bool
}

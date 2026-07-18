// Package types holds the proxy capture data model: the wire-fidelity HTTP/1.1
// request/response types, the common Flow/Message envelope, and the rule-applier
// contract. It is depended on by the proxy package and the adapter registry
// (proxy/protocol) without forming an import cycle.
package types

import (
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-analyze/bulk"
)

// CertSpec is additive leaf properties for a minted MITM leaf, beyond the
// hostname-derived single SAN. A nil *CertSpec yields the single-SAN leaf.
type CertSpec struct {
	DNSNames    []string
	IPAddresses []net.IP
	URIs        []*url.URL
	Emails      []string
	CommonName  string // upstream/declared CN; added as a SAN, not the leaf Subject.CN
}

// Empty reports whether the spec contributes no additive names.
func (s *CertSpec) Empty() bool {
	return s == nil || (len(s.DNSNames) == 0 && len(s.IPAddresses) == 0 &&
		len(s.URIs) == 0 && len(s.Emails) == 0 && s.CommonName == "")
}

// Protocol tags identify the protocol within a stored Flow.
const (
	ProtocolHTTP11 = "http/1.1"
	ProtocolH2     = "http/2"

	ProtocolTagWS      = "websocket"       // upgrade handshake flow
	ProtocolTagWSFrame = "websocket.frame" // per-frame child flow

	// AdapterScopeCore is the reserved scope naming the in-process proxy (HTTP/1.1,
	// HTTP/2, WebSocket) and Burp. It scopes rules and attributes core tools;
	// sidecars may not register under it.
	AdapterScopeCore = "sectool"

	SchemeHTTP  = "http"
	SchemeHTTPS = "https"

	DirectionC2S = "client_to_server"
	DirectionS2C = "server_to_client"

	// HeaderStreamID carries the wire stream id (e.g. an HTTP/2 stream id);
	// folded into request headers and skipped when serializing for display.
	HeaderStreamID = "X-Sectool-Stream-Id"

	// MethodFrame is the synthetic method used for WebSocket frame child flows.
	MethodFrame = "FRAME"
)

// LineEnding identifies the terminator used on a single HTTP line.
// Zero value is EndingCRLF so unset fields emit the HTTP default.
type LineEnding uint8

const (
	EndingCRLF   LineEnding = 0 // "\r\n"
	EndingBareLF LineEnding = 1 // "\n"
	EndingBareCR LineEnding = 2 // "\r" - HTTP desync vector
	EndingNone   LineEnding = 3 // no terminator observed (EOF / truncation)
)

// Bytes returns the wire terminator for this line ending.
func (e LineEnding) Bytes() string {
	switch e {
	case EndingBareLF:
		return "\n"
	case EndingBareCR:
		return "\r"
	case EndingNone:
		return ""
	default:
		return "\r\n"
	}
}

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

	// LineEnding is the terminator observed for this header's final physical line.
	LineEnding LineEnding `json:"line_ending,omitempty" msgpack:"le,omitempty"`
}

// ChunkFrame preserves per-chunk wire framing for chunked messages.
// Invariant: non-final Size values sum to len(Body); the final frame has Size=0.
type ChunkFrame struct {
	// SizeLine is the raw size line without terminator, preserving extensions (e.g. "4;foo=bar") and hex casing.
	SizeLine []byte `json:"size_line,omitempty" msgpack:"sl,omitempty"`

	// SizeEnding is the terminator after the size line.
	SizeEnding LineEnding `json:"size_ending,omitempty" msgpack:"se,omitempty"`

	// Size is the chunk payload length in bytes (0 for final terminator chunk).
	Size int `json:"size,omitempty" msgpack:"sz,omitempty"`

	// DataEnding is the terminator after the chunk data. On the final 0-chunk it
	// is the trailer block's closing blank-line terminator, or EndingNone if truncated.
	DataEnding LineEnding `json:"data_ending,omitempty" msgpack:"de,omitempty"`

	// Malformed marks the trailing frame after a bad hex size; SizeLine holds
	// the raw bytes verbatim and the parser does not read past it.
	Malformed bool `json:"malformed,omitempty" msgpack:"mf,omitempty"`
}

// WireFormat stores summary metadata about the original wire encoding.
// Per-line terminators are tracked on the LineEnding fields; these flags are
// informational and drive chunked re-emission (UsedBareCR > UsedBareLF > CRLF).
type WireFormat struct {
	// WasChunked indicates chunked transfer encoding was received.
	WasChunked bool `json:"was_chunked,omitempty" msgpack:"wc,omitempty"`

	// UsedBareLF is true when any line used bare LF (\n) as terminator.
	UsedBareLF bool `json:"used_bare_lf,omitempty" msgpack:"lf,omitempty"`

	// UsedBareCR is true when any line used bare CR (\r) as terminator.
	UsedBareCR bool `json:"used_bare_cr,omitempty" msgpack:"cr,omitempty"`
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
			if (*h)[i].LineEnding == EndingNone {
				(*h)[i].LineEnding = EndingCRLF
			}
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

	// Chunks preserves per-chunk wire framing for chunked messages.
	// When body is mutated, callers must set to nil to avoid stale state being re-emitted.
	Chunks []ChunkFrame `json:"chunks,omitempty" msgpack:"ck,omitempty"`

	// Protocol metadata for replay fidelity
	Protocol string `json:"protocol" msgpack:"pr"` // "http/1.1" - stored for history/replay

	// RequestLineEnding is the terminator observed on the request line.
	RequestLineEnding LineEnding `json:"request_line_ending,omitempty" msgpack:"rle,omitempty"`

	// HeaderBlockEnding is the terminator observed on the blank line that ends the header block.
	HeaderBlockEnding LineEnding `json:"header_block_ending,omitempty" msgpack:"hbe,omitempty"`

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

	// Chunks preserves per-chunk wire framing for chunked messages.
	// When body is mutated, callers must set to nil to avoid stale state being re-emitted.
	Chunks []ChunkFrame `json:"chunks,omitempty" msgpack:"ck,omitempty"`

	// StatusLineEnding is the terminator observed on the status line.
	StatusLineEnding LineEnding `json:"status_line_ending,omitempty" msgpack:"sle,omitempty"`

	// HeaderBlockEnding is the terminator observed on the blank line that ends the header block.
	HeaderBlockEnding LineEnding `json:"header_block_ending,omitempty" msgpack:"hbe,omitempty"`

	// Wire contains metadata about the original wire encoding.
	// Used by SerializeRaw() to preserve exact wire format.
	Wire *WireFormat `json:"wire,omitempty" msgpack:"w,omitempty"`

	// CloseDelimited indicates the body was framed by connection close (no Content-Length, not chunked).
	CloseDelimited bool `json:"-" msgpack:"-"`
}

// GetHeader returns the first header value with the given name (case-insensitive).
func (r *RawHTTP1Request) GetHeader(name string) string { return r.Headers.Get(name) }

// SetHeader sets or replaces the first header with the given name (case-insensitive).
func (r *RawHTTP1Request) SetHeader(name, value string) { r.Headers.Set(name, value) }

// RemoveHeader removes all headers with the given name (case-insensitive).
func (r *RawHTTP1Request) RemoveHeader(name string) { r.Headers.Remove(name) }

// SetBody replaces the body and clears wire state which can't be replicated with a body change.
func (r *RawHTTP1Request) SetBody(b []byte) {
	r.Body = b
	r.Chunks = nil
}

// Clone returns a copy safe to mutate without affecting the receiver. Headers are deep-copied
// because in-place rule application mutates header elements; Body/Trailers/Chunks/Wire are
// reassigned wholesale by callers (never mutated in place), so sharing them is safe.
func (r *RawHTTP1Request) Clone() *RawHTTP1Request {
	c := *r
	c.Headers = slices.Clone(r.Headers)
	return &c
}

// GetHeader returns the first header value with the given name (case-insensitive).
func (r *RawHTTP1Response) GetHeader(name string) string { return r.Headers.Get(name) }

// SetHeader sets or replaces the first header with the given name (case-insensitive).
func (r *RawHTTP1Response) SetHeader(name, value string) { r.Headers.Set(name, value) }

// RemoveHeader removes all headers with the given name (case-insensitive).
func (r *RawHTTP1Response) RemoveHeader(name string) { r.Headers.Remove(name) }

// SetBody replaces the body and clears wire state which can't be replicated with a body change.
func (r *RawHTTP1Response) SetBody(b []byte) {
	r.Body = b
	r.Chunks = nil
}

// BodyCodec is the transform chain and logical content-type mapping a Message's
// BodyRaw to its Body, supplied by adapters whose wire form sectool cannot
// natively decode.
type BodyCodec struct {
	Transforms  []string `json:"transforms,omitempty" msgpack:"tr,omitempty"`
	ContentType string   `json:"content_type,omitempty" msgpack:"ct,omitempty"`
}

// Message is the common store envelope for one side of a Flow. It is the
// structural union of RawHTTP1Request and RawHTTP1Response: a request side
// leaves the status fields zero, a response side leaves method/path/query zero.
// Wire-fidelity fields carry over verbatim for HTTP/1.1; HTTP/2 folds its
// pseudo-headers into Headers (":method", ":status", etc).
type Message struct {
	// Request-line fields (request side)
	Method string `json:"method,omitempty" msgpack:"m,omitempty"`
	Path   string `json:"path,omitempty" msgpack:"p,omitempty"`
	Query  string `json:"query,omitempty" msgpack:"q,omitempty"`

	// Version is "HTTP/1.1" / "HTTP/1.0" on either side.
	Version string `json:"version,omitempty" msgpack:"v,omitempty"`

	// Status-line fields (response side)
	StatusCode int    `json:"status_code,omitempty" msgpack:"sc,omitempty"`
	StatusText string `json:"status_text,omitempty" msgpack:"st,omitempty"`

	// Headers preserves order and original name casing/whitespace.
	Headers Headers `json:"headers" msgpack:"h"`

	// Body is the message body (decoded if chunked, raw otherwise).
	Body []byte `json:"body,omitempty" msgpack:"b,omitempty"`

	// BodyRaw holds the original wire bytes, set by an adapter only when they
	// differ from a decoded logical Body (protobuf, custom framing). nil
	// whenever Body already is the wire payload (HTTP and most flows). Replayed
	// verbatim when Body is unmutated.
	BodyRaw []byte `json:"body_raw,omitempty" msgpack:"br,omitempty"`

	// BodyCodec is the transform chain and logical content-type mapping BodyRaw
	// to Body, used to re-encode a mutated Body on replay. Set only with BodyRaw.
	BodyCodec *BodyCodec `json:"body_codec,omitempty" msgpack:"bc,omitempty"`

	// Trailers for chunked encoding (raw bytes).
	Trailers []byte `json:"trailers,omitempty" msgpack:"t,omitempty"`

	// Chunks preserves per-chunk wire framing for chunked messages.
	Chunks []ChunkFrame `json:"chunks,omitempty" msgpack:"ck,omitempty"`

	// FirstLineEnding is the terminator on the request-line or status-line.
	FirstLineEnding LineEnding `json:"first_line_ending,omitempty" msgpack:"fle,omitempty"`

	// HeaderBlockEnding is the terminator on the blank line ending the header block.
	HeaderBlockEnding LineEnding `json:"header_block_ending,omitempty" msgpack:"hbe,omitempty"`

	// Wire contains metadata about the original wire encoding.
	Wire *WireFormat `json:"wire,omitempty" msgpack:"w,omitempty"`

	// CloseDelimited indicates a response body framed by connection close.
	CloseDelimited bool `json:"-" msgpack:"-"`
}

// GetHeader returns the first header value with the given name (case-insensitive).
func (m *Message) GetHeader(name string) string { return m.Headers.Get(name) }

// SetHeader sets or replaces the first header with the given name (case-insensitive).
func (m *Message) SetHeader(name, value string) { m.Headers.Set(name, value) }

// RemoveHeader removes all headers with the given name (case-insensitive).
func (m *Message) RemoveHeader(name string) { m.Headers.Remove(name) }

// SetBody replaces the body and clears chunk wire state.
func (m *Message) SetBody(b []byte) {
	m.Body = b
	m.Chunks = nil
}

// RequestToMessage converts a parsed HTTP/1.1 request into a store Message.
func RequestToMessage(r *RawHTTP1Request) *Message {
	return &Message{
		Method:            r.Method,
		Path:              r.Path,
		Query:             r.Query,
		Version:           r.Version,
		Headers:           r.Headers,
		Body:              r.Body,
		Trailers:          r.Trailers,
		Chunks:            r.Chunks,
		FirstLineEnding:   r.RequestLineEnding,
		HeaderBlockEnding: r.HeaderBlockEnding,
		Wire:              r.Wire,
	}
}

// ResponseToMessage converts a parsed HTTP/1.1 response into a store Message.
func ResponseToMessage(r *RawHTTP1Response) *Message {
	return &Message{
		Version:           r.Version,
		StatusCode:        r.StatusCode,
		StatusText:        r.StatusText,
		Headers:           r.Headers,
		Body:              r.Body,
		Trailers:          r.Trailers,
		Chunks:            r.Chunks,
		FirstLineEnding:   r.StatusLineEnding,
		HeaderBlockEnding: r.HeaderBlockEnding,
		Wire:              r.Wire,
		CloseDelimited:    r.CloseDelimited,
	}
}

// toRawRequest converts the Message back into a wire-serializable request.
func (m *Message) toRawRequest() *RawHTTP1Request {
	return &RawHTTP1Request{
		Method:            m.Method,
		Path:              m.Path,
		Query:             m.Query,
		Version:           m.Version,
		Headers:           m.Headers,
		Body:              m.Body,
		Trailers:          m.Trailers,
		Chunks:            m.Chunks,
		Protocol:          ProtocolHTTP11,
		RequestLineEnding: m.FirstLineEnding,
		HeaderBlockEnding: m.HeaderBlockEnding,
		Wire:              m.Wire,
	}
}

// toRawResponse converts the Message back into a wire-serializable response.
func (m *Message) toRawResponse() *RawHTTP1Response {
	return &RawHTTP1Response{
		Version:           m.Version,
		StatusCode:        m.StatusCode,
		StatusText:        m.StatusText,
		Headers:           m.Headers,
		Body:              m.Body,
		Trailers:          m.Trailers,
		Chunks:            m.Chunks,
		StatusLineEnding:  m.FirstLineEnding,
		HeaderBlockEnding: m.HeaderBlockEnding,
		Wire:              m.Wire,
		CloseDelimited:    m.CloseDelimited,
	}
}

// HistoryMeta holds lightweight metadata extracted at store time.
// Used by summary/list paths to avoid deserializing full request/response bodies.
type HistoryMeta struct {
	FlowID       string `msgpack:"fid"`
	Protocol     string `msgpack:"pr"`
	Adapter      string `msgpack:"ad,omitempty"`
	ParentFlowID string `msgpack:"pid,omitempty"`

	Scheme      string        `msgpack:"sc,omitempty"`
	Port        int           `msgpack:"po,omitempty"`
	Method      string        `msgpack:"m"`
	Host        string        `msgpack:"h"`
	Path        string        `msgpack:"p"` // includes query string
	Status      int           `msgpack:"s"`
	ContentType string        `msgpack:"ct"`
	RespLen     int           `msgpack:"rl"`
	Timestamp   time.Time     `msgpack:"ts"`
	Duration    time.Duration `msgpack:"d"`

	// Annotations carries the flow's sidecar-authored metadata.
	Annotations map[string]any `msgpack:"an,omitempty"`

	InvokedBy         string `msgpack:"ib,omitempty"`
	SidecarInstanceID string `msgpack:"si,omitempty"`
}

// Target specifies where to send a request.
type Target struct {
	Hostname  string
	Port      int
	UsesHTTPS bool
}

// Scheme returns "https" when UsesHTTPS, else "http".
func (t *Target) Scheme() string {
	if t.UsesHTTPS {
		return SchemeHTTPS
	}
	return SchemeHTTP
}

// RuleApplier applies find/replace rules to requests and responses.
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

	// ApplyRequestHeaderOnlyRules applies only request header rules to headers.
	// Used when a request head is processed before its body (H2, streaming).
	// Returns the possibly-modified headers; does not apply body rules.
	ApplyRequestHeaderOnlyRules(headers Headers) Headers

	// ApplyResponseHeaderOnlyRules applies only response header rules to headers.
	// Used when a response head is forwarded before its body (H2, streaming).
	// Returns the possibly-modified headers; does not apply body rules.
	ApplyResponseHeaderOnlyRules(headers Headers) Headers

	// ApplyWSRules applies WebSocket rules to frame payload.
	// direction is "ws:to-server" or "ws:to-client".
	ApplyWSRules(payload []byte, direction string) []byte

	// HasBodyRules returns true if there are body rules for request or response.
	// Used by HTTP/2 handler to decide whether to buffer full bodies.
	// isRequest=true checks for request_body rules, false checks for response_body rules.
	HasBodyRules(isRequest bool) bool
}

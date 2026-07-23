package wire

import (
	"bytes"
	"encoding/json"
	"slices"
	"time"
)

// ProtocolVersion is the major.minor contract version.
type ProtocolVersion struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

// Capabilities are the parameterized seams a sidecar declares. Each kind is a
// list, so one registration can claim multiple protocol entry points.
type Capabilities struct {
	EarlyClaims      []EarlyClaim      `json:"early_claims,omitempty"`
	UpgradeClaims    []UpgradeClaim    `json:"upgrade_claims,omitempty"`
	InjectionTargets []InjectionTarget `json:"injection_targets,omitempty"`
}

// PortRange is an inclusive TCP port span [Low, High].
type PortRange struct {
	Low  int `json:"low"`
	High int `json:"high"`
}

// TLSClaim configures TLS termination for an early claim.
type TLSClaim struct {
	Terminate bool   `json:"terminate"`
	SNIMatch  string `json:"sni_match,omitempty"`
	// Cert declares additive SANs for the leaf sectool mints when terminating.
	Cert *TLSCertSpec `json:"cert,omitempty"`
}

// TLSCertSpec declares additive Subject Alternative Names (and a legacy CommonName)
// to include on the minted terminated leaf, beyond the SNI-derived SAN. All fields
// are additive; the leaf always retains the dialed name.
type TLSCertSpec struct {
	DNSNames    []string `json:"dns_names,omitempty"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
	URIs        []string `json:"uris,omitempty"`
	Emails      []string `json:"emails,omitempty"`
	CommonName  string   `json:"common_name,omitempty"`
}

// EarlyClaim claims TCP connections at accept on a port range.
type EarlyClaim struct {
	PortRange PortRange `json:"port_range"`
	TLS       *TLSClaim `json:"tls,omitempty"`
	// MagicBytesPrefix carries base64-encoded opening bytes.
	MagicBytesPrefix string `json:"magic_bytes_prefix,omitempty"`
	HostMatch        string `json:"host_match,omitempty"`
	Probe            bool   `json:"probe,omitempty"`
	ProbeMaxBytes    int    `json:"probe_max_bytes,omitempty"`
}

// UpgradeClaim claims a byte stream after an HTTP upgrade signal.
type UpgradeClaim struct {
	// HostPattern is an RE2 pattern matched against the whole host; empty matches any.
	HostPattern string `json:"host_pattern,omitempty"`
	// PathPattern is an RE2 pattern matched against the whole path; empty matches any.
	PathPattern string `json:"path_pattern,omitempty"`
	// UpgradeSignal is http_101 or connect; empty defaults to http_101.
	UpgradeSignal string `json:"upgrade_signal,omitempty"`
	// MethodSet limits the claim to these request methods; empty matches any.
	MethodSet []string `json:"method_set,omitempty"`
}

// InjectionTarget declares the sidecar can originate outbound messages.
type InjectionTarget struct {
	TargetSchema json.RawMessage `json:"target_schema,omitempty"`
}

// MCPTool is a tool definition the sidecar provides.
type MCPTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
}

// InvokeToolParams delegates an MCP client's call of a sidecar-registered tool.
// Arguments are validated against the tool's input_schema before delegation.
type InvokeToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// InvokeToolResult is the sidecar tool's result, returned verbatim to the MCP client.
type InvokeToolResult struct {
	// Content is markdown text.
	Content string `json:"content,omitempty"`
	// StructuredContent is optional structured content.
	StructuredContent json.RawMessage `json:"structured_content,omitempty"`
	IsError           bool            `json:"is_error,omitempty"`
}

// RegisterParams is the sidecar's first message.
type RegisterParams struct {
	Name            string          `json:"name"`
	ProtocolVersion ProtocolVersion `json:"protocol_version"`
	Protocols       []string        `json:"protocols"`
	Capabilities    Capabilities    `json:"capabilities"`
	MCPTools        []MCPTool       `json:"mcp_tools,omitempty"`
	InstanceID      string          `json:"instance_id,omitempty"`
	Resume          bool            `json:"resume,omitempty"`
}

// RegisterResult is sectool's response to register.
type RegisterResult struct {
	ProtocolVersion ProtocolVersion `json:"protocol_version"`
	ServerTime      string          `json:"server_time"`
}

// Rule type values for the Type field, shared by sectool and sidecars.
const (
	RuleTypeRequestHeader  = "request_header"
	RuleTypeRequestBody    = "request_body"
	RuleTypeResponseHeader = "response_header"
	RuleTypeResponseBody   = "response_body"
	RuleTypeWSToServer     = "ws:to-server"
	RuleTypeWSToClient     = "ws:to-client"
	RuleTypeWSBoth         = "ws:both"
)

// Rule is a find/replace rule the sidecar applies on its hot path.
type Rule struct {
	RuleID  string `json:"rule_id"`
	Type    string `json:"type"`
	Label   string `json:"label,omitempty"`
	IsRegex bool   `json:"is_regex,omitempty"`
	Find    string `json:"find,omitempty"`
	Replace string `json:"replace,omitempty"`
	// Adapter scopes the rule: empty applies to every adapter, otherwise names the owning sidecar.
	Adapter string `json:"adapter,omitempty"`
}

// SyncRulesParams carries the full ordered rule list that replaces the sidecar's cache.
type SyncRulesParams struct {
	Rules []Rule `json:"rules"`
}

// SyncRulesResult acks a sync_rules push.
type SyncRulesResult struct {
	Ack bool `json:"ack"`
}

// ShutdownParams requests a graceful close.
type ShutdownParams struct {
	DrainSeconds int `json:"drain_seconds"`
}

// ShutdownResult acknowledges a shutdown request.
type ShutdownResult struct {
	Ack bool `json:"ack"`
}

// Header is a single name-value metadata entry on a message.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// BodyCodec describes how Body was derived from BodyRaw, used on replay to
// re-encode a mutated Body back to the wire form.
type BodyCodec struct {
	// Transforms is the ordered transform chain (e.g. decryption, decompression, de-framing).
	Transforms []string `json:"transforms,omitempty"`
	// ContentType is the logical content-type.
	ContentType string `json:"content_type,omitempty"`
}

// FlowMessage is one side of a flow: request or response. Byte fields are base64 in JSON.
type FlowMessage struct {
	Method     string   `json:"method,omitempty"`
	Path       string   `json:"path,omitempty"`
	Query      string   `json:"query,omitempty"`
	StatusCode int      `json:"status_code,omitempty"`
	StatusText string   `json:"status_text,omitempty"`
	Headers    []Header `json:"headers,omitempty"`
	// Body is the logical payload every tool operates on.
	Body []byte `json:"body,omitempty"`
	// BodyRaw and BodyCodec carry the wire form when Body is not natively decodable by sectool.
	BodyRaw   []byte     `json:"body_raw,omitempty"`
	BodyCodec *BodyCodec `json:"body_codec,omitempty"`
}

// Clone returns a copy whose Headers, Body, and BodyRaw can be mutated without
// touching the source. BodyCodec is immutable and shared.
func (m *FlowMessage) Clone() *FlowMessage {
	out := *m
	out.Headers = slices.Clone(m.Headers)
	out.Body = bytes.Clone(m.Body)
	out.BodyRaw = bytes.Clone(m.BodyRaw)
	return &out
}

// Flow is a captured exchange a sidecar publishes via push_flow.
type Flow struct {
	// FlowID is empty on first emission (sectool assigns) and set to re-target an
	// existing flow for two-phase completion or session/stream teardown.
	FlowID       string         `json:"flow_id,omitempty"`
	Adapter      string         `json:"adapter,omitempty"`
	ProtocolTag  string         `json:"protocol_tag,omitempty"`
	Direction    string         `json:"direction,omitempty"`
	ParentFlowID string         `json:"parent_flow_id,omitempty"`
	Scheme       string         `json:"scheme,omitempty"`
	Port         int            `json:"port,omitempty"`
	Request      *FlowMessage   `json:"request,omitempty"`
	Response     *FlowMessage   `json:"response,omitempty"`
	StartedAt    time.Time      `json:"started_at,omitempty"`
	CompletedAt  time.Time      `json:"completed_at,omitempty"`
	Annotations  map[string]any `json:"annotations,omitempty"`
}

// PushFlowParams is the Flow emitted via push_flow.
type PushFlowParams = Flow

// PushFlowResult carries the flow_id sectool assigned (or echoed back).
type PushFlowResult struct {
	FlowID string `json:"flow_id"`
}

// LogParams is a structured diagnostic log line.
type LogParams struct {
	Level   string         `json:"level,omitempty"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields,omitempty"`
}

// ReportMetricsParams carries counter and gauge samples.
type ReportMetricsParams struct {
	Counters map[string]int64   `json:"counters,omitempty"`
	Gauges   map[string]float64 `json:"gauges,omitempty"`
}

// CoreInvokeParams invokes a core MCP tool by name.
type CoreInvokeParams struct {
	Tool   string          `json:"tool"`
	Params json.RawMessage `json:"params,omitempty"`
}

// CoreInvokeResult is the core tool's result text.
type CoreInvokeResult struct {
	Content string `json:"content"`
	IsError bool   `json:"is_error,omitempty"`
}

// StreamWrite is one entry in a writes array: bytes for sectool to write to the named stream's socket.
type StreamWrite struct {
	// StreamID names the target stream, which may differ from the stream the event arrived on.
	StreamID string `json:"stream_id"`
	Data     []byte `json:"data"`
}

// StreamResult replies to stream_open and stream_deliver, naming the streams the
// sidecar wrote to while handling the event. Bytes travel as stream_write.
type StreamResult struct {
	WroteTo []string `json:"wrote_to,omitempty"`
}

// StreamOpenParams announces that a claim fired and a new stream exists.
type StreamOpenParams struct {
	StreamID string `json:"stream_id"`
	Host     string `json:"host,omitempty"`
	Path     string `json:"path,omitempty"`
	PeerAddr string `json:"peer_addr,omitempty"`
	// RequestFlowID is the captured triggering request's flow, set only for an
	// upgrade_claim; absent for an early_claim.
	RequestFlowID string `json:"request_flow_id,omitempty"`
	// RequestHeaders are the triggering request's headers, set only for an
	// upgrade_claim; absent for an early_claim.
	RequestHeaders []Header `json:"request_headers,omitempty"`
}

// StreamWriteParams carries stream bytes in either direction: sectool's
// stream_deliver of inbound socket bytes to the sidecar, and the sidecar's
// proactive stream_write for keepalives and other timer-driven output.
type StreamWriteParams struct {
	StreamID string `json:"stream_id"`
	Data     []byte `json:"data"`
}

// StreamEndedParams signals a stream close in either direction: sectool's
// stream_ended notification to the sidecar, and the sidecar's proactive close_stream.
type StreamEndedParams struct {
	StreamID string `json:"stream_id"`
	Reason   string `json:"reason,omitempty"`
	// Abort closes immediately, dropping the writes already queued for the stream
	// rather than closing after them; close_stream only.
	Abort bool `json:"abort,omitempty"`
}

// ClaimProbeParams asks the sidecar whether a buffered opening stream is its
// protocol, for an early_claim that set probe.
type ClaimProbeParams struct {
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	PeerAddr string `json:"peer_addr,omitempty"`
	SNI      string `json:"sni,omitempty"`
	Data     []byte `json:"data,omitempty"`
}

// ClaimProbeResult is the sidecar's claim decision. A false claim is normal control flow, not an error.
type ClaimProbeResult struct {
	Claim bool `json:"claim"`
}

// DialUpstreamTLS configures TLS termination toward the upstream. When Enabled,
// sectool performs the handshake and bridges cleartext bytes to the sidecar.
type DialUpstreamTLS struct {
	Enabled    bool     `json:"enabled"`
	SNI        string   `json:"sni,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
	SkipVerify bool     `json:"skip_verify,omitempty"`
}

// DialUpstreamParams asks sectool to open an upstream TCP connection on the sidecar's behalf.
type DialUpstreamParams struct {
	// Host and Port, when omitted, default to the original destination of
	// ParentFlowID's connection; supplying them redirects to a different upstream.
	Host         string           `json:"host,omitempty"`
	Port         int              `json:"port,omitempty"`
	TLS          *DialUpstreamTLS `json:"tls,omitempty"`
	ParentFlowID string           `json:"parent_flow_id,omitempty"`
}

// DialUpstreamResult carries the stream identifier for the opened upstream socket.
type DialUpstreamResult struct {
	StreamID string `json:"stream_id"`
}

// Mutation op names, the shared vocabulary of the replay/origination and sidecar send paths.
const (
	OpSetHeader    = "set_header"
	OpRemoveHeader = "remove_header"
	OpSetJSON      = "set_json"
	OpRemoveJSON   = "remove_json"
	OpSetForm      = "set_form"
	OpRemoveForm   = "remove_form"
	OpSetQuery     = "set_query"
	OpRemoveQuery  = "remove_query"
	OpMethod       = "method"
	OpPath         = "path"
	OpQuery        = "query"
	OpBody         = "body"
)

// Mutation is one replay/origination edit applied in array order.
type Mutation struct {
	// Op names a shared mutation: set_header/remove_header, set_json/remove_json,
	// set_form/remove_form, set_query/remove_query, method, path, query, body.
	Op string `json:"op"`
	// Name holds the header name, JSON/query path, or form field for the keyed ops.
	Name string `json:"name,omitempty"`
	// Value holds the new value (the whole payload for method/path/query/body).
	Value string `json:"value,omitempty"`
}

// SidecarSendParams drives a replay or origination on the owning adapter.
type SidecarSendParams struct {
	// FlowID, when set, selects the flow to replay.
	FlowID string `json:"flow_id,omitempty"`
	// Flow carries the resolved source so the adapter has body/body_raw/body_codec without a round-trip.
	Flow *Flow `json:"flow,omitempty"`
	// Destination is an optional scheme://host[:port] routing override (replay).
	Destination     string          `json:"destination,omitempty"`
	Target          json.RawMessage `json:"target,omitempty"`
	Payload         json.RawMessage `json:"payload,omitempty"`
	Mutations       []Mutation      `json:"mutations,omitempty"`
	FollowRedirects bool            `json:"follow_redirects,omitempty"`
	Force           bool            `json:"force,omitempty"`
	// WaitForResponse defaults to true when nil.
	WaitForResponse *bool  `json:"wait_for_response,omitempty"`
	StreamStrategy  string `json:"stream_strategy,omitempty"`
}

// SidecarSendResult reports the outcome of a replay/origination.
type SidecarSendResult struct {
	// NewFlowIDs are the flows the replay/origination produced.
	NewFlowIDs []string `json:"new_flow_ids,omitempty"`
	// Writes are the optional first outbound bytes.
	Writes []StreamWrite `json:"writes,omitempty"`
	// Response is the completed response form when WaitForResponse was set.
	Response *FlowMessage `json:"response,omitempty"`
}

// InvokeAdapterParams routes an outbound message through another adapter's
// injection_target. Target/Payload are validated by the destination adapter, not
// sectool. WaitForResponse defaults to true when nil.
type InvokeAdapterParams struct {
	Adapter         string          `json:"adapter"`
	Target          json.RawMessage `json:"target,omitempty"`
	Payload         json.RawMessage `json:"payload,omitempty"`
	Mutations       []Mutation      `json:"mutations,omitempty"`
	WaitForResponse *bool           `json:"wait_for_response,omitempty"`
}

// InvokeAdapterResult carries the produced flows and optional response form.
type InvokeAdapterResult struct {
	NewFlowIDs []string     `json:"new_flow_ids,omitempty"`
	Response   *FlowMessage `json:"response,omitempty"`
}

package types

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Flow is the generalized store record for one logical exchange. It carries an
// optional request and response Message under a single flow_id. Child flows
// (e.g. WebSocket frames) reference a parent via ParentFlowID.
type Flow struct {
	// FlowID is the unique identifier, minted at Store time.
	FlowID string `json:"flow_id" msgpack:"fid"`

	// Adapter is the name of the adapter that emitted the flow.
	Adapter string `json:"adapter" msgpack:"ad"`

	// ProtocolTag is the protocol identifier within the adapter
	// (e.g. "http/1.1", "http/2", "websocket", "websocket.frame").
	ProtocolTag string `json:"protocol_tag" msgpack:"pr"`

	// Direction orients a one-way message: client_to_server, server_to_client,
	// or bidirectional. Empty for two-sided request/response flows.
	Direction string `json:"direction,omitempty" msgpack:"dir,omitempty"`

	// ParentFlowID links a child flow to its parent (e.g. a frame to its handshake).
	ParentFlowID string `json:"parent_flow_id,omitempty" msgpack:"pid,omitempty"`

	// Scheme is the captured request scheme ("http" or "https").
	Scheme string `json:"scheme,omitempty" msgpack:"sc,omitempty"`
	// Port is the captured upstream port.
	Port int `json:"port,omitempty" msgpack:"po,omitempty"`

	// Request and/or Response sides of the exchange.
	Request  *Message `json:"request,omitempty" msgpack:"rq,omitempty"`
	Response *Message `json:"response,omitempty" msgpack:"rs,omitempty"`

	// InterimResponses holds 1xx responses received before the final Response.
	InterimResponses []*Message `json:"interim_responses,omitempty" msgpack:"ir,omitempty"`

	// Timing metadata.
	StartedAt   time.Time `json:"started_at" msgpack:"ts"`
	CompletedAt time.Time `json:"completed_at,omitempty" msgpack:"ca,omitempty"`

	// Annotations is open-ended, exclusively sidecar-authored metadata.
	Annotations map[string]any `json:"annotations,omitempty" msgpack:"an,omitempty"`

	// InvokedBy names the sidecar that originated a cross-adapter message.
	InvokedBy string `json:"invoked_by,omitempty" msgpack:"ib,omitempty"`
	// SidecarInstanceID attributes a sidecar-emitted flow.
	SidecarInstanceID string `json:"sidecar_instance_id,omitempty" msgpack:"si,omitempty"`
}

// ExtractMeta builds HistoryMeta from a Flow using its accessor methods.
func (f *Flow) ExtractMeta() HistoryMeta {
	// zero CompletedAt marks an in-progress stream; report zero duration
	var duration time.Duration
	if !f.CompletedAt.IsZero() {
		duration = f.CompletedAt.Sub(f.StartedAt)
	}
	return HistoryMeta{
		FlowID:       f.FlowID,
		Protocol:     f.ProtocolTag,
		Adapter:      f.Adapter,
		ParentFlowID: f.ParentFlowID,
		Scheme:       f.Scheme,
		Port:         f.Port,
		Method:       f.GetMethod(),
		Host:         f.GetHost(),
		Path:         f.getFullPath(),
		Status:       f.GetStatusCode(),
		ContentType:  f.GetResponseHeader("content-type"),
		RespLen:      f.responseBodyLen(),
		Timestamp:    f.StartedAt,
		Duration:     duration,
		Annotations:  f.Annotations,

		InvokedBy:         f.InvokedBy,
		SidecarInstanceID: f.SidecarInstanceID,
	}
}

// isH2 reports whether the flow's request side carries folded HTTP/2 pseudo-headers.
func (f *Flow) isH2() bool { return f.ProtocolTag == ProtocolH2 }

// getFullPath returns path including query string for summary/meta display.
// For HTTP/1.1, concatenates Path + "?" + Query when Query is non-empty.
// For H2, :path already includes the query.
func (f *Flow) getFullPath() string {
	if f.Request == nil {
		return ""
	} else if f.isH2() {
		return f.Request.GetHeader(":path")
	} else if f.Request.Query != "" {
		return f.Request.Path + "?" + f.Request.Query
	}
	return f.Request.Path
}

// responseBodyLen returns the length of the response body.
func (f *Flow) responseBodyLen() int {
	if f.Response != nil {
		return len(f.Response.Body)
	}
	return 0
}

// FormatRequest returns the request in wire-compatible format.
// For HTTP/1.1, uses SerializeRaw to preserve anomalies like bare-LF.
// For HTTP/2, rebuilds HTTP/1.1-style text from the folded pseudo-headers.
func (f *Flow) FormatRequest(buf *bytes.Buffer) []byte {
	if f.Request == nil {
		return nil
	} else if f.isH2() {
		return formatH2Request(buf, f.Request)
	}
	return f.Request.toRawRequest().SerializeRaw(buf)
}

// FormatResponse returns the response in wire-compatible format.
// For HTTP/1.1, uses SerializeRaw to preserve anomalies like bare-LF.
// For HTTP/2, rebuilds HTTP/1.1-style text from the folded pseudo-headers.
func (f *Flow) FormatResponse(buf *bytes.Buffer) []byte {
	if f.Response == nil {
		return nil
	} else if f.isH2() {
		return formatH2Response(buf, f.Response)
	}
	return f.Response.toRawResponse().SerializeRaw(buf)
}

// FormatInterimResponses returns each 1xx response in wire form (HTTP/1.1 only).
func (f *Flow) FormatInterimResponses(buf *bytes.Buffer) []string {
	if len(f.InterimResponses) == 0 {
		return nil
	}
	out := make([]string, 0, len(f.InterimResponses))
	for _, ir := range f.InterimResponses {
		out = append(out, string(ir.toRawResponse().SerializeRaw(buf)))
	}
	return out
}

// GetMethod returns the request method.
func (f *Flow) GetMethod() string {
	if f.Request == nil {
		return ""
	} else if f.isH2() {
		return f.Request.GetHeader(":method")
	}
	return f.Request.Method
}

// GetPath returns the URL path without query string.
// For H2, strips the query portion since :path includes it.
func (f *Flow) GetPath() string {
	if f.Request == nil {
		return ""
	} else if f.isH2() {
		path := f.Request.GetHeader(":path")
		if idx := strings.IndexByte(path, '?'); idx >= 0 {
			return path[:idx]
		}
		return path
	}
	return f.Request.Path
}

// GetHost returns the request host.
func (f *Flow) GetHost() string {
	if f.Request == nil {
		return ""
	} else if f.isH2() {
		return f.Request.GetHeader(":authority")
	}
	return f.Request.GetHeader("Host")
}

// GetStatusCode returns the response status code.
func (f *Flow) GetStatusCode() int {
	if f.Response != nil {
		return f.Response.StatusCode
	}
	return 0
}

// GetRequestHeader returns a request header value (case-insensitive).
func (f *Flow) GetRequestHeader(name string) string {
	if f.Request != nil {
		return f.Request.GetHeader(name)
	}
	return ""
}

// GetResponseHeader returns a response header value (case-insensitive).
func (f *Flow) GetResponseHeader(name string) string {
	if f.Response != nil {
		return f.Response.GetHeader(name)
	}
	return ""
}

// isPseudoOrStreamHeader reports headers that must not be re-emitted when
// rebuilding HTTP/1.1-style text: HTTP/2 pseudo-headers and the synthetic stream id.
func isPseudoOrStreamHeader(name string) bool {
	return strings.HasPrefix(name, ":") || strings.EqualFold(name, HeaderStreamID)
}

// formatH2Request rebuilds an HTTP/1.1-style request from a folded HTTP/2 Message
// for display and replay. The HTTP/1.1 version keeps it parseable by the standard
// parser; pseudo-headers and the stream id are reconstructed into the request line
// and host, never re-emitted as headers.
func formatH2Request(buf *bytes.Buffer, req *Message) []byte {
	buf.Reset()

	buf.WriteString(req.GetHeader(":method"))
	buf.WriteByte(' ')
	buf.WriteString(req.GetHeader(":path"))
	buf.WriteString(" HTTP/1.1\r\n")

	buf.WriteString("host: ")
	buf.WriteString(req.GetHeader(":authority"))
	buf.WriteString("\r\n")

	for _, h := range req.Headers {
		if isPseudoOrStreamHeader(h.Name) {
			continue
		}
		buf.WriteString(h.Name)
		buf.WriteString(": ")
		buf.WriteString(h.Value)
		buf.WriteString("\r\n")
	}

	buf.WriteString("\r\n")
	buf.Write(req.Body)

	return buf.Bytes()
}

// formatH2Response rebuilds an HTTP/1.1-style response from a folded HTTP/2 Message.
func formatH2Response(buf *bytes.Buffer, resp *Message) []byte {
	buf.Reset()

	buf.WriteString("HTTP/2 ")
	buf.WriteString(strconv.Itoa(resp.StatusCode))
	text := http.StatusText(resp.StatusCode)
	if text != "" {
		buf.WriteByte(' ')
		buf.WriteString(text)
	}
	buf.WriteString("\r\n")

	for _, h := range resp.Headers {
		if isPseudoOrStreamHeader(h.Name) {
			continue
		}
		buf.WriteString(h.Name)
		buf.WriteString(": ")
		buf.WriteString(h.Value)
		buf.WriteString("\r\n")
	}

	buf.WriteString("\r\n")
	buf.Write(resp.Body)

	return buf.Bytes()
}

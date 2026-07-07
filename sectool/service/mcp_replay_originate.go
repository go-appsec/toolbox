package service

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// nativeSendSpec is the request shape a sidecar supplies to originate an HTTP
// request through the native proxy. It mirrors request_send: a sidecar may put
// everything in target or split body into payload.
type nativeSendSpec struct {
	URL             string          `json:"url"`
	Method          string          `json:"method"`
	Headers         json.RawMessage `json:"headers"` // object {"Name":"Value"} or array ["Name: Value"]
	Body            string          `json:"body"`
	FollowRedirects bool            `json:"follow_redirects"`
	Force           bool            `json:"force"`
}

// originateNative originates an outbound HTTP request through the native send
// path on a sidecar's behalf, producing an attributable history flow. invokedBy
// names the calling sidecar. It honors wait_for_response (default true): the
// response form is returned only when waiting.
func (m *mcpServer) originateNative(ctx context.Context, p wire.SidecarSendParams, invokedBy string) (wire.SidecarSendResult, *wire.Error) {
	var spec nativeSendSpec
	if len(p.Target) > 0 {
		if err := json.Unmarshal(p.Target, &spec); err != nil {
			return wire.SidecarSendResult{}, injectError("invalid target: "+err.Error(), invokedBy)
		}
	}
	// Payload overlays target, so a sidecar may split body out of the routing target
	if len(p.Payload) > 0 {
		if err := json.Unmarshal(p.Payload, &spec); err != nil {
			return wire.SidecarSendResult{}, injectError("invalid payload: "+err.Error(), invokedBy)
		}
	}
	if spec.URL == "" {
		return wire.SidecarSendResult{}, injectError("url is required", invokedBy)
	}

	method := spec.Method
	if method == "" {
		method = "GET"
	}

	var headers []string
	if len(spec.Headers) > 0 {
		var raw any
		if err := json.Unmarshal(spec.Headers, &raw); err != nil {
			return wire.SidecarSendResult{}, injectError("invalid headers: "+err.Error(), invokedBy)
		}
		headers = parseHeaderArg(raw)
	}

	body := []byte(spec.Body)
	// Compress the base body when a base Content-Encoding is set (mirrors request_send)
	if len(body) > 0 {
		for i, h := range headers {
			name, value, ok := splitPair(h, ":")
			if !ok || !strings.EqualFold(name, "Content-Encoding") {
				continue
			}
			var failed bool
			if body, failed = compressBody(body, value); failed {
				headers = append(headers[:i], headers[i+1:]...)
			}
			break
		}
	}

	parsedURL, err := parseURLWithDefaultHTTPS(spec.URL)
	if err != nil {
		return wire.SidecarSendResult{}, injectError("invalid URL: "+err.Error(), invokedBy)
	}
	rawRequest := buildRawRequestManual(method, parsedURL, headers, body)

	opts, mods := mutationsToOpts(p.Mutations)
	rawRequest = modifyRequestLine(rawRequest, &opts)
	mods.Target = parsedURL.Scheme + "://" + parsedURL.Host
	mods.Force = spec.Force || p.Force
	mods.FollowRedirects = spec.FollowRedirects || p.FollowRedirects
	mods.UserSetHost = proxy.ContainsHeader(headers, "Host") || proxy.ContainsHeader(mods.SetHeaders, "Host")

	flowID, result, short, err := m.executeSendFlow(ctx, rawRequest, "http/1.1", mods, "", invokedBy)
	if err != nil {
		return wire.SidecarSendResult{}, injectError(err.Error(), invokedBy)
	} else if short != nil {
		return wire.SidecarSendResult{}, injectError(callResultText(short), invokedBy)
	}

	res := wire.SidecarSendResult{NewFlowIDs: []string{flowID}}
	if p.WaitForResponse == nil || *p.WaitForResponse {
		res.Response = responseForm(result)
	}
	return res, nil
}

// mutationsToOpts translates a wire mutation list into the native request-line
// options and send modifications. It is the inverse of buildMutations; the two
// must stay in sync so both paths support the same ops.
func mutationsToOpts(muts []wire.Mutation) (PathQueryOpts, sendModifications) {
	var opts PathQueryOpts
	mods := sendModifications{SetJSON: map[string]interface{}{}, SetForm: map[string]string{}}
	for _, mut := range muts {
		switch mut.Op {
		case opSetHeader:
			mods.SetHeaders = append(mods.SetHeaders, mut.Name+": "+mut.Value)
		case opRemoveHeader:
			mods.RemoveHeaders = append(mods.RemoveHeaders, mut.Name)
		case opSetJSON:
			mods.SetJSON[mut.Name] = mut.Value
		case opRemoveJSON:
			mods.RemoveJSON = append(mods.RemoveJSON, mut.Name)
		case opSetForm:
			mods.SetForm[mut.Name] = mut.Value
		case opRemoveForm:
			mods.RemoveForm = append(mods.RemoveForm, mut.Name)
		case opSetQuery:
			opts.SetQuery = append(opts.SetQuery, mut.Name+"="+mut.Value)
		case opRemoveQuery:
			opts.RemoveQuery = append(opts.RemoveQuery, mut.Name)
		case opMethod:
			opts.Method = mut.Value
			mods.Method = mut.Value
		case opPath:
			opts.Path = mut.Value
		case opQuery:
			opts.Query = mut.Value
		case opBody:
			mods.Body = mut.Value
		}
	}
	if len(mods.SetJSON) == 0 {
		mods.SetJSON = nil
	}
	if len(mods.SetForm) == 0 {
		mods.SetForm = nil
	}
	return opts, mods
}

// responseForm builds the wire response returned to a waiting caller from a
// completed native send. Body is the logical (decompressed) payload, matching
// flow_get; the original headers, including Content-Encoding, are preserved.
func responseForm(result *SendRequestResult) *wire.FlowMessage {
	body, _ := decompressForDisplay(result.Body, string(result.Headers))
	fm := &wire.FlowMessage{Body: body}
	if resp, err := readResponseBytes(result.Headers); err == nil {
		_ = resp.Body.Close()
		fm.StatusCode = resp.StatusCode
		fm.StatusText = strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)))
	}
	for _, h := range parseHeadersFromText(result.Headers) {
		fm.Headers = append(fm.Headers, wire.Header{Name: h.Name, Value: h.Value})
	}
	return fm
}

// injectError wraps a native origination failure as an invoke_adapter wire error.
func injectError(msg, adapter string) *wire.Error {
	return wire.NewError(wire.CodeInjectSendFailed, "invoke_adapter: "+msg).
		WithData(&wire.ErrorData{Adapter: adapter})
}

// callResultText extracts the text payload of an error tool result.
func callResultText(r *mcp.CallToolResult) string {
	if r == nil {
		return "native send failed"
	}
	for _, c := range r.Content {
		if tc, ok := mcp.AsTextContent(c); ok {
			return tc.Text
		}
	}
	return "native send failed"
}

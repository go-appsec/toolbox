package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/go-analyze/bulk"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/pkg/mutate"
	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/ids"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

func (m *mcpServer) replaySendTool() mcp.Tool {
	return mcp.NewTool("replay_send",
		mcp.WithDescription(`Replay a proxied request (flow_id from proxy_poll) with edits.
Active proxy rules (proxy_rule_add) are applied before sending.

Returns: flow_id, status, headers, response_preview. Full body via flow_get.
Replayed requests appear in proxy_poll history alongside captured traffic.

Processing: remove_* is applied before set_*. Content-Length auto-updates on body changes unless explicitly set. force=true skips validation for protocol-level tests (smuggling, CRLF injection).`),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow ID to use as base request")),
		mcp.WithString("method", mcp.Description("Override HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)")),
		mcp.WithString("body", mcp.Description("Replace entire request body")),
		mcp.WithString("target", mcp.Description("Override destination scheme+host[:port]; keeps original path/query")),
		mcp.WithArray("set_headers", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Headers to set (format: 'Name: Value'). A single entry replaces an existing header of the same name; multiple entries with the same name create duplicates.")),
		mcp.WithArray("remove_headers", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Header names to remove")),
		mcp.WithString("path", mcp.Description("Override request path (include leading '/')")),
		mcp.WithString("query", mcp.Description("Override entire query string (no leading '?')")),
		mcp.WithArray("set_query", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Query params to set (format: 'name=value')")),
		mcp.WithArray("remove_query", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Query param names to remove")),
		mcp.WithObject("set_json", mcp.Description("JSON fields to set: {\"path\": value} using dot/bracket paths (e.g. {\"user.email\": \"x\", \"items[0].id\": 5}). Values auto-parse: null/true/false/numbers/{}/[], else string. Body must be valid JSON; for form-encoded bodies use set_form.")),
		mcp.WithArray("remove_json", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("JSON fields to remove (same dot/bracket path syntax as set_json: 'user.temp', 'items[2]')")),
		mcp.WithObject("set_form", mcp.Description("Form fields to set as object {\"field\": \"value\"} for application/x-www-form-urlencoded bodies (e.g. OAuth2 grant_type, scope). Keys are form-field names; values are strings. Do NOT use on JSON bodies, use set_json.")),
		mcp.WithArray("remove_form", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Form field names to remove (form-encoded bodies only)")),
		mcp.WithBoolean("follow_redirects", mcp.Description("Follow HTTP redirects (default: false)")),
		mcp.WithBoolean("force", mcp.Description("Skip validation for protocol-level tests (smuggling, CRLF injection)")),
		mcp.WithString("stream_strategy", mcp.Description("For streamed flows only: 'per_chunk' (default) replays chunk-by-chunk in order; 'collapsed' merges chunks (rejected by adapters requiring ordered framing)")),
	)
}

func (m *mcpServer) requestSendTool() mcp.Tool {
	return mcp.NewTool("request_send",
		mcp.WithDescription(`Send a request from scratch (no captured flow required).

Use this when you need to send a request to a URL without first capturing it via proxy.
Active proxy rules (proxy_rule_add) are applied before sending.
Returns: flow_id, status, headers, response_preview. Full body via flow_get.
Sent requests appear in proxy_poll history alongside captured traffic if additional modifications or resending needed.`),
		mcp.WithString("url", mcp.Required(), mcp.Description("Target URL (e.g., 'https://api.example.com/users')")),
		mcp.WithString("method", mcp.Description("HTTP method (default: GET)")),
		mcp.WithObject("headers", mcp.Description("Headers as object {\"Name\": \"Value\"} (alphabetical order) or array [\"Name: Value\"] (preserves order)")),
		mcp.WithString("body", mcp.Description("Request body content")),
		mcp.WithBoolean("follow_redirects", mcp.Description("Follow HTTP redirects (default: false)")),
		mcp.WithBoolean("force", mcp.Description("Skip validation for protocol-level tests")),
	)
}

// sendModifications holds all modification parameters for executeSend.
// handleReplaySend populates this from MCP params; handleRequestSend passes a zero value.
type sendModifications struct {
	Method          string // non-empty if method was overridden
	SetHeaders      []string
	RemoveHeaders   []string
	Target          string
	Body            string
	SetJSON         map[string]interface{}
	RemoveJSON      []string
	SetForm         map[string]string
	RemoveForm      []string
	Force           bool
	FollowRedirects bool
	UserSetHost     bool // user explicitly supplied a Host header
}

func (m *mcpServer) handleReplaySend(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	flowID := req.GetString("flow_id", "")
	if flowID == "" {
		return errorResult("flow_id is required"), nil
	}

	resolved, errResult := m.resolveFlow(ctx, flowID)
	if errResult != nil {
		return errResult, nil
	}

	// Sidecar-owned flows replay through their adapter (re-encode/re-wrap/send);
	// built-in HTTP flows fall through to the native path below
	if resolved.Adapter != "" && m.sidecars != nil && m.sidecars.HasAdapter(resolved.Adapter) {
		return m.replaySidecar(ctx, req, resolved.Adapter, flowID)
	}

	rawRequest := resolved.RawRequest
	httpProtocol := resolved.Protocol

	rawRequest = modifyRequestLine(rawRequest, &PathQueryOpts{
		Method:      req.GetString("method", ""),
		Path:        req.GetString("path", ""),
		Query:       req.GetString("query", ""),
		SetQuery:    req.GetStringSlice("set_query", nil),
		RemoveQuery: req.GetStringSlice("remove_query", nil),
	})

	setHeaders := getHeaderArg(req, "set_headers")
	target := req.GetString("target", "")

	// When no explicit target, reconstruct from stored scheme/port so
	// replaying an HTTP flow doesn't incorrectly default to HTTPS
	if target == "" && resolved.Scheme != "" {
		_, host, _ := extractRequestMeta(string(rawRequest))
		target = rebuildReplayTarget(host, resolved.Scheme, resolved.Port)
	}

	mods := sendModifications{
		Method:          req.GetString("method", ""),
		SetHeaders:      setHeaders,
		RemoveHeaders:   req.GetStringSlice("remove_headers", nil),
		Target:          target,
		Body:            req.GetString("body", ""),
		SetJSON:         getJSONArg(req),
		RemoveJSON:      req.GetStringSlice("remove_json", nil),
		SetForm:         getFormArg(req),
		RemoveForm:      req.GetStringSlice("remove_form", nil),
		Force:           req.GetBool("force", false),
		FollowRedirects: req.GetBool("follow_redirects", false),
		UserSetHost:     proxy.ContainsHeader(setHeaders, "Host"),
	}

	return m.executeSend(ctx, rawRequest, httpProtocol, mods, flowID)
}

// replaySidecar routes a replay of a sidecar-owned flow to its owning adapter.
// The adapter applies the mutations, re-encodes/re-wraps, and sends; sectool
// returns the produced flow and response form to the agent.
func (m *mcpServer) replaySidecar(ctx context.Context, req mcp.CallToolRequest, adapter, flowID string) (*mcp.CallToolResult, error) {
	wait := true
	res, rpcErr := m.sidecars.SidecarSend(ctx, adapter, wire.SidecarSendParams{
		FlowID:          flowID,
		Destination:     req.GetString("target", ""),
		Mutations:       buildMutations(req),
		FollowRedirects: req.GetBool("follow_redirects", false),
		Force:           req.GetBool("force", false),
		StreamStrategy:  req.GetString("stream_strategy", ""),
		WaitForResponse: &wait,
	})
	if rpcErr != nil {
		return errorResult("sidecar replay failed: " + rpcErr.Error()), nil
	} else if len(res.NewFlowIDs) == 0 {
		return errorResult("sidecar replay produced no flow"), nil
	}

	out := protocol.ReplaySendResponse{FlowID: res.NewFlowIDs[0]}
	if r := res.Response; r != nil {
		var hb strings.Builder
		for _, h := range r.Headers {
			hb.WriteString(h.Name)
			hb.WriteString(": ")
			hb.WriteString(h.Value)
			hb.WriteString("\r\n")
		}
		headers := hb.String()
		out.ResponseDetails = protocol.ResponseDetails{
			Status:      r.StatusCode,
			RespHeaders: headers,
			RespSize:    len(r.Body),
			RespPreview: previewBody(r.Body, responsePreviewSize, extractHeader(headers, "Content-Type")),
		}
	}
	return jsonResult(out)
}

// Mutation op names, the shared vocabulary of buildMutations and mutationsToOpts.
const (
	opSetHeader    = "set_header"
	opRemoveHeader = "remove_header"
	opSetJSON      = "set_json"
	opRemoveJSON   = "remove_json"
	opSetForm      = "set_form"
	opRemoveForm   = "remove_form"
	opSetQuery     = "set_query"
	opRemoveQuery  = "remove_query"
	opMethod       = "method"
	opPath         = "path"
	opQuery        = "query"
	opBody         = "body"
)

// buildMutations translates the replay_send MCP params into the ordered wire
// mutation list applied by a sidecar adapter (mutate via sidecar.ApplyMutations).
// It is the structured-path counterpart to executeSend's raw-byte application:
// the two paths must support the same mutation ops, so a new op added to one
// must be added to the other. The native path is intentionally NOT routed
// through this list (it edits raw bytes for force=true wire fidelity).
func buildMutations(req mcp.CallToolRequest) []wire.Mutation {
	var muts []wire.Mutation
	for _, h := range req.GetStringSlice("remove_headers", nil) {
		muts = append(muts, wire.Mutation{Op: opRemoveHeader, Name: h})
	}
	for _, h := range getHeaderArg(req, "set_headers") {
		if name, value, ok := splitPair(h, ":"); ok {
			muts = append(muts, wire.Mutation{Op: opSetHeader, Name: name, Value: value})
		}
	}
	// Sorted for a deterministic mutation array across calls
	setJSON := getJSONArg(req)
	jsonPaths := bulk.MapKeysSlice(setJSON)
	slices.Sort(jsonPaths)
	for _, path := range jsonPaths {
		// strings pass through (adapter-side type inference applies); others are JSON-encoded
		val := setJSON[path]
		sv, ok := val.(string)
		if !ok {
			if b, err := json.Marshal(val); err == nil {
				sv = string(b)
			} else {
				sv = fmt.Sprint(val)
			}
		}
		muts = append(muts, wire.Mutation{Op: opSetJSON, Name: path, Value: sv})
	}
	for _, path := range req.GetStringSlice("remove_json", nil) {
		muts = append(muts, wire.Mutation{Op: opRemoveJSON, Name: path})
	}
	setForm := getFormArg(req)
	formNames := bulk.MapKeysSlice(setForm)
	slices.Sort(formNames)
	for _, name := range formNames {
		muts = append(muts, wire.Mutation{Op: opSetForm, Name: name, Value: setForm[name]})
	}
	for _, name := range req.GetStringSlice("remove_form", nil) {
		muts = append(muts, wire.Mutation{Op: opRemoveForm, Name: name})
	}
	for _, name := range req.GetStringSlice("remove_query", nil) {
		muts = append(muts, wire.Mutation{Op: opRemoveQuery, Name: name})
	}
	for _, q := range req.GetStringSlice("set_query", nil) {
		if name, value, ok := splitPair(q, "="); ok {
			muts = append(muts, wire.Mutation{Op: opSetQuery, Name: name, Value: value})
		}
	}
	if v := req.GetString("method", ""); v != "" {
		muts = append(muts, wire.Mutation{Op: opMethod, Value: v})
	}
	if v := req.GetString("path", ""); v != "" {
		muts = append(muts, wire.Mutation{Op: opPath, Value: v})
	}
	if v := req.GetString("query", ""); v != "" {
		muts = append(muts, wire.Mutation{Op: opQuery, Value: v})
	}
	if v := req.GetString("body", ""); v != "" {
		muts = append(muts, wire.Mutation{Op: opBody, Value: v})
	}
	return muts
}

// splitPair splits s on the first sep into a trimmed name and value.
func splitPair(s, sep string) (name, value string, ok bool) {
	idx := strings.Index(s, sep)
	if idx <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+len(sep):]), true
}

func (m *mcpServer) handleRequestSend(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	urlStr := req.GetString("url", "")
	if urlStr == "" {
		return errorResult("url is required"), nil
	}

	method := req.GetString("method", "GET")

	// Parse base headers: object {"Name":"Value"} or array ["Name: Value"]
	var headers []string
	if args := req.GetArguments(); args != nil {
		if headersRaw, ok := args["headers"]; ok && headersRaw != nil {
			headers = parseHeaderArg(headersRaw)
		}
	}

	body := []byte(req.GetString("body", ""))

	// Compress body if Content-Encoding set in base headers
	if len(body) > 0 {
		for i, h := range headers {
			idx := strings.Index(h, ":")
			if idx <= 0 {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(h[:idx]), "Content-Encoding") {
				encoding := strings.TrimSpace(h[idx+1:])
				var compressionFailed bool
				body, compressionFailed = compressBody(body, encoding)
				if compressionFailed {
					headers = append(headers[:i], headers[i+1:]...)
				}
				break
			}
		}
	}

	parsedURL, err := parseURLWithDefaultHTTPS(urlStr)
	if err != nil {
		return errorResult("invalid URL: " + err.Error()), nil
	}

	rawRequest := buildRawRequestManual(method, parsedURL, headers, body)

	mods := sendModifications{
		Target:          parsedURL.Scheme + "://" + parsedURL.Host,
		Force:           req.GetBool("force", false),
		FollowRedirects: req.GetBool("follow_redirects", false),
		UserSetHost:     proxy.ContainsHeader(headers, "Host"),
	}

	return m.executeSend(ctx, rawRequest, "http/1.1", mods, "")
}

// executeSend is the shared send pipeline for replay_send and request_send.
func (m *mcpServer) executeSend(ctx context.Context, rawRequest []byte, httpProtocol string, mods sendModifications, sourceFlowID string) (*mcp.CallToolResult, error) {
	flowID, result, short, err := m.executeSendFlow(ctx, rawRequest, httpProtocol, mods, sourceFlowID, "")
	if short != nil || err != nil {
		return short, err
	}
	respCode, respStatusLine := parseResponseStatus(result.Headers)
	return jsonResult(protocol.ReplaySendResponse{
		FlowID:   flowID,
		Duration: result.Duration.String(),
		ResponseDetails: protocol.ResponseDetails{
			Status:      respCode,
			StatusLine:  respStatusLine,
			RespHeaders: string(result.Headers),
			RespSize:    len(result.Body),
			RespPreview: previewBody(result.Body, responsePreviewSize, extractHeader(string(result.Headers), "Content-Type")),
		},
	})
}

// executeSendFlow applies header/body modifications, validates, sends, and stores
// the result as a replay history flow. It returns the stored flow_id and the send
// result, or a non-nil short-circuit result (validation/domain/send failure) when
// the send does not complete. invokedBy attributes a sidecar-originated send; empty
// for agent sends. This is the native raw-byte counterpart to buildMutations (the
// sidecar path); a new mutation op supported here must also be emitted by buildMutations.
func (m *mcpServer) executeSendFlow(ctx context.Context, rawRequest []byte, httpProtocol string, mods sendModifications, sourceFlowID, invokedBy string) (string, *SendRequestResult, *mcp.CallToolResult, error) {
	headers, reqBody := splitHeadersBody(rawRequest)
	headers = applyHeaderModifications(headers, mods.RemoveHeaders, mods.SetHeaders)

	// Sync Host to Target unless the user explicitly set a Host header
	// (enables vhost routing tests and Host header injection testing).
	if mods.Target != "" && !mods.UserSetHost {
		if u, err := url.Parse(mods.Target); err == nil && u.Host != "" {
			headers = setHeader(headers, "Host", u.Host)
		}
	}

	headers = setHeaderIfMissing(headers, "User-Agent", config.UserAgent())

	// Body replacement and JSON modifications
	var bodyModified bool
	if mods.Body != "" {
		reqBody = []byte(mods.Body)
		bodyModified = true
	}
	if len(mods.SetJSON) > 0 || len(mods.RemoveJSON) > 0 {
		if isFormEncodedContentType(extractHeader(string(headers), "Content-Type")) {
			return "", nil, errorResult(
				"request body is application/x-www-form-urlencoded; use 'set_form'/'remove_form' to modify fields or 'body' to replace the raw payload. 'set_json' only applies to JSON bodies.",
			), nil
		}
		modifiedBody, err := mutate.JSON(reqBody, mods.SetJSON, mods.RemoveJSON)
		if err != nil {
			return "", nil, errorResult("JSON body modification failed: " + err.Error()), nil
		}
		reqBody = modifiedBody
		bodyModified = true
	}
	if len(mods.SetForm) > 0 || len(mods.RemoveForm) > 0 {
		modifiedBody, err := mutate.Form(reqBody, mods.SetForm, mods.RemoveForm)
		if err != nil {
			return "", nil, errorResult("form body modification failed: " + err.Error()), nil
		}
		reqBody = modifiedBody
		bodyModified = true
		// Fill in Content-Type for request_send with set_form but no headers set
		if extractHeader(string(headers), "Content-Type") == "" {
			headers = setHeader(headers, "Content-Type", "application/x-www-form-urlencoded")
		}
	}

	// Recompress if body was modified and Content-Encoding is present
	if bodyModified {
		encoding := extractHeader(string(headers), "Content-Encoding")
		var compressionFailed bool
		reqBody, compressionFailed = compressBody(reqBody, encoding)
		if compressionFailed {
			headers = removeHeader(headers, "Content-Encoding")
		}
	}

	// Strip body and framing headers on a bodyless method change. force=true keeps them for protocol testing
	if isBodylessMethod(mods.Method) && !bodyModified && !mods.Force {
		reqBody = nil
		headers = removeHeader(headers, "Content-Length")
		headers = removeHeader(headers, "Transfer-Encoding")
	}

	// Re-chunk replacement body when post-mod TE is chunked
	// Gated on bodyModified so TE-added-without-body-change ships verbatim
	teValue := extractHeader(string(headers), "Transfer-Encoding")
	if bodyModified && strings.Contains(strings.ToLower(teValue), "chunked") {
		var trailers []byte
		if parsed, err := proxy.ParseRequest(bytes.NewReader(rawRequest)); err == nil && parsed.Wire != nil && parsed.Wire.WasChunked {
			trailers = parsed.Trailers
		}
		var framed bytes.Buffer
		types.EncodeStandardChunkedBody(&framed, reqBody, trailers)
		reqBody = framed.Bytes()
	}

	// Auto-update CL only when body was modified, user didn't explicitly set CL, and not chunked
	// TE and CL are mutually exclusive (RFC 7230); auto-adding CL alongside TE would change request semantics
	if bodyModified && teValue == "" && !proxy.ContainsHeader(mods.SetHeaders, "Content-Length") {
		headers = updateContentLength(headers, len(reqBody))
	}

	rawRequest = append(headers, reqBody...)

	// Validate when force is not set
	if !mods.Force {
		if issues := validateRequest(rawRequest); len(issues) > 0 {
			res, err := validationResult(issues)
			return "", nil, res, err
		}
	}

	// Parse target and check domain scoping
	host, port, usesHTTPS := parseTarget(rawRequest, mods.Target)
	if allowed, reason := m.service.cfg.IsDomainAllowed(host); !allowed {
		return "", nil, errorResult("domain rejected: " + reason), nil
	}

	// HTTP/2 requires TLS
	if httpProtocol == "http/2" {
		if mods.Target != "" && strings.HasPrefix(strings.ToLower(mods.Target), "http://") {
			return "", nil, errorResult("cannot replay HTTP/2 request to http:// target: HTTP/2 requires TLS. To replay as HTTP/1.1, use a flow captured as HTTP/1.1 or manually construct the request."), nil
		}
		usesHTTPS = true
	}

	replayID := ids.Generate(ids.DefaultLength)
	scheme := schemeHTTP
	if usesHTTPS {
		scheme = schemeHTTPS
	}

	result, err := m.service.httpBackend.SendRequest(ctx, "sectool-"+replayID, SendRequestInput{
		RawRequest: rawRequest,
		Target: types.Target{
			Hostname:  host,
			Port:      port,
			UsesHTTPS: usesHTTPS,
		},
		FollowRedirects: mods.FollowRedirects,
		Force:           mods.Force,
		Protocol:        httpProtocol,
	})
	if err != nil {
		return "", nil, errorResultFromErr("request failed: ", err), nil
	}

	respCode, _ := parseResponseStatus(result.Headers)

	// Extract metadata from post-rule request (what was actually sent)
	displayRequest := rawRequest
	if result.ModifiedRequest != nil {
		displayRequest = result.ModifiedRequest
	}
	method, replayHost, replayPath := extractRequestMeta(string(displayRequest))
	log.Printf("send: %s %s://%s:%d status=%d size=%d duration=%v", replayID, scheme, host, port, respCode, len(result.Body), result.Duration)

	// Store in replay history for proxy_poll visibility
	// RawRequest = pre-rule (base for future replays), ModifiedRequest = post-rule (for display)
	m.service.replayHistoryStore.Store(&store.ReplayHistoryEntry{
		FlowID:          replayID,
		RawRequest:      rawRequest,
		ModifiedRequest: result.ModifiedRequest,
		Method:          method,
		Host:            replayHost,
		Path:            replayPath,
		Scheme:          scheme,
		Port:            port,
		Protocol:        httpProtocol,
		RespHeaders:     result.Headers,
		RespBody:        result.Body,
		RespStatus:      respCode,
		Duration:        result.Duration,
		SourceFlowID:    sourceFlowID,
		InvokedBy:       invokedBy,
	})

	return replayID, result, nil, nil
}

// getHeaderArg extracts a header array parameter from an MCP request.
func getHeaderArg(req mcp.CallToolRequest, name string) []string {
	if args := req.GetArguments(); args != nil {
		if raw, ok := args[name]; ok && raw != nil {
			return parseHeaderArg(raw)
		}
	}
	return nil
}

// rebuildReplayTarget builds a scheme://host[:port] target from a stored Host
// header value, stripping any existing port and re-wrapping bare IPv6 addresses.
func rebuildReplayTarget(host, scheme string, port int) string {
	// SplitHostPort handles IPv6 brackets and errors (leaving host untouched)
	// when no port is present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// Re-wrap bare IPv6 so the rebuilt URL parses
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	// Omit default ports to avoid Host: example.com:80 pollution
	if (scheme == schemeHTTP && port == 80) || (scheme == schemeHTTPS && port == 443) {
		return fmt.Sprintf("%s://%s", scheme, host)
	}
	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

// getJSONArg extracts set_json as a map from an MCP request.
func getJSONArg(req mcp.CallToolRequest) map[string]interface{} {
	if args := req.GetArguments(); args != nil {
		if raw, ok := args["set_json"]; ok && raw != nil {
			return jsonObjectArg(raw)
		}
	}
	return nil
}

// jsonObjectArg coerces an MCP argument to a JSON object, decoding agents that
// pass a string-encoded object literal (matching parseHeaderArg's leniency).
func jsonObjectArg(raw interface{}) map[string]interface{} {
	switch v := raw.(type) {
	case map[string]interface{}:
		return v
	case string:
		s := strings.TrimSpace(v)
		if len(s) >= 2 && s[0] == '{' {
			var obj map[string]interface{}
			if json.Unmarshal([]byte(s), &obj) == nil {
				return obj
			}
		}
	}
	return nil
}

// getFormArg extracts set_form as a string-valued map; non-string values are coerced via fmt.Sprint.
func getFormArg(req mcp.CallToolRequest) map[string]string {
	args := req.GetArguments()
	if args == nil {
		return nil
	}
	raw, ok := args["set_form"]
	if !ok || raw == nil {
		return nil
	}
	rawMap := jsonObjectArg(raw)
	if len(rawMap) == 0 {
		return nil
	}
	out := make(map[string]string, len(rawMap))
	for k, v := range rawMap {
		if s, ok := v.(string); ok {
			out[k] = s
		} else {
			out[k] = fmt.Sprint(v)
		}
	}
	return out
}

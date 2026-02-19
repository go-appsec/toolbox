package service

import (
	"context"
	"encoding/base64"
	"log"
	"net/url"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/ids"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

func (m *mcpServer) replaySendTool() mcp.Tool {
	return mcp.NewTool("replay_send",
		mcp.WithDescription(`Replay a proxied request (flow_id from proxy_poll) with edits.

Returns: replay_id, status, headers, response_preview. Full body via replay_get.

Edits:
- method: override HTTP method (GET, POST, PUT, DELETE, etc.)
- target: scheme+host[:port] (e.g., 'https://staging.example.com')
- path/query: override path or entire query string
- set_query/remove_query: selective query param edits
- set_headers/remove_headers: header edits. Single entry replaces existing; multiple entries with the same name create duplicates
- body: replace entire body
- set_json/remove_json: selective JSON edits; requires body to be valid JSON

JSON paths: dot notation with array brackets (e.g., "user.email", "items[0].id", "data.users[0].name").
set_json object: {"user.email": "x", "items[0].id": 5}
Types auto-parsed: null/true/false/numbers/{}/[], else string.
Processing: remove_* then set_*. Content-Length auto-updated when body is modified and CL not explicitly set.
Validation: fix issues or use force=true for protocol testing.
Replayed requests appear in proxy_poll history alongside captured traffic.`),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow ID from proxy_poll or crawl_poll to use as base request")),
		mcp.WithString("method", mcp.Description("Override HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)")),
		mcp.WithString("body", mcp.Description("Request body content (replaces existing body)")),
		mcp.WithString("target", mcp.Description("Override destination (scheme+host[:port]); keeps original path/query")),
		mcp.WithArray("set_headers", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Headers to set (format: 'Name: Value')")),
		mcp.WithArray("remove_headers", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Header names to remove")),
		mcp.WithString("path", mcp.Description("Override request path (include leading '/')")),
		mcp.WithString("query", mcp.Description("Override entire query string (no leading '?')")),
		mcp.WithArray("set_query", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Query params to set (format: 'name=value')")),
		mcp.WithArray("remove_query", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Query param names to remove")),
		mcp.WithObject("set_json", mcp.Description("JSON fields to set as object: {\"path\": value} (e.g., {\"user.email\": \"x\", \"items[0].id\": 5})")),
		mcp.WithArray("remove_json", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("JSON fields to remove (dot path: 'user.temp', 'items[2]')")),
		mcp.WithBoolean("follow_redirects", mcp.Description("Follow HTTP redirects (default: false)")),
		mcp.WithBoolean("force", mcp.Description("Skip validation for protocol-level tests (smuggling, CRLF injection)")),
	)
}

func (m *mcpServer) replayGetTool() mcp.Tool {
	return mcp.NewTool("replay_get",
		mcp.WithDescription(`Retrieve full response from a previous replay_send.

Returns headers and body. Binary bodies are returned as "<BINARY:N Bytes>" placeholder.
Results are ephemeral and cleared on service restart.`),
		mcp.WithString("replay_id", mcp.Required(), mcp.Description("Replay ID from replay_send response")),
	)
}

func (m *mcpServer) requestSendTool() mcp.Tool {
	return mcp.NewTool("request_send",
		mcp.WithDescription(`Send a request from scratch (no captured flow required).

Use this when you need to send a request to a URL without first capturing it via proxy.
Returns: replay_id, status, headers, response_preview. Full body via replay_get.
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

	// Try replay history, then proxy index, then crawler backend
	var rawRequest []byte
	var httpProtocol string // "http/1.1", "h2", or empty (defaults to http/1.1)
	if replayEntry, ok := m.service.replayHistoryStore.Get(flowID); ok {
		rawRequest = replayEntry.RawRequest
		httpProtocol = replayEntry.Protocol
	} else if offset, ok := m.service.proxyIndex.Offset(flowID); ok {
		proxyEntries, err := m.service.httpBackend.GetProxyHistory(ctx, 1, offset)
		if err != nil {
			return errorResultFromErr("failed to fetch flow: ", err), nil
		}
		if len(proxyEntries) == 0 {
			return errorResult("flow not found in proxy history"), nil
		}
		rawRequest = []byte(proxyEntries[0].Request)
		httpProtocol = proxyEntries[0].Protocol
	} else if flow, err := m.service.crawlerBackend.GetFlow(ctx, flowID); err == nil && flow != nil {
		rawRequest = flow.Request
	} else {
		return errorResult("flow_id not found: run proxy_poll or crawl_poll to see available flows"), nil
	}

	rawRequest = modifyRequestLine(rawRequest, &PathQueryOpts{
		Method:      req.GetString("method", ""),
		Path:        req.GetString("path", ""),
		Query:       req.GetString("query", ""),
		SetQuery:    req.GetStringSlice("set_query", nil),
		RemoveQuery: req.GetStringSlice("remove_query", nil),
	})

	setHeaders := getHeaderArg(req, "set_headers")
	mods := sendModifications{
		Method:          req.GetString("method", ""),
		SetHeaders:      setHeaders,
		RemoveHeaders:   req.GetStringSlice("remove_headers", nil),
		Target:          req.GetString("target", ""),
		Body:            req.GetString("body", ""),
		SetJSON:         getJSONArg(req),
		RemoveJSON:      req.GetStringSlice("remove_json", nil),
		Force:           req.GetBool("force", false),
		FollowRedirects: req.GetBool("follow_redirects", false),
		UserSetHost:     proxy.ContainsHeader(setHeaders, "Host"),
	}

	return m.executeSend(ctx, rawRequest, httpProtocol, mods, flowID)
}

func (m *mcpServer) handleReplayGet(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	replayID := req.GetString("replay_id", "")
	if replayID == "" {
		return errorResult("replay_id is required"), nil
	}

	// Hidden parameter for CLI: returns full base64-encoded body instead of preview
	fullBody := req.GetBool("full_body", false)

	result, ok := m.service.replayHistoryStore.Get(replayID)
	if !ok {
		return errorResult("replay not found: replay results are ephemeral and cleared on service restart"), nil
	}

	respCode, respStatusLine := parseResponseStatus(result.RespHeaders)
	log.Printf("replay/get: %s status=%d size=%d", replayID, respCode, len(result.RespBody))

	// Decompress response for display (gzip/deflate) - applies to both modes
	displayBody, _ := decompressForDisplay(result.RespBody, string(result.RespHeaders))

	// Format body based on full_body flag
	var respBodyStr string
	if fullBody { // Full body mode: base64-encode the decompressed content
		respBodyStr = base64.StdEncoding.EncodeToString(displayBody)
	} else { // Preview mode: truncated text preview
		respBodyStr = previewBody(displayBody, fullBodyMaxSize, extractHeader(string(result.RespHeaders), "Content-Type"))
	}

	return jsonResult(protocol.ReplayGetResponse{
		ReplayID:          replayID,
		Duration:          result.Duration.String(),
		Status:            respCode,
		StatusLine:        respStatusLine,
		RespHeaders:       string(result.RespHeaders),
		RespHeadersParsed: parseHeadersToMap(string(result.RespHeaders)),
		RespBody:          respBodyStr,
		RespSize:          len(result.RespBody),
	})
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
// Applies header/body modifications, validates, sends, and stores the result.
func (m *mcpServer) executeSend(ctx context.Context, rawRequest []byte, httpProtocol string, mods sendModifications, sourceFlowID string) (*mcp.CallToolResult, error) {
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
		modifiedBody, err := modifyJSONBodyMap(reqBody, mods.SetJSON, mods.RemoveJSON)
		if err != nil {
			return errorResult("JSON body modification failed: " + err.Error()), nil
		}
		reqBody = modifiedBody
		bodyModified = true
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

	// Strip body when method changed to bodyless (GET/HEAD) and no explicit body provided.
	// Prevents stale Content-Length from causing server errors (e.g., 400 on GET+CL).
	// Use force=true to send GET/HEAD with body intentionally.
	if isBodylessMethod(mods.Method) && !bodyModified && !mods.Force {
		reqBody = nil
		headers = removeHeader(headers, "Content-Length")
	}

	// Auto-update CL only when body was modified, user didn't explicitly set CL,
	// and no Transfer-Encoding is present. TE and CL are mutually exclusive per
	// RFC 7230; auto-adding CL alongside TE would change request semantics.
	hasTE := extractHeader(string(headers), "Transfer-Encoding") != ""
	if bodyModified && !hasTE && !proxy.ContainsHeader(mods.SetHeaders, "Content-Length") {
		headers = updateContentLength(headers, len(reqBody))
	}

	rawRequest = append(headers, reqBody...)

	// Validate when force is not set
	if !mods.Force {
		if issues := validateRequest(rawRequest); len(issues) > 0 {
			return errorResult("validation failed:\n" + formatIssues(issues)), nil
		}
	}

	// Parse target and check domain scoping
	host, port, usesHTTPS := parseTarget(rawRequest, mods.Target)
	if allowed, reason := m.service.cfg.IsDomainAllowed(host); !allowed {
		return errorResult("domain rejected: " + reason), nil
	}

	// HTTP/2 requires TLS
	if httpProtocol == "h2" {
		if mods.Target != "" && strings.HasPrefix(strings.ToLower(mods.Target), "http://") {
			return errorResult("cannot replay HTTP/2 request to http:// target: HTTP/2 requires TLS. To replay as HTTP/1.1, use a flow captured as HTTP/1.1 or manually construct the request."), nil
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
		Target: Target{
			Hostname:  host,
			Port:      port,
			UsesHTTPS: usesHTTPS,
		},
		FollowRedirects: mods.FollowRedirects,
		Force:           mods.Force,
		Protocol:        httpProtocol,
	})
	if err != nil {
		return errorResultFromErr("request failed: ", err), nil
	}

	respCode, respStatusLine := parseResponseStatus(result.Headers)
	method, replayHost, replayPath := extractRequestMeta(string(rawRequest))
	log.Printf("send: %s %s://%s:%d status=%d size=%d duration=%v", replayID, scheme, host, port, respCode, len(result.Body), result.Duration)

	// Store in replay history for proxy_poll visibility
	refOffset, _ := m.service.replayHistoryStore.UpdateReferenceOffset(m.service.proxyLastOffset.Load())
	m.service.replayHistoryStore.Store(&store.ReplayHistoryEntry{
		FlowID:          replayID,
		ReferenceOffset: refOffset,
		RawRequest:      rawRequest,
		Method:          method,
		Host:            replayHost,
		Path:            replayPath,
		Protocol:        httpProtocol,
		RespHeaders:     result.Headers,
		RespBody:        result.Body,
		RespStatus:      respCode,
		Duration:        result.Duration,
		SourceFlowID:    sourceFlowID,
	})

	return jsonResult(protocol.ReplaySendResponse{
		ReplayID: replayID,
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

// getHeaderArg extracts a header array parameter from an MCP request.
func getHeaderArg(req mcp.CallToolRequest, name string) []string {
	if args := req.GetArguments(); args != nil {
		if raw, ok := args[name]; ok && raw != nil {
			return parseHeaderArg(raw)
		}
	}
	return nil
}

// getJSONArg extracts set_json as a map from an MCP request.
func getJSONArg(req mcp.CallToolRequest) map[string]interface{} {
	if args := req.GetArguments(); args != nil {
		if raw, ok := args["set_json"]; ok && raw != nil {
			if jsonMap, ok := raw.(map[string]interface{}); ok {
				return jsonMap
			}
		}
	}
	return nil
}

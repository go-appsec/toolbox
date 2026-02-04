package service

import (
	"context"
	"encoding/base64"
	"log"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/llm-security-toolbox/sectool/config"
	"github.com/go-appsec/llm-security-toolbox/sectool/protocol"
	"github.com/go-appsec/llm-security-toolbox/sectool/service/ids"
	"github.com/go-appsec/llm-security-toolbox/sectool/service/store"
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
- add_headers/remove_headers: header edits
- body: replace entire body
- set_json/remove_json: selective JSON edits; requires body to be valid JSON

JSON paths: dot notation with array brackets (e.g., "user.email", "items[0].id", "data.users[0].name").
set_json object: {"user.email": "x", "items[0].id": 5}
Types auto-parsed: null/true/false/numbers/{}/[], else string.
Processing: remove_* then set_*. Content-Length/Host auto-updated.
Validation: fix issues or use force=true for protocol testing.`),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow ID from proxy_poll or crawl_poll to use as base request")),
		mcp.WithString("method", mcp.Description("Override HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)")),
		mcp.WithString("body", mcp.Description("Request body content (replaces existing body)")),
		mcp.WithString("target", mcp.Description("Override destination (scheme+host[:port]); keeps original path/query")),
		mcp.WithArray("add_headers", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Headers to add/replace (format: 'Name: Value')")),
		mcp.WithArray("remove_headers", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Header names to remove")),
		mcp.WithString("path", mcp.Description("Override request path (include leading '/')")),
		mcp.WithString("query", mcp.Description("Override entire query string (no leading '?')")),
		mcp.WithArray("set_query", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Query params to set (format: 'name=value')")),
		mcp.WithArray("remove_query", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Query param names to remove")),
		mcp.WithObject("set_json", mcp.Description("JSON fields to set as object: {\"path\": value} (e.g., {\"user.email\": \"x\", \"items[0].id\": 5})")),
		mcp.WithArray("remove_json", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("JSON fields to remove (dot path: 'user.temp', 'items[2]')")),
		mcp.WithBoolean("follow_redirects", mcp.Description("Follow HTTP redirects (default: false)")),
		mcp.WithString("timeout", mcp.Description("Request timeout (e.g., '30s', '1m')")),
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
Returns: replay_id, status, headers, response_preview. Full body via replay_get.`),
		mcp.WithString("url", mcp.Required(), mcp.Description("Target URL (e.g., 'https://api.example.com/users')")),
		mcp.WithString("method", mcp.Description("HTTP method (default: GET)")),
		mcp.WithObject("headers", mcp.Description("Headers as object: {\"Name\": \"Value\"}")),
		mcp.WithString("body", mcp.Description("Request body content")),
		mcp.WithBoolean("follow_redirects", mcp.Description("Follow HTTP redirects (default: false)")),
		mcp.WithString("timeout", mcp.Description("Request timeout (e.g., '30s', '1m')")),
	)
}
func (m *mcpServer) handleReplaySend(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	flowID := req.GetString("flow_id", "")
	if flowID == "" {
		return errorResult("flow_id is required"), nil
	}

	// Try flowStore (proxy or replay), then crawler backend
	var rawRequest []byte
	var httpProtocol string // "http/1.1", "h2", or empty (defaults to http/1.1)
	if entry, ok := m.service.flowStore.Lookup(flowID); ok {
		if entry.Source == SourceReplay {
			// Fetch from replay history store
			replayEntry, ok := m.service.replayHistoryStore.Get(flowID)
			if !ok {
				return errorResult("replay flow not found in history"), nil
			}
			rawRequest = replayEntry.RawRequest
			httpProtocol = replayEntry.Protocol
		} else {
			// Fetch from proxy history
			proxyEntries, err := m.service.httpBackend.GetProxyHistory(ctx, 1, entry.Offset)
			if err != nil {
				return errorResultFromErr("failed to fetch flow: ", err), nil
			}
			if len(proxyEntries) == 0 {
				return errorResult("flow not found in proxy history"), nil
			}
			rawRequest = []byte(proxyEntries[0].Request)
			httpProtocol = proxyEntries[0].Protocol
		}
	} else if flow, err := m.service.crawlerBackend.GetFlow(ctx, flowID); err == nil && flow != nil {
		rawRequest = flow.Request
		// Crawler uses HTTP/1.1
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

	headers, reqBody := splitHeadersBody(rawRequest)

	sendReq := &ReplaySendRequest{
		AddHeaders:    req.GetStringSlice("add_headers", nil),
		RemoveHeaders: req.GetStringSlice("remove_headers", nil),
		Target:        req.GetString("target", ""),
	}
	headers = applyHeaderModifications(headers, sendReq)
	headers = setHeaderIfMissing(headers, "User-Agent", config.UserAgent())

	var bodyModified bool // Track if user provided a new body (for recompression)
	if body := req.GetString("body", ""); body != "" {
		reqBody = []byte(body)
		bodyModified = true
	}

	// Get set_json as a map (MCP format: {"path": value})
	var setJSON map[string]interface{}
	if args := req.GetArguments(); args != nil {
		if setJSONRaw, ok := args["set_json"]; ok && setJSONRaw != nil {
			if setJSONMap, ok := setJSONRaw.(map[string]interface{}); ok {
				setJSON = setJSONMap
			}
		}
	}
	removeJSON := req.GetStringSlice("remove_json", nil)
	if len(setJSON) > 0 || len(removeJSON) > 0 {
		modifiedBody, err := modifyJSONBodyMap(reqBody, setJSON, removeJSON)
		if err != nil {
			return errorResult("JSON body modification failed: " + err.Error()), nil
		}
		reqBody = modifiedBody
		bodyModified = true
	}

	// If user provided/modified body and Content-Encoding header is present, recompress
	if bodyModified {
		encoding := extractHeader(string(headers), "Content-Encoding")
		var compressionFailed bool
		reqBody, compressionFailed = compressBody(reqBody, encoding)
		if compressionFailed {
			// remove Content-Encoding to send uncompressed
			headers = removeHeader(headers, "Content-Encoding")
		}
	}

	force := req.GetBool("force", false)

	// Check if user explicitly set Content-Length in add_headers
	userSetContentLength := containsContentLengthHeader(sendReq.AddHeaders)

	if !userSetContentLength {
		// User didn't explicitly set Content-Length, so auto-update it to match body.
		// This is the normal case for body replacement.
		headers = updateContentLength(headers, len(reqBody))
	}
	// If user explicitly set Content-Length, preserve it for validation.

	rawRequest = append(headers, reqBody...)

	if !force {
		if issues := validateRequest(rawRequest); len(issues) > 0 {
			return errorResult("validation failed:\n" + formatIssues(issues)), nil
		}
	}
	// When force=true, skip validation and preserve user-specified Content-Length for security testing scenarios.

	targetOverride := req.GetString("target", "")
	host, port, usesHTTPS := parseTarget(rawRequest, targetOverride)

	// HTTP/2 requires TLS.
	// If replaying an H2 request and user explicitly specified http://, return error.
	// Otherwise force HTTPS (handles non-443 ports where parseTarget can't infer scheme).
	if httpProtocol == "h2" {
		if targetOverride != "" && strings.HasPrefix(strings.ToLower(targetOverride), "http://") {
			return errorResult("cannot replay HTTP/2 request to http:// target: HTTP/2 requires TLS. To replay as HTTP/1.1, use a flow captured as HTTP/1.1 or manually construct the request."), nil
		}
		usesHTTPS = true
	}

	replayID := ids.Generate(ids.DefaultLength)

	scheme := schemeHTTP
	if usesHTTPS {
		scheme = schemeHTTPS
	}
	log.Printf("mcp/replay_send: %s sending to %s://%s:%d (flow=%s)", replayID, scheme, host, port, flowID)

	var timeout time.Duration
	if timeoutStr := req.GetString("timeout", ""); timeoutStr != "" {
		parsed, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return errorResult("invalid timeout duration: " + err.Error()), nil
		}
		timeout = parsed
	}

	sendInput := SendRequestInput{
		RawRequest: rawRequest,
		Target: Target{
			Hostname:  host,
			Port:      port,
			UsesHTTPS: usesHTTPS,
		},
		FollowRedirects: req.GetBool("follow_redirects", false),
		Timeout:         timeout,
		Force:           req.GetBool("force", false),
		Protocol:        httpProtocol,
	}

	result, err := m.service.httpBackend.SendRequest(ctx, "sectool-"+replayID, sendInput)
	if err != nil {
		return errorResultFromErr("request failed: ", err), nil
	}

	respHeaders := result.Headers
	respBody := result.Body
	respCode, respStatusLine := parseResponseStatus(respHeaders)
	log.Printf("mcp/replay_send: %s completed in %v (status=%d, size=%d)", replayID, result.Duration, respCode, len(respBody))

	m.service.requestStore.Store(replayID, &store.RequestEntry{
		Headers:  respHeaders,
		Body:     respBody,
		Duration: result.Duration,
	})

	// Store in replay history for proxy_poll visibility
	method, replayHost, replayPath := extractRequestMeta(string(rawRequest))
	refOffset, _ := m.service.replayHistoryStore.UpdateReferenceOffset(m.service.proxyLastOffset.Load())
	m.service.replayHistoryStore.Store(&store.ReplayHistoryEntry{
		FlowID:          replayID,
		ReferenceOffset: refOffset,
		RawRequest:      rawRequest,
		Method:          method,
		Host:            replayHost,
		Path:            replayPath,
		Protocol:        httpProtocol,
		RespHeaders:     respHeaders,
		RespBody:        respBody,
		RespStatus:      respCode,
		Duration:        result.Duration,
		SourceFlowID:    flowID,
	})
	m.service.flowStore.RegisterKnown(replayID, SourceReplay)

	return jsonResult(protocol.ReplaySendResponse{
		ReplayID: replayID,
		Duration: result.Duration.String(),
		ResponseDetails: protocol.ResponseDetails{
			Status:      respCode,
			StatusLine:  respStatusLine,
			RespHeaders: string(respHeaders),
			RespSize:    len(respBody),
			RespPreview: previewBody(respBody, responsePreviewSize),
		},
	})
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

	log.Printf("mcp/replay_get: retrieving %s", replayID)
	result, ok := m.service.requestStore.Get(replayID)
	if !ok {
		return errorResult("replay not found: replay results are ephemeral and cleared on service restart"), nil
	}

	respCode, respStatusLine := parseResponseStatus(result.Headers)

	// Decompress response for display (gzip/deflate) - applies to both modes
	displayBody, _ := decompressForDisplay(result.Body, string(result.Headers))

	// Format body based on full_body flag
	var respBodyStr string
	if fullBody { // Full body mode: base64-encode the decompressed content
		respBodyStr = base64.StdEncoding.EncodeToString(displayBody)
	} else { // Preview mode: truncated text preview
		respBodyStr = previewBody(displayBody, fullBodyMaxSize)
	}

	return jsonResult(protocol.ReplayGetResponse{
		ReplayID:          replayID,
		Duration:          result.Duration.String(),
		Status:            respCode,
		StatusLine:        respStatusLine,
		RespHeaders:       string(result.Headers),
		RespHeadersParsed: parseHeadersToMap(string(result.Headers)),
		RespBody:          respBodyStr,
		RespSize:          len(result.Body),
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

	// Parse headers from object
	var headers map[string]string
	if args := req.GetArguments(); args != nil {
		if headersRaw, ok := args["headers"]; ok && headersRaw != nil {
			if headersMap, ok := headersRaw.(map[string]interface{}); ok {
				headers = make(map[string]string)
				for k, v := range headersMap {
					if vs, ok := v.(string); ok {
						headers[k] = vs
					}
				}
			}
		}
	}

	body := []byte(req.GetString("body", ""))

	// If Content-Encoding header is present, compress the body
	// This handles the case where user exported a decompressed request
	// (e.g., from proxy_get) and is sending it back with the original encoding
	if len(body) > 0 {
		for k, v := range headers {
			if strings.EqualFold(k, "Content-Encoding") {
				var compressionFailed bool
				body, compressionFailed = compressBody(body, v)
				if compressionFailed {
					delete(headers, k)
				}
				break
			}
		}
	}

	parsedURL, err := parseURLWithDefaultHTTPS(urlStr)
	if err != nil {
		return errorResult("invalid URL: " + err.Error()), nil
	}

	rawRequest := buildRawRequest(method, parsedURL, headers, body)
	if rawRequest == nil {
		return errorResult("failed to build request: invalid method or URL"), nil
	}
	target := targetFromURL(parsedURL)
	replayID := ids.Generate(ids.DefaultLength)

	log.Printf("mcp/request_send: %s sending to %s", replayID, parsedURL)

	var timeout time.Duration
	if timeoutStr := req.GetString("timeout", ""); timeoutStr != "" {
		parsed, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return errorResult("invalid timeout duration: " + err.Error()), nil
		}
		timeout = parsed
	}

	sendInput := SendRequestInput{
		RawRequest:      rawRequest,
		Target:          target,
		FollowRedirects: req.GetBool("follow_redirects", false),
		Timeout:         timeout,
	}

	result, err := m.service.httpBackend.SendRequest(ctx, "sectool-"+replayID, sendInput)
	if err != nil {
		return errorResultFromErr("request failed: ", err), nil
	}

	respCode, respStatusLine := parseResponseStatus(result.Headers)
	log.Printf("mcp/request_send: %s completed in %v (status=%d, size=%d)", replayID, result.Duration, respCode, len(result.Body))

	m.service.requestStore.Store(replayID, &store.RequestEntry{
		Headers:  result.Headers,
		Body:     result.Body,
		Duration: result.Duration,
	})

	// Store in replay history for proxy_poll visibility
	refOffset, _ := m.service.replayHistoryStore.UpdateReferenceOffset(m.service.proxyLastOffset.Load())
	m.service.replayHistoryStore.Store(&store.ReplayHistoryEntry{
		FlowID:          replayID,
		ReferenceOffset: refOffset,
		RawRequest:      rawRequest,
		Method:          method,
		Host:            target.Hostname,
		Path:            parsedURL.Path,
		Protocol:        "http/1.1",
		RespHeaders:     result.Headers,
		RespBody:        result.Body,
		RespStatus:      respCode,
		Duration:        result.Duration,
		SourceFlowID:    "", // No source for request_send
	})
	m.service.flowStore.RegisterKnown(replayID, SourceReplay)

	return jsonResult(protocol.ReplaySendResponse{
		ReplayID: replayID,
		Duration: result.Duration.String(),
		ResponseDetails: protocol.ResponseDetails{
			Status:      respCode,
			StatusLine:  respStatusLine,
			RespHeaders: string(result.Headers),
			RespSize:    len(result.Body),
			RespPreview: previewBody(result.Body, responsePreviewSize),
		},
	})
}

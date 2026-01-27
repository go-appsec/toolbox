package service

import (
	"context"
	"encoding/base64"
	"log"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-harden/llm-security-toolbox/sectool/config"
	"github.com/go-harden/llm-security-toolbox/sectool/protocol"
	"github.com/go-harden/llm-security-toolbox/sectool/service/ids"
	"github.com/go-harden/llm-security-toolbox/sectool/service/store"
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

	// Try proxy flowStore first, then crawler backend
	var rawRequest []byte
	if entry, ok := m.service.flowStore.Lookup(flowID); ok {
		proxyEntries, err := m.service.httpBackend.GetProxyHistory(ctx, 1, entry.Offset)
		if err != nil {
			return errorResultFromErr("failed to fetch flow: ", err), nil
		}
		if len(proxyEntries) == 0 {
			return errorResult("flow not found in proxy history"), nil
		}
		rawRequest = []byte(proxyEntries[0].Request)
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

	headers, reqBody := splitHeadersBody(rawRequest)

	sendReq := &ReplaySendRequest{
		AddHeaders:    req.GetStringSlice("add_headers", nil),
		RemoveHeaders: req.GetStringSlice("remove_headers", nil),
		Target:        req.GetString("target", ""),
	}
	headers = applyHeaderModifications(headers, sendReq)
	headers = setHeaderIfMissing(headers, "User-Agent", config.UserAgent())

	if body := req.GetString("body", ""); body != "" {
		reqBody = []byte(body)
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
	}

	headers = updateContentLength(headers, len(reqBody))
	rawRequest = append(headers, reqBody...)

	if !req.GetBool("force", false) {
		if issues := validateRequest(rawRequest); len(issues) > 0 {
			return errorResult("validation failed:\n" + formatIssues(issues)), nil
		}
	}

	host, port, usesHTTPS := parseTarget(rawRequest, req.GetString("target", ""))

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

	// Format body based on full_body flag
	var respBodyStr string
	if fullBody {
		respBodyStr = base64.StdEncoding.EncodeToString(result.Body)
	} else {
		respBodyStr = previewBody(result.Body, fullBodyMaxSize)
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

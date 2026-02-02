package service

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/llm-security-toolbox/sectool/protocol"
)

func TestMCP_ReplayWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMCPServerWithMock(t)

	mockMCP.AddProxyEntry(
		"GET /replay-test HTTP/1.1\r\nHost: mock.test\r\n\r\n",
		"HTTP/1.1 200 OK\r\n\r\noriginal",
		"",
	)
	mockMCP.SetSendResponse(
		"HttpRequestResponse{httpRequest=GET /replay-test HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nreplayed response}",
	)

	listResult := CallMCPTool(t, mcpClient, "proxy_poll", map[string]interface{}{
		"output_mode": "flows",
		"method":      "GET",
	})
	require.False(t, listResult.IsError,
		"proxy_poll failed: %s", ExtractMCPText(t, listResult))

	var listResp protocol.ProxyPollResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, listResult)), &listResp))
	require.NotEmpty(t, listResp.Flows)

	flowID := listResp.Flows[0].FlowID

	sendResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
		"flow_id": flowID,
	})
	assert.NotEmpty(t, sendResp.ReplayID)
	assert.NotEmpty(t, sendResp.Duration)

	getResp := CallMCPToolJSONOK[protocol.ReplayGetResponse](t, mcpClient, "replay_get", map[string]interface{}{
		"replay_id": sendResp.ReplayID,
	})
	assert.Equal(t, sendResp.ReplayID, getResp.ReplayID)
	assert.NotEmpty(t, getResp.RespHeaders)
}

func TestMCP_RequestSendWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMCPServerWithMock(t)

	mockMCP.SetSendResponse(
		"HttpRequestResponse{httpRequest=GET /test HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}}",
	)

	cases := []struct {
		name       string
		args       map[string]interface{}
		wantStatus int
	}{
		{
			name: "basic_request",
			args: map[string]interface{}{
				"url":    "https://example.com/test",
				"method": "GET",
			},
			wantStatus: 200,
		},
		{
			name: "with_headers",
			args: map[string]interface{}{
				"url":    "https://example.com/test",
				"method": "GET",
				"headers": map[string]interface{}{
					"X-Custom": "value",
					"Accept":   "application/json",
				},
			},
		},
		{
			name: "post_with_body",
			args: map[string]interface{}{
				"url":    "https://example.com/api",
				"method": "POST",
				"headers": map[string]interface{}{
					"Content-Type": "application/json",
				},
				"body": `{"test": "data"}`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", tc.args)
			assert.NotEmpty(t, resp.ReplayID)
			if tc.wantStatus != 0 {
				assert.Equal(t, tc.wantStatus, resp.Status)
			}
		})
	}
}

func TestMCP_RequestSendValidation(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMCPServerWithMock(t)

	t.Run("missing_url", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "request_send", map[string]interface{}{
			"method": "GET",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "url is required")
	})

	t.Run("defaults_to_get", func(t *testing.T) {
		mockMCP.SetSendResponse(
			"HttpRequestResponse{httpRequest=GET /test HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\n\r\nok}",
		)
		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", map[string]interface{}{
			"url": "https://example.com/test",
		})
		assert.NotEmpty(t, resp.ReplayID)
	})

	t.Run("invalid_url", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "request_send", map[string]interface{}{
			"url": "://invalid",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "invalid URL")
	})

	t.Run("invalid_timeout", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "request_send", map[string]interface{}{
			"url":     "https://example.com",
			"timeout": "not-a-duration",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "invalid timeout")
	})
}

func TestMCP_ReplayValidation(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, mockCrawler := setupMCPServerWithMock(t)

	t.Run("missing_flow_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "flow_id")
	})

	t.Run("invalid_flow_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "not found")
	})

	t.Run("missing_replay_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "replay_get", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "replay_id is required")
	})

	t.Run("invalid_replay_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "replay_get", map[string]interface{}{
			"replay_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "not found")
	})

	t.Run("invalid_timeout", func(t *testing.T) {
		mockMCP.AddProxyEntry(
			"GET /timeout-test HTTP/1.1\r\nHost: test.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)
		listResult := CallMCPTool(t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"host":        "test.com",
		})
		require.False(t, listResult.IsError)
		var listResp protocol.ProxyPollResponse
		require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, listResult)), &listResp))
		require.NotEmpty(t, listResp.Flows)

		result := CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": listResp.Flows[0].FlowID,
			"timeout": "invalid",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "invalid timeout")
	})

	t.Run("from_crawler_flow", func(t *testing.T) {
		createResp := CallMCPToolJSONOK[protocol.CrawlCreateResponse](t, mcpClient, "crawl_create", map[string]interface{}{
			"seed_urls": "https://crawl.test",
		})

		crawlFlowID := "crawl-flow-replay"
		err := mockCrawler.AddFlow(createResp.SessionID, CrawlFlow{
			ID:         crawlFlowID,
			SessionID:  createResp.SessionID,
			URL:        "https://crawl.test/page",
			Host:       "crawl.test",
			Path:       "/page",
			Method:     "GET",
			StatusCode: 200,
			Request:    []byte("GET /page HTTP/1.1\r\nHost: crawl.test\r\n\r\n"),
			Response:   []byte("HTTP/1.1 200 OK\r\n\r\ncrawled"),
		})
		require.NoError(t, err)

		mockMCP.SetSendResponse(
			"HttpRequestResponse{httpRequest=GET /page HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\n\r\nreplayed}",
		)

		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": crawlFlowID,
		})
		assert.NotEmpty(t, resp.ReplayID)
	})
}

func TestMCP_ReplaySendModifications(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMCPServerWithMock(t)

	mockMCP.AddProxyEntry(
		"POST /api/users HTTP/1.1\r\nHost: original.test\r\nContent-Type: application/json\r\nX-Remove-Me: value\r\n\r\n{\"name\":\"test\",\"temp\":\"remove\"}",
		"HTTP/1.1 200 OK\r\n\r\nok",
		"",
	)
	mockMCP.SetSendResponse(
		"HttpRequestResponse{httpRequest=POST /api/users HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\n\r\nmodified}",
	)

	listResult := CallMCPTool(t, mcpClient, "proxy_poll", map[string]interface{}{
		"output_mode": "flows",
		"method":      "POST",
	})
	require.False(t, listResult.IsError)
	var listResp protocol.ProxyPollResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, listResult)), &listResp))
	require.NotEmpty(t, listResp.Flows)
	flowID := listResp.Flows[0].FlowID

	modCases := []struct {
		name string
		args map[string]interface{}
	}{
		{name: "with_method_override", args: map[string]interface{}{"method": "PUT"}},
		{name: "with_target_override", args: map[string]interface{}{"target": "https://staging.test:8443"}},
		{
			name: "with_header_modifications",
			args: map[string]interface{}{
				"add_headers":    []interface{}{"X-Custom: added", "Authorization: Bearer token"},
				"remove_headers": []interface{}{"X-Remove-Me"},
			},
		},
		{name: "with_path_override", args: map[string]interface{}{"path": "/api/v2/users"}},
		{
			name: "with_query_modifications",
			args: map[string]interface{}{
				"set_query":    []interface{}{"page=1", "limit=10"},
				"remove_query": []interface{}{"debug"},
			},
		},
		{name: "with_body_replacement", args: map[string]interface{}{"body": `{"completely":"new"}`}},
		{
			name: "with_json_modifications",
			args: map[string]interface{}{
				"set_json":    map[string]interface{}{"name": "modified", "email": "test@example.com"},
				"remove_json": []interface{}{"temp"},
			},
		},
		{name: "with_timeout", args: map[string]interface{}{"timeout": "5s"}},
		{name: "with_follow_redirects", args: map[string]interface{}{"follow_redirects": true}},
	}

	for _, tc := range modCases {
		t.Run(tc.name, func(t *testing.T) {
			args := make(map[string]interface{}, len(tc.args)+1)
			args["flow_id"] = flowID
			for k, v := range tc.args {
				args[k] = v
			}
			resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", args)
			assert.NotEmpty(t, resp.ReplayID)
		})
	}
}

func TestMCP_ReplayGetFullBodyReturnsBase64(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMCPServerWithMock(t)

	// Add proxy entry
	mockMCP.AddProxyEntry(
		"GET /api/replay HTTP/1.1\r\nHost: test.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\n\r\noriginal",
		"",
	)

	// Set send response to return plain text body
	mockMCP.SetSendResponse(
		"HttpRequestResponse{httpRequest=GET /api/replay HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nreplay response body}",
	)

	// Get flow_id
	listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
		"output_mode": "flows",
		"host":        "test.com",
	})
	require.NotEmpty(t, listResp.Flows)
	flowID := listResp.Flows[0].FlowID

	// Send replay request
	sendResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
		"flow_id": flowID,
	})
	require.NotEmpty(t, sendResp.ReplayID)

	// Get replay result with full_body=true
	getResult := CallMCPTool(t, mcpClient, "replay_get", map[string]interface{}{
		"replay_id": sendResp.ReplayID,
		"full_body": true,
	})
	require.False(t, getResult.IsError)

	var getResp protocol.ReplayGetResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, getResult)), &getResp))

	// Decode base64 body and verify content
	decodedBody, err := base64.StdEncoding.DecodeString(getResp.RespBody)
	require.NoError(t, err)
	assert.Equal(t, "replay response body", string(decodedBody))
}

func TestMCP_ReplaySendCompressesBodyWhenModified(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMCPServerWithMock(t)

	// Add proxy entry with Content-Encoding: gzip header
	mockMCP.AddProxyEntry(
		"POST /api/data HTTP/1.1\r\nHost: test.com\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\n\r\noriginal body",
		"HTTP/1.1 200 OK\r\n\r\nok",
		"",
	)
	mockMCP.SetSendResponse(
		"HttpRequestResponse{httpRequest=POST /api/data HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\n\r\nmodified}",
	)

	// Get flow_id
	listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
		"output_mode": "flows",
		"method":      "POST",
	})
	require.NotEmpty(t, listResp.Flows)
	flowID := listResp.Flows[0].FlowID

	// Send replay with new body - should compress since Content-Encoding: gzip is present
	const newBody = "new body content that should be compressed"
	sendResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
		"flow_id": flowID,
		"body":    newBody,
	})
	require.NotEmpty(t, sendResp.ReplayID)

	// Verify the sent request body was transformed (compressed).
	// Note: Binary gzip bytes get corrupted when passed through the JSON/string-based MCP protocol,
	// so we verify compression indirectly by checking the body differs from the uncompressed input.
	// The actual compression logic is tested in TestCompressBody.
	sentRequest := mockMCP.LastSentRequest()
	require.NotEmpty(t, sentRequest)

	parts := strings.SplitN(sentRequest, "\r\n\r\n", 2)
	require.Len(t, parts, 2)
	sentBody := parts[1]

	// Body should be different from the uncompressed input (compression was applied)
	assert.NotEqual(t, newBody, sentBody)

	// Verify Content-Length header was updated to match compressed size
	assert.Contains(t, parts[0], "Content-Length:")
}

func TestMCP_ReplaySendNoCompressionWhenBodyUnmodified(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMCPServerWithMock(t)

	const originalBody = "original body unchanged"
	mockMCP.AddProxyEntry(
		"POST /api/data HTTP/1.1\r\nHost: test.com\r\nContent-Type: application/json\r\n\r\n"+originalBody,
		"HTTP/1.1 200 OK\r\n\r\nok",
		"",
	)
	mockMCP.SetSendResponse(
		"HttpRequestResponse{httpRequest=POST /api/data HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\n\r\nok}",
	)

	listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
		"output_mode": "flows",
		"method":      "POST",
	})
	require.NotEmpty(t, listResp.Flows)
	flowID := listResp.Flows[0].FlowID

	// Send replay WITHOUT modifying body
	sendResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
		"flow_id": flowID,
	})
	require.NotEmpty(t, sendResp.ReplayID)

	// Verify body was sent unchanged (no compression applied)
	sentRequest := mockMCP.LastSentRequest()
	parts := strings.SplitN(sentRequest, "\r\n\r\n", 2)
	require.Len(t, parts, 2)
	assert.Equal(t, originalBody, parts[1])
}

func TestMCP_ReplaySendSetJSONTriggersCompression(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMCPServerWithMock(t)

	// Original JSON body (stored uncompressed, but request has Content-Encoding: gzip)
	const originalJSON = `{"key":"value"}`
	mockMCP.AddProxyEntry(
		"POST /api/data HTTP/1.1\r\nHost: test.com\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\n\r\n"+originalJSON,
		"HTTP/1.1 200 OK\r\n\r\nok",
		"",
	)
	mockMCP.SetSendResponse(
		"HttpRequestResponse{httpRequest=POST /api/data HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\n\r\nok}",
	)

	listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
		"output_mode": "flows",
		"method":      "POST",
	})
	require.NotEmpty(t, listResp.Flows)
	flowID := listResp.Flows[0].FlowID

	// Send replay with set_json modification - should trigger compression
	sendResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
		"flow_id":  flowID,
		"set_json": map[string]interface{}{"key": "modified"},
	})
	require.NotEmpty(t, sendResp.ReplayID)

	// Verify body was compressed (different from both original and modified JSON plaintext)
	sentRequest := mockMCP.LastSentRequest()
	parts := strings.SplitN(sentRequest, "\r\n\r\n", 2)
	require.Len(t, parts, 2)
	sentBody := parts[1]

	// Body should not be plaintext JSON
	assert.NotEqual(t, originalJSON, sentBody)
	assert.NotContains(t, sentBody, `"key"`)
}

func TestMCP_RequestSendCompressesBody(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMCPServerWithMock(t)

	mockMCP.SetSendResponse(
		"HttpRequestResponse{httpRequest=POST /api/data HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\n\r\nok}",
	)

	// Send request with Content-Encoding: gzip header
	const originalBody = "uncompressed body content for request_send"
	sendResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", map[string]interface{}{
		"url":    "https://test.com/api/data",
		"method": "POST",
		"headers": map[string]interface{}{
			"Content-Encoding": "gzip",
			"Content-Type":     "application/json",
		},
		"body": originalBody,
	})
	require.NotEmpty(t, sendResp.ReplayID)

	// Verify the sent request body was transformed (compressed).
	// Note: Binary gzip bytes get corrupted when passed through the JSON/string-based MCP protocol,
	// so we verify compression indirectly. The actual compression is tested in TestCompressBody.
	sentRequest := mockMCP.LastSentRequest()
	require.NotEmpty(t, sentRequest)

	parts := strings.SplitN(sentRequest, "\r\n\r\n", 2)
	require.Len(t, parts, 2)
	sentBody := parts[1]

	// Body should be different from the uncompressed input
	assert.NotEqual(t, originalBody, sentBody)

	// Verify Content-Length header exists
	assert.Contains(t, parts[0], "Content-Length:")
}

func TestMCP_RequestSendNoCompressionWithoutHeader(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMCPServerWithMock(t)

	mockMCP.SetSendResponse(
		"HttpRequestResponse{httpRequest=POST /api/data HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\n\r\nok}",
	)

	// Send request WITHOUT Content-Encoding header
	originalBody := "plain body without compression"
	sendResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", map[string]interface{}{
		"url":    "https://test.com/api/data",
		"method": "POST",
		"headers": map[string]interface{}{
			"Content-Type": "text/plain",
		},
		"body": originalBody,
	})
	require.NotEmpty(t, sendResp.ReplayID)

	// Verify body was sent uncompressed
	sentRequest := mockMCP.LastSentRequest()
	parts := strings.SplitN(sentRequest, "\r\n\r\n", 2)
	require.Len(t, parts, 2)
	assert.Equal(t, originalBody, parts[1])
}

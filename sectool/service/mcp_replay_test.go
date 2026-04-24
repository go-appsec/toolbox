package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sectool/protocol"
)

func TestHandleReplaySend(t *testing.T) {
	t.Parallel()

	t.Run("happy_path", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.AddProxyEntry(
			"GET /replay-test HTTP/1.1\r\nHost: mock.test\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\noriginal",
			"",
		)
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n",
			"replayed response",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "GET",
		})
		require.NotEmpty(t, listResp.Flows)
		flowID := listResp.Flows[0].FlowID

		sendResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
		})
		assert.NotEmpty(t, sendResp.FlowID)
		assert.NotEmpty(t, sendResp.Duration)
	})

	t.Run("missing_flow_id", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil)

		result := CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "flow_id")
	})

	t.Run("invalid_flow_id", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil)

		result := CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "not found")
	})

	t.Run("from_crawler_flow", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, mockCrawler := setupMockMCPServer(t, nil)

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

		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"replayed",
		)

		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": crawlFlowID,
		})
		assert.NotEmpty(t, resp.FlowID)
	})

	t.Run("set_headers_array", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.AddProxyEntry(
			"GET /header-test HTTP/1.1\r\nHost: mock.test\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\noriginal",
			"",
		)
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "GET",
		})
		require.NotEmpty(t, listResp.Flows)
		flowID := listResp.Flows[0].FlowID

		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":     flowID,
			"set_headers": []interface{}{"X-Test-Header: ArrayFormat"},
		})
		assert.NotEmpty(t, resp.FlowID)
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "X-Test-Header: ArrayFormat")
	})

	t.Run("set_headers_object", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.AddProxyEntry(
			"GET /header-test HTTP/1.1\r\nHost: mock.test\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\noriginal",
			"",
		)
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "GET",
		})
		require.NotEmpty(t, listResp.Flows)
		flowID := listResp.Flows[0].FlowID

		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
			"set_headers": map[string]interface{}{
				"X-Test-Header": "ObjectFormat",
			},
		})
		assert.NotEmpty(t, resp.FlowID)
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "X-Test-Header: ObjectFormat")
	})

	t.Run("with_path_override", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.AddProxyEntry(
			"POST /api/users HTTP/1.1\r\nHost: original.test\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test\"}",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"modified",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "POST",
		})
		require.NotEmpty(t, listResp.Flows)
		flowID := listResp.Flows[0].FlowID

		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
			"path":    "/api/v2/users",
		})
		assert.NotEmpty(t, resp.FlowID)
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "POST /api/v2/users HTTP/1.1")
	})

	t.Run("with_query_modifications", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.AddProxyEntry(
			"POST /api/users HTTP/1.1\r\nHost: original.test\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test\"}",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"modified",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "POST",
		})
		require.NotEmpty(t, listResp.Flows)
		flowID := listResp.Flows[0].FlowID

		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":   flowID,
			"set_query": []interface{}{"page=1", "limit=10"},
		})
		assert.NotEmpty(t, resp.FlowID)
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "page=1")
		assert.Contains(t, sent, "limit=10")
	})

	t.Run("with_json_modifications", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.AddProxyEntry(
			"POST /api/users HTTP/1.1\r\nHost: original.test\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test\",\"temp\":\"remove\"}",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"modified",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "POST",
		})
		require.NotEmpty(t, listResp.Flows)
		flowID := listResp.Flows[0].FlowID

		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":     flowID,
			"set_json":    map[string]interface{}{"name": "modified", "email": "test@example.com"},
			"remove_json": []interface{}{"temp"},
		})
		assert.NotEmpty(t, resp.FlowID)
		sent := mockHTTP.LastSentRequest()
		parts := strings.SplitN(sent, "\r\n\r\n", 2)
		require.Len(t, parts, 2)
		var body map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(parts[1]), &body))
		assert.Equal(t, "modified", body["name"])
		assert.Equal(t, "test@example.com", body["email"])
		assert.NotContains(t, body, "temp")
	})

	t.Run("form_encoded_rejects_set_json", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.AddProxyEntry(
			"POST /oauth2/token HTTP/1.1\r\nHost: idp.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ngrant_type=refresh_token&refresh_token=x",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "POST",
		})
		require.NotEmpty(t, listResp.Flows)
		flowID := listResp.Flows[0].FlowID

		result := CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":  flowID,
			"set_json": map[string]interface{}{"grant_type": "password"},
		})
		assert.True(t, result.IsError)
		text := ExtractMCPText(t, result)
		assert.Contains(t, text, "application/x-www-form-urlencoded")
		assert.Contains(t, text, "set_form")
		assert.NotContains(t, text, "invalid character 'g'")
	})

	t.Run("set_form_modifies_form_encoded_body", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.AddProxyEntry(
			"POST /oauth2/token HTTP/1.1\r\nHost: idp.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ngrant_type=refresh_token&refresh_token=abc",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"replayed",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "POST",
		})
		require.NotEmpty(t, listResp.Flows)
		flowID := listResp.Flows[0].FlowID

		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":     flowID,
			"set_form":    map[string]interface{}{"grant_type": "password", "scope": "read"},
			"remove_form": []interface{}{"refresh_token"},
		})
		assert.NotEmpty(t, resp.FlowID)
		sent := mockHTTP.LastSentRequest()
		parts := strings.SplitN(sent, "\r\n\r\n", 2)
		require.Len(t, parts, 2)
		assert.Contains(t, parts[1], "grant_type=password")
		assert.Contains(t, parts[1], "scope=read")
		assert.NotContains(t, parts[1], "refresh_token")
	})

	t.Run("form_encoded_rejects_set_json_with_charset", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.AddProxyEntry(
			"POST /oauth2/token HTTP/1.1\r\nHost: idp.test\r\nContent-Type: application/x-www-form-urlencoded; charset=utf-8\r\n\r\ngrant_type=refresh_token",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "POST",
		})
		require.NotEmpty(t, listResp.Flows)
		flowID := listResp.Flows[0].FlowID

		result := CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":  flowID,
			"set_json": map[string]interface{}{"x": "y"},
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "application/x-www-form-urlencoded")
	})

	t.Run("with_follow_redirects", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.AddProxyEntry(
			"POST /api/users HTTP/1.1\r\nHost: original.test\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test\"}",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"modified",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "POST",
		})
		require.NotEmpty(t, listResp.Flows)
		flowID := listResp.Flows[0].FlowID

		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":          flowID,
			"follow_redirects": true,
		})
		assert.NotEmpty(t, resp.FlowID)
	})

	t.Run("with_body_replacement", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.AddProxyEntry(
			"POST /api/users HTTP/1.1\r\nHost: original.test\r\nContent-Type: application/json\r\n\r\n{\"name\":\"original\"}",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"modified",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "POST",
		})
		require.NotEmpty(t, listResp.Flows)
		flowID := listResp.Flows[0].FlowID

		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
			"body":    `{"completely":"new"}`,
		})
		assert.NotEmpty(t, resp.FlowID)
		sent := mockHTTP.LastSentRequest()
		parts := strings.SplitN(sent, "\r\n\r\n", 2)
		require.Len(t, parts, 2)
		assert.JSONEq(t, `{"completely":"new"}`, parts[1])
	})

	t.Run("compresses_modified_body", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.AddProxyEntry(
			"POST /api/data HTTP/1.1\r\nHost: test.com\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\n\r\noriginal body",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"modified",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "POST",
		})
		require.NotEmpty(t, listResp.Flows)
		flowID := listResp.Flows[0].FlowID

		const newBody = "new body content that should be compressed"
		sendResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
			"body":    newBody,
		})
		require.NotEmpty(t, sendResp.FlowID)

		sentRequest := mockHTTP.LastSentRequest()
		require.NotEmpty(t, sentRequest)

		parts := strings.SplitN(sentRequest, "\r\n\r\n", 2)
		require.Len(t, parts, 2)
		sentBody := parts[1]

		assert.NotEqual(t, newBody, sentBody)
		assert.Contains(t, parts[0], "Content-Length:")
	})

	t.Run("no_compression_unmodified", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		const originalBody = "original body unchanged"
		mockHTTP.AddProxyEntry(
			"POST /api/data HTTP/1.1\r\nHost: test.com\r\nContent-Type: application/json\r\n\r\n"+originalBody,
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "POST",
		})
		require.NotEmpty(t, listResp.Flows)
		flowID := listResp.Flows[0].FlowID

		sendResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
		})
		require.NotEmpty(t, sendResp.FlowID)

		sentRequest := mockHTTP.LastSentRequest()
		parts := strings.SplitN(sentRequest, "\r\n\r\n", 2)
		require.Len(t, parts, 2)
		assert.Equal(t, originalBody, parts[1])
	})

	t.Run("set_json_triggers_compression", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		const originalJSON = `{"key":"value"}`
		mockHTTP.AddProxyEntry(
			"POST /api/data HTTP/1.1\r\nHost: test.com\r\nContent-Encoding: gzip\r\nContent-Type: application/json\r\n\r\n"+originalJSON,
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "POST",
		})
		require.NotEmpty(t, listResp.Flows)
		flowID := listResp.Flows[0].FlowID

		sendResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":  flowID,
			"set_json": map[string]interface{}{"key": "modified"},
		})
		require.NotEmpty(t, sendResp.FlowID)

		sentRequest := mockHTTP.LastSentRequest()
		parts := strings.SplitN(sentRequest, "\r\n\r\n", 2)
		require.Len(t, parts, 2)
		sentBody := parts[1]

		assert.NotEqual(t, originalJSON, sentBody)
		assert.NotContains(t, sentBody, `"key"`)
	})
}

func TestHandleRequestSend(t *testing.T) {
	t.Parallel()

	t.Run("defaults_to_get", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", map[string]interface{}{
			"url": "https://example.com/test",
		})
		assert.NotEmpty(t, resp.FlowID)
		assert.Equal(t, 200, resp.Status)
	})

	t.Run("missing_url", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil)

		result := CallMCPTool(t, mcpClient, "request_send", map[string]interface{}{
			"method": "GET",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "url is required")
	})

	t.Run("invalid_url", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil)

		result := CallMCPTool(t, mcpClient, "request_send", map[string]interface{}{
			"url": "://invalid",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "invalid URL")
	})

	t.Run("headers_object", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", map[string]interface{}{
			"url":    "https://example.com/test",
			"method": "GET",
			"headers": map[string]interface{}{
				"X-Test-Header": "ObjectFormat",
			},
		})
		assert.NotEmpty(t, resp.FlowID)
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "X-Test-Header: ObjectFormat")
	})

	t.Run("headers_array", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", map[string]interface{}{
			"url":    "https://example.com/test",
			"method": "GET",
			"headers": []interface{}{
				"X-Test-Header: ArrayFormat",
			},
		})
		assert.NotEmpty(t, resp.FlowID)
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "X-Test-Header: ArrayFormat")
	})

	t.Run("headers_string_array", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", map[string]interface{}{
			"url":     "https://example.com/test",
			"method":  "GET",
			"headers": `["X-String-Header: from-string-array"]`,
		})
		assert.NotEmpty(t, resp.FlowID)
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "X-String-Header: from-string-array")
	})

	t.Run("headers_string_object", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", map[string]interface{}{
			"url":     "https://example.com/test",
			"method":  "GET",
			"headers": `{"X-String-Header": "from-string-object"}`,
		})
		assert.NotEmpty(t, resp.FlowID)
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "X-String-Header: from-string-object")
	})

	t.Run("compresses_with_encoding", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)

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
		require.NotEmpty(t, sendResp.FlowID)

		sentRequest := mockHTTP.LastSentRequest()
		require.NotEmpty(t, sentRequest)

		parts := strings.SplitN(sentRequest, "\r\n\r\n", 2)
		require.Len(t, parts, 2)
		sentBody := parts[1]

		assert.NotEqual(t, originalBody, sentBody)
		assert.Contains(t, parts[0], "Content-Length:")
	})

	t.Run("no_compression_without_header", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)

		originalBody := "plain body without compression"
		sendResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", map[string]interface{}{
			"url":    "https://test.com/api/data",
			"method": "POST",
			"headers": map[string]interface{}{
				"Content-Type": "text/plain",
			},
			"body": originalBody,
		})
		require.NotEmpty(t, sendResp.FlowID)

		sentRequest := mockHTTP.LastSentRequest()
		parts := strings.SplitN(sentRequest, "\r\n\r\n", 2)
		require.Len(t, parts, 2)
		assert.Equal(t, originalBody, parts[1])
	})

	t.Run("te_with_force", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", map[string]interface{}{
			"url":     "https://wire.test/test",
			"method":  "POST",
			"body":    "hello",
			"headers": []interface{}{"Transfer-Encoding: chunked"},
			"force":   true,
		})
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "Transfer-Encoding: chunked")
		assert.NotContains(t, sent, "Content-Length:")
	})

	t.Run("explicit_cl_with_force", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", map[string]interface{}{
			"url":     "https://wire.test/test",
			"method":  "POST",
			"body":    "hello",
			"headers": []interface{}{"Content-Length: 100"},
			"force":   true,
		})
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "Content-Length: 100")
	})

	t.Run("user_host_preserved", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", map[string]interface{}{
			"url":     "https://wire.test/test",
			"headers": []interface{}{"Host: vhost.internal"},
		})
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "Host: vhost.internal")
		assert.NotContains(t, sent, "Host: wire.test")
	})
}

func TestExecuteSend_WireFidelity(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

	mockHTTP.AddProxyEntry(
		"POST /test HTTP/1.1\r\nHost: wire.test\r\nContent-Length: 5\r\n\r\nhello",
		"HTTP/1.1 200 OK\r\n\r\nok",
		"",
	)
	mockHTTP.SetSendResult(
		"HTTP/1.1 200 OK\r\n",
		"ok",
	)

	listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
		"output_mode": "flows",
		"limit":       1,
	})
	require.NotEmpty(t, listResp.Flows)
	flowID := listResp.Flows[0].FlowID

	t.Run("cl_not_recalculated_when_body_unchanged", func(t *testing.T) {
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
			"force":   true,
		})
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "Content-Length: 5")
	})

	t.Run("cl_removed_stays_removed", func(t *testing.T) {
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":        flowID,
			"remove_headers": []interface{}{"Content-Length"},
			"force":          true,
		})
		sent := mockHTTP.LastSentRequest()
		assert.NotContains(t, sent, "Content-Length")
	})

	t.Run("duplicate_te_preserved_with_force", func(t *testing.T) {
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":     flowID,
			"set_headers": []interface{}{"Transfer-Encoding: chunked", "Transfer-Encoding: identity"},
			"force":       true,
		})
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "Transfer-Encoding: chunked")
		assert.Contains(t, sent, "Transfer-Encoding: identity")
	})

	t.Run("duplicate_cl_no_crash_with_force", func(t *testing.T) {
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":     flowID,
			"set_headers": []interface{}{"Content-Length: 5", "Content-Length: 100"},
			"force":       true,
		})
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "Content-Length: 5")
		assert.Contains(t, sent, "Content-Length: 100")
	})

	t.Run("header_whitespace_blocked_without_force", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":     flowID,
			"set_headers": []interface{}{"Content-Length : 4"},
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "header-whitespace")
	})

	t.Run("te_cl_conflict_blocked_without_force", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":     flowID,
			"set_headers": []interface{}{"Transfer-Encoding:  chunked"},
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "te-cl-conflict")
	})

	t.Run("te_cl_conflict_allowed_with_force", func(t *testing.T) {
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":     flowID,
			"set_headers": []interface{}{"Transfer-Encoding:  chunked"},
			"force":       true,
		})
		assert.NotEmpty(t, resp.FlowID)
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "Transfer-Encoding:  chunked")
	})

	t.Run("cl_auto_update_with_body_mod", func(t *testing.T) {
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
			"body":    "new body content",
			"force":   true,
		})
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "Content-Length: 16")
	})

	t.Run("explicit_cl_preserved_with_body_mod", func(t *testing.T) {
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":     flowID,
			"body":        "hello",
			"set_headers": []interface{}{"Content-Length: 99"},
			"force":       true,
		})
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "Content-Length: 99")
	})

	t.Run("user_host_preserved_with_target", func(t *testing.T) {
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":     flowID,
			"target":      "https://staging.test:8443",
			"set_headers": []interface{}{"Host: vhost.internal"},
			"force":       true,
		})
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "Host: vhost.internal")
		assert.NotContains(t, sent, "Host: staging.test")
	})

	t.Run("crlf_in_header_with_force", func(t *testing.T) {
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":     flowID,
			"set_headers": []interface{}{"X-Test: value\r\nX-Injected: crlf"},
			"force":       true,
		})
		assert.NotEmpty(t, resp.FlowID)
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "X-Test: value")
		assert.Contains(t, sent, "X-Injected: crlf")
		assert.Contains(t, sent, "hello")
	})

	t.Run("crlf_te_injection_with_force", func(t *testing.T) {
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":     flowID,
			"set_headers": []interface{}{"Transfer-Encoding: chunked\r\nX-Injected: crlf"},
			"force":       true,
		})
		assert.NotEmpty(t, resp.FlowID)
		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "Transfer-Encoding: chunked")
		assert.Contains(t, sent, "X-Injected: crlf")
		assert.Contains(t, sent, "hello")
	})

	t.Run("method_post_to_get_strips_body", func(t *testing.T) {
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
			"method":  "GET",
		})
		sent := mockHTTP.LastSentRequest()
		assert.True(t, strings.HasPrefix(sent, "GET "))
		assert.NotContains(t, sent, "Content-Length")
		parts := strings.SplitN(sent, "\r\n\r\n", 2)
		require.Len(t, parts, 2)
		assert.Empty(t, parts[1])
	})

	t.Run("method_post_to_head_strips_body", func(t *testing.T) {
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"",
		)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
			"method":  "HEAD",
		})
		sent := mockHTTP.LastSentRequest()
		assert.True(t, strings.HasPrefix(sent, "HEAD "))
		assert.NotContains(t, sent, "Content-Length")
	})

	t.Run("method_post_to_get_with_force_keeps_body", func(t *testing.T) {
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
			"method":  "GET",
			"force":   true,
		})
		sent := mockHTTP.LastSentRequest()
		assert.True(t, strings.HasPrefix(sent, "GET "))
		assert.Contains(t, sent, "Content-Length: 5")
		assert.Contains(t, sent, "hello")
	})

	t.Run("method_post_to_get_explicit_body_kept", func(t *testing.T) {
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
			"method":  "GET",
			"body":    "explicit body",
		})
		sent := mockHTTP.LastSentRequest()
		assert.True(t, strings.HasPrefix(sent, "GET "))
		assert.Contains(t, sent, "explicit body")
	})

	t.Run("method_post_to_put_keeps_body", func(t *testing.T) {
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
			"method":  "PUT",
		})
		sent := mockHTTP.LastSentRequest()
		assert.True(t, strings.HasPrefix(sent, "PUT "))
		assert.Contains(t, sent, "Content-Length: 5")
		assert.Contains(t, sent, "hello")
	})

	t.Run("chunked_body_replacement", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		chunkedReq := "POST /case1 HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Connection: close\r\n" +
			"\r\n" +
			"5\r\nhello\r\n0\r\n\r\n"
		mockHTTP.AddProxyEntry(chunkedReq, "HTTP/1.1 200 OK\r\n\r\norig", "")
		mockHTTP.SetSendResult("HTTP/1.1 200 OK\r\n", "ok")

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "POST",
		})
		require.NotEmpty(t, listResp.Flows)

		newBody := "DIFFERENT body now - 42 bytes of fresh con"
		require.Len(t, newBody, 42)
		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": listResp.Flows[0].FlowID,
			"body":    newBody,
			"force":   true,
		})

		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "Transfer-Encoding: chunked")
		assert.Contains(t, sent, "\r\n2a\r\n")
		assert.True(t, strings.HasSuffix(sent, "0\r\n\r\n"))
	})

	t.Run("chunked_trailer_headers_with_new_body", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		chunkedReq := "POST /case2 HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"TE: trailers\r\n" +
			"Trailer: X-Trailer-One, X-Trailer-Two\r\n" +
			"\r\n" +
			"5\r\nhello\r\n0\r\n" +
			"X-Trailer-One: a\r\n" +
			"X-Trailer-Two: b\r\n" +
			"\r\n"
		mockHTTP.AddProxyEntry(chunkedReq, "HTTP/1.1 200 OK\r\n\r\norig", "")
		mockHTTP.SetSendResult("HTTP/1.1 200 OK\r\n", "ok")

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "POST",
		})
		require.NotEmpty(t, listResp.Flows)

		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": listResp.Flows[0].FlowID,
			"body":    "new body",
			"force":   true,
		})

		sent := mockHTTP.LastSentRequest()
		assert.Contains(t, sent, "Transfer-Encoding: chunked")
		assert.Contains(t, sent, "\r\n8\r\n")
		assert.Contains(t, sent, "new body")
	})
}

func TestExecuteSend_DomainScoping(t *testing.T) {
	t.Parallel()

	t.Run("replay_send_rejected", func(t *testing.T) {
		t.Parallel()

		srv, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, &config.Config{
			AllowedDomains: []string{"allowed.test"},
		})

		mockHTTP.AddProxyEntry(
			"GET /page HTTP/1.1\r\nHost: blocked.test\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)

		flowID := srv.proxyIndex.Register(0)

		result := CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "domain rejected")
	})

	t.Run("replay_send_force_still_rejected", func(t *testing.T) {
		t.Parallel()

		srv, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, &config.Config{
			AllowedDomains: []string{"allowed.test"},
		})

		mockHTTP.AddProxyEntry(
			"GET /page HTTP/1.1\r\nHost: blocked.test\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)

		flowID := srv.proxyIndex.Register(0)

		result := CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
			"force":   true,
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "domain rejected")
	})

	t.Run("request_send_rejected", func(t *testing.T) {
		t.Parallel()

		_, mcpClient, _, _, _ := setupMockMCPServer(t, &config.Config{
			AllowedDomains: []string{"allowed.test"},
		})

		result := CallMCPTool(t, mcpClient, "request_send", map[string]interface{}{
			"url": "https://blocked.test/api",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "domain rejected")
	})

	t.Run("request_send_excluded_subdomain", func(t *testing.T) {
		t.Parallel()

		_, mcpClient, _, _, _ := setupMockMCPServer(t, &config.Config{
			ExcludeDomains: []string{"internal.corp"},
		})

		result := CallMCPTool(t, mcpClient, "request_send", map[string]interface{}{
			"url": "https://db.internal.corp/admin",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "domain rejected")
	})

	t.Run("allowed_domain_succeeds", func(t *testing.T) {
		t.Parallel()

		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, &config.Config{
			AllowedDomains: []string{"allowed.test"},
		})

		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)

		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", map[string]interface{}{
			"url": "https://allowed.test/ok",
		})
		assert.NotEmpty(t, resp.FlowID)
	})
}

package service

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

func TestHandleReplaySend(t *testing.T) {
	t.Parallel()

	t.Run("happy_path", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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
		assert.Equal(t, 200, sendResp.Status)
		assert.Contains(t, mockHTTP.LastSentRequest(), "GET /replay-test HTTP/1.1")
		assert.False(t, mockHTTP.LastSendInput().FollowRedirects) // omitted -> default false
	})

	t.Run("follow_redirects_propagates", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		mockHTTP.AddProxyEntry(
			"GET /replay-test HTTP/1.1\r\nHost: mock.test\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\noriginal",
			"",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "GET",
		})
		require.NotEmpty(t, listResp.Flows)

		sendResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":          listResp.Flows[0].FlowID,
			"follow_redirects": true,
		})
		assert.NotEmpty(t, sendResp.FlowID)
		assert.True(t, mockHTTP.LastSendInput().FollowRedirects)
	})

	t.Run("missing_flow_id", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		result := CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "flow_id")
	})

	t.Run("invalid_flow_id", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		result := CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "not found")
	})

	t.Run("from_crawler_flow", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, mockCrawler := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		createResp := CallMCPToolJSONOK[protocol.CrawlCreateResponse](t, mcpClient, "crawl_create", map[string]interface{}{
			"seed_urls": "https://crawl.test",
		})

		crawlFlowID := "crawl-flow-replay"
		err := mockCrawler.AddFlow(createResp.SessionID, store.CrawlFlow{
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
		assert.Contains(t, mockHTTP.LastSentRequest(), "GET /page HTTP/1.1")
	})

	// set_headers accepts either an array of "Name: value" strings or a name→value
	// object; both must reach the sent request identically.
	t.Run("set_headers_shapes", func(t *testing.T) {
		cases := []struct {
			name       string
			setHeaders interface{}
			want       string
		}{
			{"array", []interface{}{"X-Test-Header: ArrayFormat"}, "X-Test-Header: ArrayFormat"},
			{"object", map[string]interface{}{"X-Test-Header": "ObjectFormat"}, "X-Test-Header: ObjectFormat"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

				mockHTTP.AddProxyEntry("GET /header-test HTTP/1.1\r\nHost: mock.test\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\noriginal", "")
				mockHTTP.SetSendResult("HTTP/1.1 200 OK\r\n", "ok")

				listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
					"output_mode": "flows",
					"method":      "GET",
				})
				require.NotEmpty(t, listResp.Flows)

				resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
					"flow_id":     listResp.Flows[0].FlowID,
					"set_headers": tc.setHeaders,
				})
				assert.NotEmpty(t, resp.FlowID)
				assert.Contains(t, mockHTTP.LastSentRequest(), tc.want)
			})
		}
	})

	t.Run("with_path_override", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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

	t.Run("body_then_json_order", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		mockHTTP.AddProxyEntry(
			"POST /api HTTP/1.1\r\nHost: mock.test\r\nContent-Type: application/json\r\n\r\n{\"old\":1}",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)
		mockHTTP.SetSendResult("HTTP/1.1 200 OK\r\n", "ok")

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "POST",
		})
		require.NotEmpty(t, listResp.Flows)

		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id":  listResp.Flows[0].FlowID,
			"body":     `{"a":0}`,
			"set_json": map[string]interface{}{"a": "1"},
		})
		assert.NotEmpty(t, resp.FlowID)

		parts := strings.SplitN(mockHTTP.LastSentRequest(), "\r\n\r\n", 2)
		require.Len(t, parts, 2)
		assert.JSONEq(t, `{"a":1}`, parts[1])
	})

	t.Run("form_encoded_rejects_set_json", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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

	t.Run("with_body_replacement", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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

	t.Run("decompresses_response_preview", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		mockHTTP.AddProxyEntry(
			"GET /api/data HTTP/1.1\r\nHost: test.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)
		const plaintext = "decompressed response preview body"
		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Type: text/plain\r\n",
			string(compressGzip(t, []byte(plaintext))),
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "GET",
		})
		require.NotEmpty(t, listResp.Flows)

		sendResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": listResp.Flows[0].FlowID,
		})
		assert.Equal(t, plaintext, sendResp.RespPreview)
	})

	t.Run("no_compression_unmodified", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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
		assert.NotEqual(t, originalJSON, parts[1])
		assert.Contains(t, parts[0], "Content-Encoding: gzip")

		// flate may emit stored blocks for tiny bodies; decode rather than sniff raw bytes
		gr, err := gzip.NewReader(strings.NewReader(parts[1]))
		require.NoError(t, err)
		decoded, err := io.ReadAll(gr)
		require.NoError(t, err)
		assert.JSONEq(t, `{"key":"modified"}`, string(decoded))
	})
}

// TestBuildMutations pins the ordered op list the sidecar replay path forwards.
// Routing of a sidecar-owned flow through its adapter is covered end-to-end by
// TestSidecarReplaySendE2E; here we assert the structured mutation grammar that
// must mirror executeSend's native application.
func TestBuildMutations(t *testing.T) {
	t.Parallel()

	t.Run("documented_op_order", func(t *testing.T) {
		req := argRequest(map[string]interface{}{
			"remove_headers": []interface{}{"X-Old"},
			"set_headers":    []interface{}{"X-New: 1"},
			"set_json":       map[string]interface{}{"a": 1},
			"remove_json":    []interface{}{"b"},
			"set_form":       map[string]interface{}{"f": "v"},
			"remove_form":    []interface{}{"g"},
			"remove_query":   []interface{}{"q"},
			"set_query":      []interface{}{"r=2"},
			"method":         "PUT",
			"path":           "/p",
			"query":          "x=1",
			"body":           "raw",
		})
		muts := buildMutations(req)
		ops := make([]string, 0, len(muts))
		for _, mu := range muts {
			ops = append(ops, mu.Op)
		}
		assert.Equal(t, []string{
			"remove_header", "set_header",
			"body",
			"remove_json", "set_json",
			"remove_form", "set_form",
			"remove_query", "set_query",
			"method", "path", "query",
		}, ops)
	})

	t.Run("empty_request_no_mutations", func(t *testing.T) {
		assert.Empty(t, buildMutations(argRequest(map[string]interface{}{})))
	})
}

func TestHandleReplaySendSidecarRouting(t *testing.T) {
	t.Parallel()

	t.Run("unregistered_adapter_stays_native", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)
		// Adapter set but no sidecar registry (mock backend): native replay runs.
		flowID := mockHTTP.AddProxyEntryAdapter(
			"GET /x HTTP/1.1\r\nHost: mock.test\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", "ghost")
		mockHTTP.SetSendResult("HTTP/1.1 200 OK\r\n", "native")

		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
		})
		// Native replay produced a real flow and actually sent upstream
		assert.NotEmpty(t, resp.FlowID)
		assert.NotEmpty(t, mockHTTP.LastSentRequest())
	})
}

func TestHandleRequestSend(t *testing.T) {
	t.Parallel()

	t.Run("defaults_to_get", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		mockHTTP.SetSendResult(
			"HTTP/1.1 200 OK\r\n",
			"ok",
		)
		resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", map[string]interface{}{
			"url": "https://example.com/test",
		})
		assert.NotEmpty(t, resp.FlowID)
		assert.Equal(t, 200, resp.Status)
		assert.True(t, strings.HasPrefix(mockHTTP.LastSentRequest(), "GET "))
	})

	t.Run("missing_url", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		result := CallMCPTool(t, mcpClient, "request_send", map[string]interface{}{
			"method": "GET",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "url is required")
	})

	t.Run("invalid_url", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		result := CallMCPTool(t, mcpClient, "request_send", map[string]interface{}{
			"url": "://invalid",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "invalid URL")
	})

	// headers accepts a name→value object, an array of "Name: value" strings, a
	// JSON-string encoding of either, or a single "Name: value" string; all reach
	// the sent request identically.
	t.Run("header_shapes", func(t *testing.T) {
		cases := []struct {
			name    string
			headers interface{}
			want    string
		}{
			{"object", map[string]interface{}{"X-Test-Header": "ObjectFormat"}, "X-Test-Header: ObjectFormat"},
			{"array", []interface{}{"X-Test-Header: ArrayFormat"}, "X-Test-Header: ArrayFormat"},
			{"string_array", `["X-String-Header: from-string-array"]`, "X-String-Header: from-string-array"},
			{"string_object", `{"X-String-Header": "from-string-object"}`, "X-String-Header: from-string-object"},
			{"single_string", "X-Test-Header: single-string", "X-Test-Header: single-string"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

				mockHTTP.SetSendResult("HTTP/1.1 200 OK\r\n", "ok")
				resp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "request_send", map[string]interface{}{
					"url":     "https://example.com/test",
					"headers": tc.headers,
				})
				assert.NotEmpty(t, resp.FlowID)
				assert.Contains(t, mockHTTP.LastSentRequest(), tc.want)
			})
		}
	})

	t.Run("headers_unparseable_errors", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		result := CallMCPTool(t, mcpClient, "request_send", map[string]interface{}{
			"url":     "https://example.com/test",
			"headers": "no-colon-here",
		})
		assert.True(t, result.IsError)
		msg := ExtractMCPText(t, result)
		assert.Contains(t, msg, "headers was provided as a string but could not be parsed")
		assert.Contains(t, msg, `an object {"Name":"Value"}`)
	})

	t.Run("compresses_with_encoding", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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

	_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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

	// H2 requests carry the body in DATA frames, so replay never adds content-length,
	// whether the body is sent verbatim or mutated.
	for _, tc := range []struct {
		name     string
		setJSON  map[string]interface{}
		wantBody string
	}{
		{name: "h2_unframed_body_replayed", wantBody: `{"a":1}`},
		{name: "h2_body_mod_adds_no_cl", setJSON: map[string]interface{}{"a": 2}, wantBody: `{"a":2}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h2FlowID := mockHTTP.AddProxyEntryProtocol(
				"POST /api HTTP/1.1\r\nhost: h2.test\r\ncontent-type: application/json\r\n\r\n{\"a\":1}",
				"HTTP/2 200 OK\r\n\r\nok",
				types.ProtocolH2,
			)
			mockHTTP.SetSendResult("HTTP/2 200 OK\r\n", "ok")

			args := map[string]interface{}{"flow_id": h2FlowID}
			if tc.setJSON != nil {
				args["set_json"] = tc.setJSON
			}
			CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", args)

			sent := mockHTTP.LastSentRequest()
			assert.Contains(t, sent, tc.wantBody)
			assert.NotContains(t, strings.ToLower(sent), "content-length")
		})
	}

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
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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

	t.Run("crawl_flow_bytes_preserved", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, mockCrawler := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		createResp := CallMCPToolJSONOK[protocol.CrawlCreateResponse](t, mcpClient, "crawl_create", map[string]interface{}{
			"seed_urls": "https://crawl.test",
		})

		chunkedReq := "POST /submit HTTP/1.1\r\n" +
			"Host: crawl.test\r\n" +
			"User-Agent: colly\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"5\r\nhello\r\n0\r\n\r\n"
		// spare capacity mirrors the crawler's bytes.Buffer dumps
		request := append(make([]byte, 0, len(chunkedReq)+256), chunkedReq...)

		crawlFlowID := "crawl-flow-chunked"
		require.NoError(t, mockCrawler.AddFlow(createResp.SessionID, store.CrawlFlow{
			ID:         crawlFlowID,
			SessionID:  createResp.SessionID,
			URL:        "https://crawl.test/submit",
			Host:       "crawl.test",
			Path:       "/submit",
			Method:     "POST",
			StatusCode: 200,
			Request:    request,
			Response:   []byte("HTTP/1.1 200 OK\r\n\r\ncrawled"),
		}))
		mockHTTP.SetSendResult("HTTP/1.1 200 OK\r\n", "ok")

		CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": crawlFlowID,
			"body":    "a much longer replacement body",
			"force":   true,
		})
		assert.Contains(t, mockHTTP.LastSentRequest(), "a much longer replacement body")

		flow, err := mockCrawler.GetFlow(t.Context(), crawlFlowID)
		require.NoError(t, err)
		assert.Equal(t, chunkedReq, string(flow.Request))
	})
}

func TestExecuteSend_DomainScoping(t *testing.T) {
	t.Parallel()

	t.Run("replay_send_rejected", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, &config.Config{
			AllowedDomains: []string{"allowed.test"},
		}, protocol.WorkflowModeNone)

		flowID := mockHTTP.AddProxyEntry(
			"GET /page HTTP/1.1\r\nHost: blocked.test\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)

		result := CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "domain rejected")
	})

	t.Run("replay_send_force_still_rejected", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, &config.Config{
			AllowedDomains: []string{"allowed.test"},
		}, protocol.WorkflowModeNone)

		flowID := mockHTTP.AddProxyEntry(
			"GET /page HTTP/1.1\r\nHost: blocked.test\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)

		result := CallMCPTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flowID,
			"force":   true,
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "domain rejected")
	})

	t.Run("request_send_rejected", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, &config.Config{
			AllowedDomains: []string{"allowed.test"},
		}, protocol.WorkflowModeNone)

		result := CallMCPTool(t, mcpClient, "request_send", map[string]interface{}{
			"url": "https://blocked.test/api",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "domain rejected")
	})

	t.Run("request_send_excluded_subdomain", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, &config.Config{
			ExcludeDomains: []string{"internal.corp"},
		}, protocol.WorkflowModeNone)

		result := CallMCPTool(t, mcpClient, "request_send", map[string]interface{}{
			"url": "https://db.internal.corp/admin",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "domain rejected")
	})

	t.Run("allowed_domain_succeeds", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, &config.Config{
			AllowedDomains: []string{"allowed.test"},
		}, protocol.WorkflowModeNone)

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

func argRequest(args map[string]interface{}) mcp.CallToolRequest {
	return mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: args}}
}

func TestGetJSONArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args map[string]interface{}
		want map[string]interface{}
	}{
		{
			name: "object",
			args: map[string]interface{}{"set_json": map[string]interface{}{"user.id": float64(5)}},
			want: map[string]interface{}{"user.id": float64(5)},
		},
		{
			name: "string_encoded_object",
			args: map[string]interface{}{"set_json": `{"user.id": 5}`},
			want: map[string]interface{}{"user.id": float64(5)},
		},
		{
			name: "garbage_string",
			args: map[string]interface{}{"set_json": "not json"},
			want: nil,
		},
		{
			name: "missing",
			args: map[string]interface{}{},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, getJSONArg(argRequest(tt.args)))
		})
	}
}

func TestGetFormArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args map[string]interface{}
		want map[string]string
	}{
		{
			name: "object",
			args: map[string]interface{}{"set_form": map[string]interface{}{"a": "1"}},
			want: map[string]string{"a": "1"},
		},
		{
			name: "string_encoded_object",
			args: map[string]interface{}{"set_form": `{"a": "1", "b": 2}`},
			want: map[string]string{"a": "1", "b": "2"},
		},
		{
			name: "garbage_string",
			args: map[string]interface{}{"set_form": "not json"},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, getFormArg(argRequest(tt.args)))
		})
	}
}

func TestRebuildReplayTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		host   string
		scheme string
		port   int
		want   string
	}{
		{"plain_default_port", "example.com", schemeHTTPS, 443, "https://example.com"},
		{"plain_custom_port", "example.com:8080", schemeHTTP, 8080, "http://example.com:8080"},
		{"ipv6_bare_default_port", "[::1]", schemeHTTP, 80, "http://[::1]"},
		{"ipv6_with_port", "[::1]:8443", schemeHTTPS, 8443, "https://[::1]:8443"},
		{"ipv6_bare_custom_port", "[fe80::1]", schemeHTTPS, 8443, "https://[fe80::1]:8443"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rebuildReplayTarget(tt.host, tt.scheme, tt.port))
		})
	}
}

func TestGetStringMapArg(t *testing.T) {
	t.Parallel()

	t.Run("missing_key", func(t *testing.T) {
		assert.Nil(t, getStringMapArg(argRequest(map[string]interface{}{}), "headers", ":"))
	})

	t.Run("nil_value", func(t *testing.T) {
		assert.Nil(t, getStringMapArg(argRequest(map[string]interface{}{"headers": nil}), "headers", ":"))
	})

	t.Run("bare_string_no_sep", func(t *testing.T) {
		assert.Nil(t, getStringMapArg(argRequest(map[string]interface{}{"headers": "oops"}), "headers", ":"))
	})

	t.Run("string_encoded_object", func(t *testing.T) {
		got := getStringMapArg(argRequest(map[string]interface{}{
			"headers": `{"X-Test": "v", "X-Num": 2}`,
		}), "headers", ":")

		assert.Equal(t, map[string]string{"X-Test": "v", "X-Num": "2"}, got)
	})

	t.Run("coerce_scalars", func(t *testing.T) {
		got := getStringMapArg(argRequest(map[string]interface{}{"headers": map[string]interface{}{
			"str":    "v",
			"num":    float64(0),
			"flag":   true,
			"null":   nil,
			"nested": map[string]interface{}{"a": "b"},
			"list":   []interface{}{"a"},
		}}), "headers", ":")

		assert.Equal(t, map[string]string{
			"str":  "v",
			"num":  "0",
			"flag": "true",
			"null": "",
		}, got)
	})

	t.Run("object_value_not_trimmed", func(t *testing.T) {
		got := getStringMapArg(argRequest(map[string]interface{}{
			"headers": map[string]interface{}{"X-Test": "  spaced  "},
		}), "headers", ":")

		assert.Equal(t, map[string]string{"X-Test": "  spaced  "}, got)
	})

	t.Run("array_of_kv_strings", func(t *testing.T) {
		got := getStringMapArg(argRequest(map[string]interface{}{
			"headers": []interface{}{"X-Test: v", "Content-Type: text/html"},
		}), "headers", ":")

		assert.Equal(t, map[string]string{"X-Test": "v", "Content-Type": "text/html"}, got)
	})

	t.Run("single_kv_string", func(t *testing.T) {
		got := getStringMapArg(argRequest(map[string]interface{}{
			"headers": "X-Test: v",
		}), "headers", ":")

		assert.Equal(t, map[string]string{"X-Test": "v"}, got)
	})

	t.Run("form_separator", func(t *testing.T) {
		got := getStringMapArg(argRequest(map[string]interface{}{
			"set_form": []interface{}{"grant_type=client_credentials"},
		}), "set_form", "=")

		assert.Equal(t, map[string]string{"grant_type": "client_credentials"}, got)
	})

	t.Run("form_value_keeps_leading_space", func(t *testing.T) {
		got := getStringMapArg(argRequest(map[string]interface{}{
			"set_form": []interface{}{"scope= openid profile"},
		}), "set_form", "=")

		assert.Equal(t, map[string]string{"scope": " openid profile"}, got)
	})

	t.Run("kv_value_keeps_inner_whitespace", func(t *testing.T) {
		got := getStringMapArg(argRequest(map[string]interface{}{
			"headers": []interface{}{"X-Test:  v "},
		}), "headers", ":")

		assert.Equal(t, map[string]string{"X-Test": " v "}, got)
	})
}

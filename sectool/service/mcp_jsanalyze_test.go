package service

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

func TestHandleJSAnalyze(t *testing.T) {
	t.Parallel()

	t.Run("javascript_bundle_full", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		// A prior proxy flow that the JS bundle's URL should match against.
		priorFlowID := mockHTTP.AddProxyEntry(
			"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[]",
			"",
		)

		jsBody := `
fetch('/api/users', {method: 'POST'});
axios.get('/api/items');
new WebSocket('wss://example.com/ws');
window.location.href = '/login';
var key = 'AKIAIOSFODNN7EXAMPLE';
//# sourceMappingURL=app.js.map
`
		bundleFlowID := mockHTTP.AddProxyEntry(
			"GET /app.js HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"+jsBody,
			"",
		)

		resp := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_analyze",
			map[string]interface{}{"flow_id": bundleFlowID})

		assert.Equal(t, "javascript", resp.Source)

		endpointURLs := make(map[string]protocol.ExtractedEndpoint, len(resp.Endpoints))
		for _, e := range resp.Endpoints {
			endpointURLs[e.URL] = e
		}
		require.Contains(t, endpointURLs, "/api/users")
		assert.Equal(t, "POST", endpointURLs["/api/users"].Method)
		assert.Equal(t, "fetch", endpointURLs["/api/users"].Library)
		assert.Equal(t, priorFlowID, endpointURLs["/api/users"].LastFlow)

		require.Contains(t, endpointURLs, "/api/items")
		assert.Empty(t, endpointURLs["/api/items"].LastFlow)

		require.Contains(t, endpointURLs, "wss://example.com/ws")
		assert.Equal(t, "websocket", endpointURLs["wss://example.com/ws"].Library)

		assert.Contains(t, resp.SourceMaps, "app.js.map")

		require.Len(t, resp.Secrets, 1)
		assert.Equal(t, "aws_access_key", resp.Secrets[0].Kind)
		assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", resp.Secrets[0].Value)
	})

	t.Run("html_inline", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		html := `<html><head>
<script src="/static/bundle.js"></script>
<script>fetch('/api/inline');</script>
</head></html>`
		flowID := mockHTTP.AddProxyEntry(
			"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"+html,
			"",
		)

		resp := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_analyze",
			map[string]interface{}{"flow_id": flowID})

		assert.Equal(t, "html-inline", resp.Source)
		assert.Equal(t, []string{"/static/bundle.js"}, resp.ExternalScripts)

		assert.True(t, slices.ContainsFunc(resp.Endpoints, func(e protocol.ExtractedEndpoint) bool {
			return e.URL == "/api/inline"
		}))
	})

	t.Run("last_flow_query_fallback", func(t *testing.T) {
		cases := []struct {
			name        string
			historyPath string
			jsFetchPath string
		}{
			{"js_bare_history_query", "/api/things?id=1", "/api/things"},
			{"js_query_history_bare", "/api/things", "/api/things?x=1"},
			{"exact_match_wins", "/api/things?id=1", "/api/things?id=1"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

				historyFlowID := mockHTTP.AddProxyEntry(
					"GET "+tc.historyPath+" HTTP/1.1\r\nHost: example.com\r\n\r\n",
					"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[]",
					"",
				)

				jsBody := "fetch('" + tc.jsFetchPath + "');"
				bundleFlowID := mockHTTP.AddProxyEntry(
					"GET /app.js HTTP/1.1\r\nHost: example.com\r\n\r\n",
					"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\n"+jsBody,
					"",
				)

				resp := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_analyze",
					map[string]interface{}{"flow_id": bundleFlowID})

				idx := slices.IndexFunc(resp.Endpoints, func(e protocol.ExtractedEndpoint) bool {
					return e.URL == tc.jsFetchPath
				})
				require.GreaterOrEqual(t, idx, 0)
				assert.Equal(t, historyFlowID, resp.Endpoints[idx].LastFlow)
			})
		}
	})

	t.Run("cross_host_not_annotated", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		// /api/things lives on a different host than the bundle.
		mockHTTP.AddProxyEntry(
			"GET /api/things HTTP/1.1\r\nHost: other.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[]",
			"",
		)
		bundleFlowID := mockHTTP.AddProxyEntry(
			"GET /app.js HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nfetch('/api/things');",
			"",
		)

		resp := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_analyze",
			map[string]interface{}{"flow_id": bundleFlowID})

		idx := slices.IndexFunc(resp.Endpoints, func(e protocol.ExtractedEndpoint) bool {
			return e.URL == "/api/things"
		})
		require.GreaterOrEqual(t, idx, 0)
		assert.Empty(t, resp.Endpoints[idx].LastFlow)
	})

	t.Run("same_host_path_relative_matches", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		historyFlowID := mockHTTP.AddProxyEntry(
			"GET /api/things HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[]",
			"",
		)
		bundleFlowID := mockHTTP.AddProxyEntry(
			"GET /app.js HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nfetch('/api/things');",
			"",
		)

		resp := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_analyze",
			map[string]interface{}{"flow_id": bundleFlowID})

		idx := slices.IndexFunc(resp.Endpoints, func(e protocol.ExtractedEndpoint) bool {
			return e.URL == "/api/things"
		})
		require.GreaterOrEqual(t, idx, 0)
		assert.Equal(t, historyFlowID, resp.Endpoints[idx].LastFlow)
	})

	t.Run("absolute_url_matches_own_host", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		apiFlowID := mockHTTP.AddProxyEntry(
			"GET /v1/users HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n[]",
			"",
		)
		bundleFlowID := mockHTTP.AddProxyEntry(
			"GET /app.js HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nfetch('https://api.example.com/v1/users');",
			"",
		)

		resp := CallMCPToolJSONOK[protocol.JSAnalyzeResponse](t, mcpClient, "js_analyze",
			map[string]interface{}{"flow_id": bundleFlowID})

		idx := slices.IndexFunc(resp.Endpoints, func(e protocol.ExtractedEndpoint) bool {
			return e.URL == "https://api.example.com/v1/users"
		})
		require.GreaterOrEqual(t, idx, 0)
		assert.Equal(t, apiFlowID, resp.Endpoints[idx].LastFlow)
	})

	t.Run("rejects_non_js", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil)

		flowID := mockHTTP.AddProxyEntry(
			"GET /data.json HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"x\":1}",
			"",
		)

		result := CallMCPTool(t, mcpClient, "js_analyze",
			map[string]interface{}{"flow_id": flowID})
		require.True(t, result.IsError)
	})

	t.Run("unknown_flow", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil)

		result := CallMCPTool(t, mcpClient, "js_analyze",
			map[string]interface{}{"flow_id": "no-such-flow"})
		require.True(t, result.IsError)
	})
}

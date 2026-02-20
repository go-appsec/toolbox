package service

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sectool/protocol"
)

func TestMCP_ProxyPoll(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

	// Summary filter entries
	mockMCP.AddProxyEntry(
		"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"users\":[]}",
		"",
	)
	mockMCP.AddProxyEntry(
		"POST /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n{\"name\":\"test\"}",
		"HTTP/1.1 201 Created\r\n\r\n",
		"",
	)
	mockMCP.AddProxyEntry(
		"GET /other HTTP/1.1\r\nHost: other.com\r\n\r\n",
		"HTTP/1.1 404 Not Found\r\n\r\n",
		"",
	)

	// Flow search entries
	mockMCP.AddProxyEntry(
		"GET /api/data HTTP/1.1\r\nHost: test.com\r\nX-Custom: searchme\r\n\r\n",
		"HTTP/1.1 200 OK\r\n\r\nresponse body with findme",
		"",
	)
	mockMCP.AddProxyEntry(
		"POST /api/submit HTTP/1.1\r\nHost: test.com\r\nContent-Type: application/json\r\n\r\n{\"search\":\"bodysearch\"}",
		"HTTP/1.1 201 Created\r\n\r\n",
		"",
	)

	// Pagination entries
	for i := 0; i < 5; i++ {
		mockMCP.AddProxyEntry(
			"GET /page HTTP/1.1\r\nHost: limit-test.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\n",
			"",
		)
	}

	// Regex fallback entry
	mockMCP.AddProxyEntry(
		"GET / HTTP/1.1\r\nHost: fallback.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\n\r\nsome [invalid regex",
		"",
	)

	t.Run("summary_filters", func(t *testing.T) {
		cases := []struct {
			name          string
			args          map[string]interface{}
			minAggregates int
			wantHost      string
			wantPath      string
			wantMeth      string
			excludeHost   string
			excludePath   string
		}{
			{
				name:          "unfiltered",
				minAggregates: 2,
			},
			{
				name:     "host_filter",
				args:     map[string]interface{}{"host": "example.com"},
				wantHost: "example.com",
			},
			{
				name:     "path_filter",
				args:     map[string]interface{}{"path": "/api/*"},
				wantPath: "/api/",
			},
			{
				name:     "method_filter",
				args:     map[string]interface{}{"method": "GET"},
				wantMeth: "GET",
			},
			{
				name:        "exclude_host",
				args:        map[string]interface{}{"exclude_host": "other.com"},
				excludeHost: "other.com",
			},
			{
				name:        "exclude_path",
				args:        map[string]interface{}{"exclude_path": "/other*"},
				excludePath: "/other",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				resp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", tc.args)
				if tc.minAggregates > 0 {
					assert.GreaterOrEqual(t, len(resp.Aggregates), tc.minAggregates)
				} else {
					require.NotEmpty(t, resp.Aggregates)
				}
				for _, agg := range resp.Aggregates {
					if tc.wantHost != "" {
						assert.Equal(t, tc.wantHost, agg.Host)
					}
					if tc.wantPath != "" {
						assert.Contains(t, agg.Path, tc.wantPath)
					}
					if tc.wantMeth != "" {
						assert.Equal(t, tc.wantMeth, agg.Method)
					}
					if tc.excludeHost != "" {
						assert.NotEqual(t, tc.excludeHost, agg.Host)
					}
					if tc.excludePath != "" {
						assert.NotEqual(t, tc.excludePath, agg.Path)
					}
				}
			})
		}
	})

	t.Run("flow_filters", func(t *testing.T) {
		cases := []struct {
			name      string
			args      map[string]interface{}
			wantMeth  string
			statusEq  int
			statusMin int
			statusMax int
		}{
			{
				name:     "method_filter",
				args:     map[string]interface{}{"output_mode": "flows", "method": "GET"},
				wantMeth: "GET",
			},
			{
				name:     "status_exact",
				args:     map[string]interface{}{"output_mode": "flows", "status": "201"},
				statusEq: 201,
			},
			{
				name:      "status_range",
				args:      map[string]interface{}{"output_mode": "flows", "status": "2XX"},
				statusMin: 200,
				statusMax: 300,
			},
			{
				name: "search_header",
				args: map[string]interface{}{"output_mode": "flows", "search_header": "searchme"},
			},
			{
				name: "search_body",
				args: map[string]interface{}{"output_mode": "flows", "search_body": "bodysearch"},
			},
			{
				name: "search_header_regex",
				args: map[string]interface{}{"output_mode": "flows", "search_header": "X-Custom:\\s+search.*"},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				resp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", tc.args)
				require.NotEmpty(t, resp.Flows)
				for _, flow := range resp.Flows {
					if tc.wantMeth != "" {
						assert.Equal(t, tc.wantMeth, flow.Method)
					}
					if tc.statusEq != 0 {
						assert.Equal(t, tc.statusEq, flow.Status)
					}
					if tc.statusMin != 0 || tc.statusMax != 0 {
						assert.GreaterOrEqual(t, flow.Status, tc.statusMin)
						assert.Less(t, flow.Status, tc.statusMax)
					}
				}
			})
		}
	})

	t.Run("pagination", func(t *testing.T) {
		t.Run("limit_only", func(t *testing.T) {
			resp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
				"output_mode": "flows",
				"host":        "limit-test.com",
				"limit":       2,
			})
			assert.LessOrEqual(t, len(resp.Flows), 2)
		})

		t.Run("with_offset", func(t *testing.T) {
			allResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
				"output_mode": "flows",
				"host":        "limit-test.com",
			})
			totalFlows := len(allResp.Flows)

			resp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
				"output_mode": "flows",
				"host":        "limit-test.com",
				"offset":      2,
			})
			assert.Len(t, resp.Flows, totalFlows-2)
		})

		t.Run("since_flow_id", func(t *testing.T) {
			listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
				"output_mode": "flows",
				"host":        "limit-test.com",
				"limit":       1,
			})
			require.NotEmpty(t, listResp.Flows)
			sinceID := listResp.Flows[0].FlowID

			resp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
				"output_mode": "flows",
				"host":        "limit-test.com",
				"since":       sinceID,
			})
			for _, flow := range resp.Flows {
				assert.NotEqual(t, sinceID, flow.FlowID)
			}
		})

		t.Run("since_last", func(t *testing.T) {
			_ = CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
				"output_mode": "flows",
				"host":        "limit-test.com",
			})

			resp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
				"output_mode": "flows",
				"host":        "limit-test.com",
				"since":       "last",
			})
			assert.Empty(t, resp.Flows)
		})

		t.Run("since_replay_flow_id", func(t *testing.T) {
			_, mc, mock, _, _ := setupMockMCPServer(t)

			mock.AddProxyEntry(
				"GET /api/1 HTTP/1.1\r\nHost: test.com\r\n\r\n",
				"HTTP/1.1 200 OK\r\n\r\nresponse1", "",
			)
			mock.AddProxyEntry(
				"GET /api/2 HTTP/1.1\r\nHost: test.com\r\n\r\n",
				"HTTP/1.1 200 OK\r\n\r\nresponse2", "",
			)
			mock.SetSendResponse(
				"HttpRequestResponse{httpRequest=GET /api/1 HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\n\r\nreplayed}",
			)

			listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mc, "proxy_poll", map[string]interface{}{
				"output_mode": "flows",
				"host":        "test.com",
			})
			require.Len(t, listResp.Flows, 2)

			sendResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mc, "replay_send", map[string]interface{}{
				"flow_id": listResp.Flows[0].FlowID,
			})

			mock.AddProxyEntry(
				"GET /api/3 HTTP/1.1\r\nHost: test.com\r\n\r\n",
				"HTTP/1.1 200 OK\r\n\r\nresponse3", "",
			)

			sinceResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mc, "proxy_poll", map[string]interface{}{
				"output_mode": "flows",
				"host":        "test.com",
				"since":       sendResp.FlowID,
			})
			require.NotEmpty(t, sinceResp.Flows)

			var foundNewProxy bool
			for _, flow := range sinceResp.Flows {
				if flow.Path == "/api/3" {
					foundNewProxy = true
					break
				}
			}
			assert.True(t, foundNewProxy)
		})

		t.Run("since_multiple_replays", func(t *testing.T) {
			_, mc, mock, _, _ := setupMockMCPServer(t)

			mock.AddProxyEntry(
				"GET /api/test HTTP/1.1\r\nHost: test.com\r\n\r\n",
				"HTTP/1.1 200 OK\r\n\r\noriginal", "",
			)
			mock.SetSendResponse(
				"HttpRequestResponse{httpRequest=GET /api/test HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\n\r\nreplayed}",
			)

			listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mc, "proxy_poll", map[string]interface{}{
				"output_mode": "flows",
				"host":        "test.com",
			})
			require.NotEmpty(t, listResp.Flows)
			flowID := listResp.Flows[0].FlowID

			replay1 := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mc, "replay_send", map[string]interface{}{
				"flow_id": flowID,
			})
			replay2 := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mc, "replay_send", map[string]interface{}{
				"flow_id": flowID,
			})

			sinceResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mc, "proxy_poll", map[string]interface{}{
				"output_mode": "flows",
				"source":      "replay",
				"since":       replay1.FlowID,
			})
			require.NotEmpty(t, sinceResp.Flows)

			var foundReplay2 bool
			for _, flow := range sinceResp.Flows {
				if flow.FlowID == replay2.FlowID {
					foundReplay2 = true
				}
				assert.NotEqual(t, replay1.FlowID, flow.FlowID)
			}
			assert.True(t, foundReplay2)
		})
	})

	t.Run("flows_require_filter", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
		})
		assert.True(t, result.IsError)
	})

	t.Run("search_regex_fallback", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"search_body": "[invalid",
		})
		assert.NotEmpty(t, resp.Note)
		assert.Contains(t, resp.Note, "treated as literal")
		require.NotEmpty(t, resp.Flows)
	})
}

func TestMCP_ProxyPollDomainScoping(t *testing.T) {
	t.Parallel()

	t.Run("allowed_domains_filters", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServerWithConfig(t, &config.Config{
			AllowedDomains: []string{"example.com"},
		})
		mockMCP.AddProxyEntry(
			"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\n", "",
		)
		mockMCP.AddProxyEntry(
			"GET /other HTTP/1.1\r\nHost: other.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\n", "",
		)

		// Summary mode: only example.com
		summary := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", nil)
		require.NotEmpty(t, summary.Aggregates)
		for _, agg := range summary.Aggregates {
			assert.Equal(t, "example.com", agg.Host)
		}

		// Flows mode: only example.com
		flows := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"limit":       10,
		})
		require.NotEmpty(t, flows.Flows)
		for _, f := range flows.Flows {
			assert.Equal(t, "example.com", f.Host)
		}
	})

	t.Run("exclude_domains_filters", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServerWithConfig(t, &config.Config{
			ExcludeDomains: []string{"noise.com"},
		})
		mockMCP.AddProxyEntry(
			"GET /target HTTP/1.1\r\nHost: target.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\n", "",
		)
		mockMCP.AddProxyEntry(
			"GET /noise HTTP/1.1\r\nHost: noise.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\n", "",
		)

		summary := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", nil)
		require.NotEmpty(t, summary.Aggregates)
		for _, agg := range summary.Aggregates {
			assert.NotEqual(t, "noise.com", agg.Host)
		}
	})

	t.Run("no_scoping_passes_all", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)
		mockMCP.AddProxyEntry(
			"GET /a HTTP/1.1\r\nHost: one.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\n", "",
		)
		mockMCP.AddProxyEntry(
			"GET /b HTTP/1.1\r\nHost: two.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\n", "",
		)

		summary := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", nil)
		assert.Len(t, summary.Aggregates, 2)
	})

	t.Run("replay_entries_filtered", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServerWithConfig(t, &config.Config{
			AllowedDomains: []string{"allowed.com"},
		})

		// Add proxy entries for both domains so replay_send can reference one
		mockMCP.AddProxyEntry(
			"GET /ok HTTP/1.1\r\nHost: allowed.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\n", "",
		)
		mockMCP.AddProxyEntry(
			"GET /nope HTTP/1.1\r\nHost: blocked.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\n", "",
		)

		// Get flow_id for the allowed entry, then replay it
		flows := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"limit":       10,
		})
		require.NotEmpty(t, flows.Flows)
		allowedFlowID := flows.Flows[0].FlowID

		// Replay the allowed entry — creates a replay entry for allowed.com
		replayResp := CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": allowedFlowID,
		})
		require.NotEmpty(t, replayResp.FlowID)

		// Poll again: should only see allowed.com entries (proxy + replay)
		all := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"limit":       50,
		})
		for _, f := range all.Flows {
			assert.Equal(t, "allowed.com", f.Host)
		}
	})
}

func TestMCP_FlowGet(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

	mockMCP.AddProxyEntry(
		"GET /scoped HTTP/1.1\r\nHost: scope.com\r\n\r\nreq body here",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nresp body here",
		"",
	)

	listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
		"output_mode": "flows",
		"host":        "scope.com",
	})
	require.NotEmpty(t, listResp.Flows)
	flowID := listResp.Flows[0].FlowID

	t.Run("basic", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.FlowGetResponse](t, mcpClient, "flow_get", map[string]interface{}{
			"flow_id": flowID,
		})
		assert.Equal(t, flowID, resp.FlowID)
		assert.Equal(t, "GET", resp.Method)
		assert.NotEmpty(t, resp.ReqHeaders)
		assert.NotEmpty(t, resp.RespHeaders)
	})

	t.Run("full_body_base64", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.FlowGetResponse](t, mcpClient, "flow_get", map[string]interface{}{
			"flow_id":   flowID,
			"full_body": true,
		})
		decodedBody, err := base64.StdEncoding.DecodeString(resp.RespBody)
		require.NoError(t, err)
		assert.Equal(t, "resp body here", string(decodedBody))
	})

	t.Run("scope_response_body", func(t *testing.T) {
		var raw map[string]interface{}
		text := CallMCPToolTextOK(t, mcpClient, "flow_get", map[string]interface{}{
			"flow_id": flowID,
			"scope":   "response_body",
		})
		require.NoError(t, json.Unmarshal([]byte(text), &raw))
		assert.Contains(t, raw, "response_body")
		assert.NotContains(t, raw, "request_headers")
		assert.NotContains(t, raw, "request_body")
		assert.NotContains(t, raw, "response_headers")
		// Metadata always present
		assert.Contains(t, raw, "flow_id")
		assert.Contains(t, raw, "method")
	})

	t.Run("scope_request_headers", func(t *testing.T) {
		var raw map[string]interface{}
		text := CallMCPToolTextOK(t, mcpClient, "flow_get", map[string]interface{}{
			"flow_id": flowID,
			"scope":   "request_headers",
		})
		require.NoError(t, json.Unmarshal([]byte(text), &raw))
		assert.Contains(t, raw, "request_headers")
		assert.Contains(t, raw, "request_headers_parsed")
		assert.NotContains(t, raw, "response_body")
	})

	t.Run("pattern_match", func(t *testing.T) {
		var raw map[string]interface{}
		text := CallMCPToolTextOK(t, mcpClient, "flow_get", map[string]interface{}{
			"flow_id": flowID,
			"scope":   "response_body",
			"pattern": "resp.*here",
		})
		require.NoError(t, json.Unmarshal([]byte(text), &raw))
		assert.Contains(t, raw, "response_body")
		respBody, ok := raw["response_body"].(string)
		require.True(t, ok)
		assert.Contains(t, respBody, "resp body here")
		// Pattern mode excludes parsed fields
		assert.NotContains(t, raw, "response_headers_parsed")
	})

	t.Run("pattern_no_match", func(t *testing.T) {
		var raw map[string]interface{}
		text := CallMCPToolTextOK(t, mcpClient, "flow_get", map[string]interface{}{
			"flow_id": flowID,
			"scope":   "response_body",
			"pattern": "NOMATCH_xyz",
		})
		require.NoError(t, json.Unmarshal([]byte(text), &raw))
		assert.NotContains(t, raw, "response_body")
	})

	t.Run("invalid_scope", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "flow_get", map[string]interface{}{
			"flow_id": flowID,
			"scope":   "bogus",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "invalid scope")
	})

	t.Run("missing_flow_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "flow_get", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "flow_id is required")
	})

	t.Run("invalid_flow_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "flow_get", map[string]interface{}{
			"flow_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "not found")
	})
}

// Note: Gzip decompression for full_body is tested via TestMCP_FlowGetDecompressesGzipBody
// since the Burp mock server's JSON encoding corrupts binary data.
// The decompression logic is also covered by TestDecompressForDisplay in httputil_test.go.

func TestMCP_ProxyRules(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t)

	t.Run("crud", func(t *testing.T) {
		var ruleID string

		t.Run("add_rule", func(t *testing.T) {
			text := CallMCPToolTextOK(t, mcpClient, "proxy_rule_add", map[string]interface{}{
				"type":    RuleTypeRequestHeader,
				"label":   "mock-test-rule",
				"replace": "X-Mock-Test: value",
			})
			var rule protocol.RuleEntry
			require.NoError(t, json.Unmarshal([]byte(text), &rule))
			assert.NotEmpty(t, rule.RuleID)
			assert.Equal(t, "mock-test-rule", rule.Label)
			ruleID = rule.RuleID
		})

		t.Run("add_with_regex", func(t *testing.T) {
			rule := CallMCPToolJSONOK[protocol.RuleEntry](t, mcpClient, "proxy_rule_add", map[string]interface{}{
				"type":     RuleTypeRequestBody,
				"label":    "regex-rule",
				"match":    "password=.*",
				"replace":  "password=REDACTED",
				"is_regex": true,
			})
			assert.NotEmpty(t, rule.RuleID)
			assert.Equal(t, "regex-rule", rule.Label)
		})

		t.Run("list_rules", func(t *testing.T) {
			resp := CallMCPToolJSONOK[protocol.RuleListResponse](t, mcpClient, "proxy_rule_list", nil)

			var found bool
			for _, r := range resp.Rules {
				if r.RuleID == ruleID {
					found = true
					break
				}
			}
			assert.True(t, found)
		})

		t.Run("list_with_type_filter", func(t *testing.T) {
			for _, tf := range []string{"http", "websocket"} {
				t.Run(tf, func(t *testing.T) {
					_ = CallMCPToolJSONOK[protocol.RuleListResponse](t, mcpClient, "proxy_rule_list", map[string]interface{}{
						"type_filter": tf,
					})
				})
			}
		})

		t.Run("list_with_limit", func(t *testing.T) {
			resp := CallMCPToolJSONOK[protocol.RuleListResponse](t, mcpClient, "proxy_rule_list", map[string]interface{}{
				"limit": 1,
			})
			assert.LessOrEqual(t, len(resp.Rules), 1)
		})

		t.Run("delete_rule", func(t *testing.T) {
			_ = CallMCPToolTextOK(t, mcpClient, "proxy_rule_delete", map[string]interface{}{
				"rule_id": ruleID,
			})
			resp := CallMCPToolJSONOK[protocol.RuleListResponse](t, mcpClient, "proxy_rule_list", nil)

			for _, r := range resp.Rules {
				assert.NotEqual(t, ruleID, r.RuleID)
			}
		})
	})

	t.Run("regex_escaping", func(t *testing.T) {
		cases := []struct {
			name      string
			match     string
			isRegex   bool
			wantMatch string
			rawAssert bool // verify JSON-escaped backslashes in list output
		}{
			{
				name:      "double_escape_corrected",
				match:     `Accept: \\*/\\*`,
				isRegex:   true,
				wantMatch: `Accept: \*/\*`,
			},
			{
				name:      "single_escape_preserved",
				match:     `Accept: \*/\*`,
				isRegex:   true,
				wantMatch: `Accept: \*/\*`,
				rawAssert: true,
			},
			{
				name:      "non_regex_preserved",
				match:     `Accept: \\*/\\*`,
				wantMatch: `Accept: \\*/\\*`,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				args := map[string]interface{}{
					"type":    RuleTypeRequestHeader,
					"label":   "escape-" + tc.name,
					"match":   tc.match,
					"replace": "Accept: application/json",
				}
				if tc.isRegex {
					args["is_regex"] = true
				}

				addResult := CallMCPToolJSONOK[protocol.RuleEntry](t, mcpClient, "proxy_rule_add", args)
				assert.Equal(t, tc.wantMatch, addResult.Match)

				if tc.rawAssert {
					rawText := CallMCPToolTextOK(t, mcpClient, "proxy_rule_list", nil)
					assert.Contains(t, rawText, `\\*/\\*`)
					assert.NotContains(t, rawText, `\\\\*/\\\\*`)
				}

				// Clean up
				_ = CallMCPToolTextOK(t, mcpClient, "proxy_rule_delete", map[string]interface{}{
					"rule_id": addResult.RuleID,
				})
			})
		}
	})

	t.Run("validation", func(t *testing.T) {
		t.Run("add_missing_type", func(t *testing.T) {
			result := CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
				"replace": "X-Test: value",
			})
			assert.True(t, result.IsError)
			assert.Contains(t, ExtractMCPText(t, result), "type is required")
		})

		t.Run("add_invalid_type", func(t *testing.T) {
			result := CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
				"type": "invalid_type",
			})
			assert.True(t, result.IsError)
			assert.Contains(t, ExtractMCPText(t, result), "invalid rule type")
		})

		t.Run("add_missing_match_replace", func(t *testing.T) {
			result := CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
				"type": RuleTypeRequestHeader,
			})
			assert.True(t, result.IsError)
			assert.Contains(t, ExtractMCPText(t, result), "match or replace is required")
		})

		t.Run("add_duplicate_label", func(t *testing.T) {
			result := CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
				"type":    RuleTypeRequestHeader,
				"label":   "unique-label",
				"replace": "X-Test: value",
			})
			require.False(t, result.IsError,
				"proxy_rule_add failed: %s", ExtractMCPText(t, result))

			result = CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
				"type":    RuleTypeRequestHeader,
				"label":   "unique-label",
				"replace": "X-Test: value2",
			})
			assert.True(t, result.IsError)
			text := ExtractMCPText(t, result)
			assert.Contains(t, text, "label already exists")
			assert.Contains(t, text, "delete")
		})

		t.Run("list_invalid_type_filter", func(t *testing.T) {
			result := CallMCPTool(t, mcpClient, "proxy_rule_list", map[string]interface{}{
				"type_filter": "invalid",
			})
			assert.True(t, result.IsError)
			assert.Contains(t, ExtractMCPText(t, result), "invalid type_filter")
		})

		t.Run("delete_missing_rule_id", func(t *testing.T) {
			result := CallMCPTool(t, mcpClient, "proxy_rule_delete", map[string]interface{}{})
			assert.True(t, result.IsError)
			assert.Contains(t, ExtractMCPText(t, result), "rule_id is required")
		})

		t.Run("delete_invalid_rule_id", func(t *testing.T) {
			result := CallMCPTool(t, mcpClient, "proxy_rule_delete", map[string]interface{}{
				"rule_id": "nonexistent",
			})
			assert.True(t, result.IsError)
			assert.Contains(t, ExtractMCPText(t, result), "not found")
		})
	})
}

func TestUnDoubleEscapeRegex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no_escapes", "Accept: text/html", "Accept: text/html"},
		{"single_escape_preserved", `Accept: \*/\*`, `Accept: \*/\*`},
		{"double_escape_collapsed", `Accept: \\*/\\*`, `Accept: \*/\*`},
		{"double_escape_dot", `Host: example\\.com`, `Host: example\.com`},
		{"double_escape_plus", `count: \\d\\+`, `count: \d\+`},
		{"shorthand_classes", `\\d{3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}`, `\d{3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`},
		{"word_whitespace", `\\w+\\s+\\b`, `\w+\s+\b`},
		{"literal_backslash_kept", `path: \\\\server`, `path: \\\\server`},
		{"mixed", `\\. and \. ok`, `\. and \. ok`},
		{"empty", "", ""},
		{"trailing_backslash", `test\\`, `test\\`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, unDoubleEscapeRegex(tt.in))
		})
	}
}

func TestMCP_CookieJar(t *testing.T) {
	t.Parallel()

	t.Run("overview_no_values", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		mockMCP.AddProxyEntry(
			"GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax\r\n\r\n",
			"",
		)

		// No filters: overview mode, no values
		resp := CallMCPToolJSONOK[protocol.CookieJarResponse](t, mcpClient, "cookie_jar", nil)
		require.Len(t, resp.Cookies, 1)
		c := resp.Cookies[0]
		assert.Equal(t, "sid", c.Name)
		assert.Empty(t, c.Value)
		assert.Nil(t, c.Decoded)
		assert.Equal(t, "example.com", c.Domain)
		assert.Equal(t, "/", c.Path)
		assert.True(t, c.Secure)
		assert.True(t, c.HttpOnly)
		assert.Equal(t, "Lax", c.SameSite)
		assert.NotEmpty(t, c.FlowID)
	})

	t.Run("detail_with_name", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		mockMCP.AddProxyEntry(
			"GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax\r\nSet-Cookie: csrf=xyz\r\nSet-Cookie: tracking=123\r\n\r\n",
			"",
		)

		// Name filter: only matching cookie returned with full detail
		resp := CallMCPToolJSONOK[protocol.CookieJarResponse](t, mcpClient, "cookie_jar", map[string]interface{}{
			"name": "sid",
		})
		require.Len(t, resp.Cookies, 1)
		c := resp.Cookies[0]
		assert.Equal(t, "sid", c.Name)
		assert.Equal(t, "abc123", c.Value)
		assert.Equal(t, "example.com", c.Domain)
		assert.Equal(t, "/", c.Path)
		assert.True(t, c.Secure)
		assert.True(t, c.HttpOnly)
		assert.Equal(t, "Lax", c.SameSite)
		assert.NotEmpty(t, c.FlowID)
	})

	t.Run("dedup_keeps_last", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		mockMCP.AddProxyEntry(
			"GET /page1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: token=old; Domain=example.com\r\n\r\n",
			"",
		)
		mockMCP.AddProxyEntry(
			"GET /page2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: token=new; Domain=example.com\r\n\r\n",
			"",
		)

		resp := CallMCPToolJSONOK[protocol.CookieJarResponse](t, mcpClient, "cookie_jar", map[string]interface{}{
			"name": "token",
		})
		require.Len(t, resp.Cookies, 1)
		assert.Equal(t, "new", resp.Cookies[0].Value)
	})

	t.Run("domain_filter", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		mockMCP.AddProxyEntry(
			"GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Domain=example.com\r\n\r\n",
			"",
		)
		mockMCP.AddProxyEntry(
			"GET / HTTP/1.1\r\nHost: sub.example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: c=3; Domain=sub.example.com\r\n\r\n",
			"",
		)
		mockMCP.AddProxyEntry(
			"GET / HTTP/1.1\r\nHost: other.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: b=2; Domain=other.com\r\n\r\n",
			"",
		)

		// "example.com" matches example.com and subdomains
		resp := CallMCPToolJSONOK[protocol.CookieJarResponse](t, mcpClient, "cookie_jar", map[string]interface{}{
			"domain": "example.com",
		})
		require.Len(t, resp.Cookies, 2)
		names := map[string]bool{resp.Cookies[0].Name: true, resp.Cookies[1].Name: true}
		assert.True(t, names["a"])
		assert.True(t, names["c"])
	})

	t.Run("replay_included", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		mockMCP.AddProxyEntry(
			"GET /api HTTP/1.1\r\nHost: test.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\nok",
			"",
		)
		mockMCP.SetSendResponse(
			"HttpRequestResponse{httpRequest=GET /api HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\nSet-Cookie: replay_cookie=yes\r\n\r\nok}",
		)

		// Get flow_id and replay it
		flows := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"limit":       1,
		})
		require.NotEmpty(t, flows.Flows)

		_ = CallMCPToolJSONOK[protocol.ReplaySendResponse](t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": flows.Flows[0].FlowID,
		})

		// Use name filter to get value in detail mode
		resp := CallMCPToolJSONOK[protocol.CookieJarResponse](t, mcpClient, "cookie_jar", map[string]interface{}{
			"name": "replay_cookie",
		})
		require.Len(t, resp.Cookies, 1)
		assert.Equal(t, "replay_cookie", resp.Cookies[0].Name)
		assert.Equal(t, "yes", resp.Cookies[0].Value)
	})

	t.Run("no_cookies", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		mockMCP.AddProxyEntry(
			"GET /plain HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello",
			"",
		)

		resp := CallMCPToolJSONOK[protocol.CookieJarResponse](t, mcpClient, "cookie_jar", nil)
		assert.Empty(t, resp.Cookies)
	})

	t.Run("domain_defaults_to_host", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		// Cookie without Domain attribute should default to request host
		mockMCP.AddProxyEntry(
			"GET / HTTP/1.1\r\nHost: mysite.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: name=val; Path=/\r\n\r\n",
			"",
		)

		resp := CallMCPToolJSONOK[protocol.CookieJarResponse](t, mcpClient, "cookie_jar", nil)
		require.Len(t, resp.Cookies, 1)
		assert.Equal(t, "mysite.com", resp.Cookies[0].Domain)
	})

	t.Run("config_domain_scoping", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServerWithConfig(t, &config.Config{
			AllowedDomains: []string{"allowed.com"},
		})

		mockMCP.AddProxyEntry(
			"GET / HTTP/1.1\r\nHost: allowed.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: ok=1\r\n\r\n",
			"",
		)
		mockMCP.AddProxyEntry(
			"GET / HTTP/1.1\r\nHost: blocked.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: nope=2\r\n\r\n",
			"",
		)

		resp := CallMCPToolJSONOK[protocol.CookieJarResponse](t, mcpClient, "cookie_jar", nil)
		require.Len(t, resp.Cookies, 1)
		assert.Equal(t, "ok", resp.Cookies[0].Name)
	})

	t.Run("multiple_cookies_one_response", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		mockMCP.AddProxyEntry(
			"GET / HTTP/1.1\r\nHost: multi.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2; Secure\r\nSet-Cookie: c=3; SameSite=Strict\r\n\r\n",
			"",
		)

		resp := CallMCPToolJSONOK[protocol.CookieJarResponse](t, mcpClient, "cookie_jar", nil)
		require.Len(t, resp.Cookies, 3)

		names := make(map[string]bool)
		for _, c := range resp.Cookies {
			names[c.Name] = true
		}
		assert.True(t, names["a"])
		assert.True(t, names["b"])
		assert.True(t, names["c"])
	})

	t.Run("name_and_domain_filter", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		mockMCP.AddProxyEntry(
			"GET / HTTP/1.1\r\nHost: a.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: sid=a1; Domain=a.com\r\n\r\n",
			"",
		)
		mockMCP.AddProxyEntry(
			"GET / HTTP/1.1\r\nHost: b.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: sid=b1; Domain=b.com\r\n\r\n",
			"",
		)

		resp := CallMCPToolJSONOK[protocol.CookieJarResponse](t, mcpClient, "cookie_jar", map[string]interface{}{
			"name":   "sid",
			"domain": "a.com",
		})
		require.Len(t, resp.Cookies, 1)
		assert.Equal(t, "a1", resp.Cookies[0].Value)
		assert.Equal(t, "a.com", resp.Cookies[0].Domain)
	})

	t.Run("jwt_auto_decode", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		jwtValue := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

		mockMCP.AddProxyEntry(
			"GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: token="+jwtValue+"; Path=/; HttpOnly\r\n\r\n",
			"",
		)

		// With name filter: detail mode returns value + decoded JWT
		resp := CallMCPToolJSONOK[protocol.CookieJarResponse](t, mcpClient, "cookie_jar", map[string]interface{}{
			"name": "token",
		})
		require.Len(t, resp.Cookies, 1)
		c := resp.Cookies[0]
		assert.Equal(t, "token", c.Name)
		assert.Equal(t, jwtValue, c.Value)
		require.NotNil(t, c.Decoded)
		assert.Equal(t, "HS256", c.Decoded.Header["alg"])
		assert.Equal(t, "1234567890", c.Decoded.Payload["sub"])
		assert.Equal(t, "John Doe", c.Decoded.Payload["name"])
	})

	t.Run("jwt_hidden_in_overview", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		jwtValue := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

		mockMCP.AddProxyEntry(
			"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: token="+jwtValue+"\r\n\r\n",
			"",
		)

		// No filter: overview mode omits value and decoded
		resp := CallMCPToolJSONOK[protocol.CookieJarResponse](t, mcpClient, "cookie_jar", nil)
		require.Len(t, resp.Cookies, 1)
		assert.Empty(t, resp.Cookies[0].Value)
		assert.Nil(t, resp.Cookies[0].Decoded)
	})

	t.Run("non_jwt_no_decoded", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		mockMCP.AddProxyEntry(
			"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nSet-Cookie: sid=plainvalue123; Path=/\r\n\r\n",
			"",
		)

		// With name filter: detail mode but non-JWT has no decoded
		resp := CallMCPToolJSONOK[protocol.CookieJarResponse](t, mcpClient, "cookie_jar", map[string]interface{}{
			"name": "sid",
		})
		require.Len(t, resp.Cookies, 1)
		assert.Equal(t, "plainvalue123", resp.Cookies[0].Value)
		assert.Nil(t, resp.Cookies[0].Decoded)
	})
}

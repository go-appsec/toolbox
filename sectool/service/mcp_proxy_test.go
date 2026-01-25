package service

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-harden/llm-security-toolbox/sectool/protocol"
)

func TestMCP_ProxySummaryWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMCPServerWithMock(t)

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

	t.Run("basic", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", nil)
		assert.GreaterOrEqual(t, len(resp.Aggregates), 2)
	})

	summaryCases := []struct {
		name         string
		args         map[string]interface{}
		wantNonEmpty bool

		wantHost string
		wantPath string
		wantMeth string

		statusMin int
		statusMax int

		excludeHost string
		excludePath string
	}{
		{
			name:         "with_host_filter",
			args:         map[string]interface{}{"host": "example.com"},
			wantNonEmpty: true,
			wantHost:     "example.com",
		},
		{
			name:         "with_path_filter",
			args:         map[string]interface{}{"path": "/api/*"},
			wantNonEmpty: true,
			wantPath:     "/api/",
		},
		{
			name:         "with_method_filter",
			args:         map[string]interface{}{"method": "GET"},
			wantNonEmpty: true,
			wantMeth:     "GET",
		},
		{
			name:         "with_status_filter",
			args:         map[string]interface{}{"status": "2XX"},
			wantNonEmpty: true,
			statusMin:    200,
			statusMax:    300,
		},
		{
			name:         "with_exclude_host",
			args:         map[string]interface{}{"exclude_host": "other.com"},
			wantNonEmpty: true,
			excludeHost:  "other.com",
		},
		{
			name:         "with_exclude_path",
			args:         map[string]interface{}{"exclude_path": "/other*"},
			wantNonEmpty: true,
			excludePath:  "/other",
		},
	}
	for _, tc := range summaryCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", tc.args)
			if tc.wantNonEmpty {
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
				if tc.statusMin != 0 || tc.statusMax != 0 {
					assert.GreaterOrEqual(t, agg.Status, tc.statusMin)
					assert.Less(t, agg.Status, tc.statusMax)
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
}

func TestMCP_ProxyListWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMCPServerWithMock(t)
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

	t.Run("basic_filter", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"method":      "GET",
		})
		require.NotEmpty(t, resp.Flows)
		assert.Equal(t, "GET", resp.Flows[0].Method)
		assert.Equal(t, "test.com", resp.Flows[0].Host)
	})

	listCases := []struct {
		name         string
		args         map[string]interface{}
		wantNonEmpty bool

		statusEq  int
		statusMin int
		statusMax int
	}{
		{
			name:         "with_contains_header",
			args:         map[string]interface{}{"output_mode": "flows", "contains": "searchme"},
			wantNonEmpty: true,
		},
		{
			name:         "with_contains_body",
			args:         map[string]interface{}{"output_mode": "flows", "contains_body": "bodysearch"},
			wantNonEmpty: true,
		},
		{
			name:         "with_status_filter",
			args:         map[string]interface{}{"output_mode": "flows", "status": "201"},
			wantNonEmpty: true,
			statusEq:     201,
		},
		{
			name:         "with_status_range",
			args:         map[string]interface{}{"output_mode": "flows", "status": "2XX"},
			wantNonEmpty: true,
			statusMin:    200,
			statusMax:    300,
		},
	}
	for _, tc := range listCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", tc.args)
			if tc.wantNonEmpty {
				require.NotEmpty(t, resp.Flows)
			}
			for _, flow := range resp.Flows {
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
}

func TestMCP_ProxyListWithLimit(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMCPServerWithMock(t)

	for i := 0; i < 5; i++ {
		mockMCP.AddProxyEntry(
			"GET /page HTTP/1.1\r\nHost: limit-test.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\n",
			"",
		)
	}

	t.Run("limit_only", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"host":        "limit-test.com",
			"limit":       2,
		})
		assert.LessOrEqual(t, len(resp.Flows), 2)
	})

	t.Run("with_offset", func(t *testing.T) {
		// First get all flows to know what we have
		allResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"host":        "limit-test.com",
		})
		totalFlows := len(allResp.Flows)

		// Now get with offset
		resp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"host":        "limit-test.com",
			"offset":      2,
		})
		assert.Len(t, resp.Flows, totalFlows-2)
	})

	t.Run("with_since_flow_id", func(t *testing.T) {
		// Get flows to find a flow_id to use as since
		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"host":        "limit-test.com",
			"limit":       1,
		})
		require.NotEmpty(t, listResp.Flows)
		sinceID := listResp.Flows[0].FlowID

		// Query with since
		resp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"host":        "limit-test.com",
			"since":       sinceID,
		})
		// Should not include the flow we used as since
		for _, flow := range resp.Flows {
			assert.NotEqual(t, sinceID, flow.FlowID)
		}
	})

	t.Run("with_since_last", func(t *testing.T) {
		// First call to establish "last" cursor
		_ = CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"host":        "limit-test.com",
		})

		// Second call with since=last should return no new entries
		resp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"host":        "limit-test.com",
			"since":       "last",
		})
		// No new entries since last call
		assert.Empty(t, resp.Flows)
	})
}

func TestMCP_ProxyGetWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMCPServerWithMock(t)

	mockMCP.AddProxyEntry(
		"GET /api/test HTTP/1.1\r\nHost: mock.example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\ntest response body",
		"",
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

	getResult := CallMCPTool(t, mcpClient, "proxy_get", map[string]interface{}{
		"flow_id": flowID,
	})
	assert.False(t, getResult.IsError,
		"proxy_get failed: %s", ExtractMCPText(t, getResult))

	text := ExtractMCPText(t, getResult)
	var getResp protocol.ProxyGetResponse
	require.NoError(t, json.Unmarshal([]byte(text), &getResp))

	assert.Equal(t, flowID, getResp.FlowID)
	assert.Equal(t, "GET", getResp.Method)
	assert.NotEmpty(t, getResp.ReqHeaders)
	assert.NotEmpty(t, getResp.RespHeaders)
}

func TestMCP_ProxyRulesCRUDWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMCPServerWithMock(t)

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

	t.Run("add_rule_with_regex", func(t *testing.T) {
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

	ruleListFilterCases := []struct {
		name       string
		typeFilter string
	}{
		{name: "list_rules_http_filter", typeFilter: "http"},
		{name: "list_rules_websocket_filter", typeFilter: "websocket"},
	}
	for _, tc := range ruleListFilterCases {
		t.Run(tc.name, func(t *testing.T) {
			_ = CallMCPToolJSONOK[protocol.RuleListResponse](t, mcpClient, "proxy_rule_list", map[string]interface{}{
				"type_filter": tc.typeFilter,
			})
		})
	}

	t.Run("list_rules_with_limit", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.RuleListResponse](t, mcpClient, "proxy_rule_list", map[string]interface{}{
			"limit": 1,
		})
		assert.LessOrEqual(t, len(resp.Rules), 1)
	})

	t.Run("update_rule", func(t *testing.T) {
		rule := CallMCPToolJSONOK[protocol.RuleEntry](t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"rule_id": ruleID,
			"type":    RuleTypeRequestBody,
			"label":   "mock-test-updated",
			"match":   "old",
			"replace": "new",
		})
		assert.Equal(t, "mock-test-updated", rule.Label)
		assert.Equal(t, RuleTypeRequestBody, rule.Type)
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
}

func TestMCP_ProxyListRequiresFilters(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMCPServerWithMock(t)

	// List mode requires at least one filter
	result := CallMCPTool(t, mcpClient, "proxy_poll", map[string]interface{}{
		"output_mode": "flows",
	})
	assert.True(t, result.IsError)
}

func TestMCP_ProxyGetValidation(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMCPServerWithMock(t)

	t.Run("missing_flow_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "proxy_get", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "flow_id is required")
	})

	t.Run("invalid_flow_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "proxy_get", map[string]interface{}{
			"flow_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "not found")
	})
}

func TestMCP_ProxyRuleValidation(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMCPServerWithMock(t)

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

	t.Run("add_missing_match_and_replace", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
			"type": RuleTypeRequestHeader,
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "match or replace is required")
	})

	t.Run("add_duplicate_label", func(t *testing.T) {
		// First rule with label
		result := CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
			"type":    RuleTypeRequestHeader,
			"label":   "unique-label",
			"replace": "X-Test: value",
		})
		require.False(t, result.IsError,
			"proxy_rule_add failed: %s", ExtractMCPText(t, result))

		// Second rule with same label
		result = CallMCPTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
			"type":    RuleTypeRequestHeader,
			"label":   "unique-label",
			"replace": "X-Test: value2",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "label already exists")
	})

	t.Run("list_invalid_type_filter", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "proxy_rule_list", map[string]interface{}{
			"type_filter": "invalid",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "invalid type_filter")
	})

	t.Run("update_missing_rule_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"type": RuleTypeRequestHeader,
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "rule_id is required")
	})

	t.Run("update_missing_type", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"rule_id": "some-id",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "type is required")
	})

	t.Run("update_invalid_type", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"rule_id": "some-id",
			"type":    "invalid_type",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "invalid rule type")
	})

	t.Run("update_missing_match_and_replace", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"rule_id": "some-id",
			"type":    RuleTypeRequestHeader,
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "match or replace is required")
	})

	t.Run("update_invalid_rule_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"rule_id": "nonexistent",
			"type":    RuleTypeRequestHeader,
			"replace": "X-Test: value",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "not found")
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
}

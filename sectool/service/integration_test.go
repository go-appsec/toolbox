package service

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jentfoo/llm-security-toolbox/sectool/config"
	"github.com/jentfoo/llm-security-toolbox/sectool/service/mcp"
	"github.com/jentfoo/llm-security-toolbox/sectool/service/testutil"
)

func connectBurpOrSkip(t *testing.T) *mcp.BurpClient {
	t.Helper()

	// Acquire exclusive lock to prevent concurrent MCP connections across packages
	_ = testutil.AcquireBurpLock(t)

	client := mcp.New(config.DefaultBurpMCPURL)
	if err := client.Connect(t.Context()); err != nil {
		t.Skipf("Burp MCP not available at %s: %v", config.DefaultBurpMCPURL, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func setupBurpServer(t *testing.T) (*Server, func()) {
	t.Helper()

	_ = connectBurpOrSkip(t)
	workDir := t.TempDir()
	srv, err := NewServer(DaemonFlags{
		WorkDir:    workDir,
		BurpMCPURL: config.DefaultBurpMCPURL,
	})
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Run(t.Context())
	}()
	srv.WaitTillStarted()

	cleanup := func() {
		srv.RequestShutdown()
		<-serverErr
	}

	return srv, cleanup
}

func doBurpRequest(t *testing.T, srv *Server, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()

	var reqBody bytes.Buffer
	if body != nil {
		err := json.NewEncoder(&reqBody).Encode(body)
		require.NoError(t, err)
	}

	req := httptest.NewRequest(method, path, &reqBody)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.routes().ServeHTTP(w, req)
	return w
}

// TestParseBurpResponse_Integration validates that parseBurpResponse correctly extracts
// headers and body from real Burp MCP responses.
func TestParseBurpResponse_Integration(t *testing.T) {
	client := connectBurpOrSkip(t)

	params := mcp.SendRequestParams{
		Content:        "GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n",
		TargetHostname: "httpbin.org",
		TargetPort:     443,
		UsesHTTPS:      true,
	}
	response, err := client.SendHTTP1Request(t.Context(), params)
	require.NoError(t, err)

	t.Logf("Raw Burp response length: %d bytes", len(response))

	// Test the parsing function
	headers, body, err := parseBurpResponse(response)
	require.NoError(t, err, "parseBurpResponse should succeed")

	// Validate headers structure
	assert.True(t, bytes.HasPrefix(headers, []byte("HTTP/")), "headers should start with HTTP/")
	assert.True(t, bytes.HasSuffix(headers, []byte("\r\n\r\n")), "headers should end with CRLF CRLF")

	// Validate status can be extracted
	resp, err := readResponseBytes(headers)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	// httpbin /get returns JSON body
	assert.NotEmpty(t, body, "body should not be empty")
	assert.True(t, bytes.Contains(body, []byte("httpbin.org")), "body should contain httpbin.org")

	t.Logf("Parsed headers length: %d, body length: %d", len(headers), len(body))
	t.Logf("Headers preview:\n%s", truncateBytes(headers, 300))
}

func truncateBytes(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}

func cleanupIntegrationRules(t *testing.T, backend *BurpBackend) {
	t.Helper()

	// Clean up HTTP rules
	rules, err := backend.ListRules(t.Context(), false)
	require.NoError(t, err)
	for _, r := range rules {
		err = backend.DeleteRule(t.Context(), r.RuleID)
		require.NoError(t, err)
	}

	// Clean up WebSocket rules
	wsRules, err := backend.ListRules(t.Context(), true)
	require.NoError(t, err)
	for _, r := range wsRules {
		err = backend.DeleteRule(t.Context(), r.RuleID)
		require.NoError(t, err)
	}
}

// TestBurpBackendRules_Integration tests the rule CRUD operations against real Burp MCP.
func TestBurpBackendRules_Integration(t *testing.T) {
	client := connectBurpOrSkip(t)

	backend := &BurpBackend{client: client}

	// Clean up any stale rules from previous test runs
	cleanupIntegrationRules(t, backend)

	// Track rules we create for cleanup
	var createdRuleIDs []string
	t.Cleanup(func() {
		for _, id := range createdRuleIDs {
			_ = backend.DeleteRule(t.Context(), id)
		}
	})

	t.Run("list_empty", func(t *testing.T) {
		rules, err := backend.ListRules(t.Context(), false)
		require.NoError(t, err)
		assert.Empty(t, rules, "no sectool rules should exist after cleanup")
	})

	t.Run("add_rule", func(t *testing.T) {
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label:   "integration-test-add",
			Type:    "request_header",
			IsRegex: false,
			Match:   "",
			Replace: "X-Integration-Test: add",
		})
		require.NoError(t, err)
		createdRuleIDs = append(createdRuleIDs, rule.RuleID)

		assert.NotEmpty(t, rule.RuleID)
		assert.Equal(t, "integration-test-add", rule.Label)
		assert.Equal(t, "request_header", rule.Type)
		assert.False(t, rule.IsRegex)
		assert.Equal(t, "X-Integration-Test: add", rule.Replace)

		// Verify it appears in list
		rules, err := backend.ListRules(t.Context(), false)
		require.NoError(t, err)

		var found bool
		for _, r := range rules {
			if r.RuleID == rule.RuleID {
				found = true
				assert.Equal(t, rule.Label, r.Label)
				break
			}
		}
		assert.True(t, found, "created rule should appear in list")
	})

	t.Run("add_rule_regex", func(t *testing.T) {
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label:   "integration-test-regex",
			Type:    "response_header",
			IsRegex: true,
			Match:   "^X-Test-Header.*$",
			Replace: "",
		})
		require.NoError(t, err)
		createdRuleIDs = append(createdRuleIDs, rule.RuleID)

		assert.True(t, rule.IsRegex)
		assert.Equal(t, "response_header", rule.Type)
		assert.Equal(t, "^X-Test-Header.*$", rule.Match)
	})

	t.Run("update_rule_by_id", func(t *testing.T) {
		// First add a rule
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label:   "integration-test-update-id",
			Type:    "request_header",
			Replace: "X-Original: value",
		})
		require.NoError(t, err)
		createdRuleIDs = append(createdRuleIDs, rule.RuleID)

		// Update by ID
		updated, err := backend.UpdateRule(t.Context(), rule.RuleID, ProxyRuleInput{
			Label:   "integration-test-updated",
			Type:    "request_body",
			IsRegex: true,
			Match:   "old",
			Replace: "new",
		})
		require.NoError(t, err)

		assert.Equal(t, rule.RuleID, updated.RuleID) // ID should not change
		assert.Equal(t, "integration-test-updated", updated.Label)
		assert.Equal(t, "request_body", updated.Type)
		assert.True(t, updated.IsRegex)
		assert.Equal(t, "old", updated.Match)
		assert.Equal(t, "new", updated.Replace)
	})

	t.Run("update_rule_by_label", func(t *testing.T) {
		// First add a rule
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label:   "integration-test-update-label",
			Type:    "request_header",
			Replace: "X-By-Label: original",
		})
		require.NoError(t, err)
		createdRuleIDs = append(createdRuleIDs, rule.RuleID)

		// Update by label
		updated, err := backend.UpdateRule(t.Context(), "integration-test-update-label", ProxyRuleInput{
			Label:   "integration-test-update-label-new",
			Type:    "request_header",
			Replace: "X-By-Label: updated",
		})
		require.NoError(t, err)

		assert.Equal(t, rule.RuleID, updated.RuleID)
		assert.Equal(t, "integration-test-update-label-new", updated.Label)
		assert.Equal(t, "X-By-Label: updated", updated.Replace)
	})

	t.Run("delete_rule_by_id", func(t *testing.T) {
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "integration-test-delete-id",
			Type:  "request_header",
		})
		require.NoError(t, err)

		err = backend.DeleteRule(t.Context(), rule.RuleID)
		require.NoError(t, err)

		// Should not appear in list
		rules, err := backend.ListRules(t.Context(), false)
		require.NoError(t, err)
		for _, r := range rules {
			assert.NotEqual(t, rule.RuleID, r.RuleID, "deleted rule should not appear in list")
		}
	})

	t.Run("delete_rule_by_label", func(t *testing.T) {
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "integration-test-delete-label",
			Type:  "request_header",
		})
		require.NoError(t, err)

		err = backend.DeleteRule(t.Context(), "integration-test-delete-label")
		require.NoError(t, err)

		// Should not appear in list
		rules, err := backend.ListRules(t.Context(), false)
		require.NoError(t, err)
		for _, r := range rules {
			assert.NotEqual(t, rule.RuleID, r.RuleID, "deleted rule should not appear in list")
		}
	})

	t.Run("duplicate_label_rejected", func(t *testing.T) {
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "integration-test-duplicate",
			Type:  "request_header",
		})
		require.NoError(t, err)
		createdRuleIDs = append(createdRuleIDs, rule.RuleID)

		// Try to add another with same label
		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "integration-test-duplicate",
			Type:  "request_header",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("update_to_duplicate_label", func(t *testing.T) {
		// Add a second rule
		rule2, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "integration-test-unique",
			Type:  "request_header",
		})
		require.NoError(t, err)
		createdRuleIDs = append(createdRuleIDs, rule2.RuleID)

		// Try to update it to have the same label as the duplicate test rule
		_, err = backend.UpdateRule(t.Context(), rule2.RuleID, ProxyRuleInput{
			Label: "integration-test-duplicate",
			Type:  "request_header",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("update_not_found", func(t *testing.T) {
		_, err := backend.UpdateRule(t.Context(), "nonexistent-rule-id", ProxyRuleInput{
			Type: "request_header",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("delete_not_found", func(t *testing.T) {
		err := backend.DeleteRule(t.Context(), "nonexistent-rule-id")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

// TestBurpBackendWSRules_Integration tests WebSocket rule CRUD operations against real Burp MCP.
func TestBurpBackendWSRules_Integration(t *testing.T) {
	client := connectBurpOrSkip(t)

	backend := &BurpBackend{client: client}

	// Clean up any stale rules from previous test runs
	cleanupIntegrationRules(t, backend)

	// Track rules we create for cleanup
	var createdRuleIDs []string
	t.Cleanup(func() {
		for _, id := range createdRuleIDs {
			_ = backend.DeleteRule(t.Context(), id)
		}
	})

	t.Run("list_empty", func(t *testing.T) {
		rules, err := backend.ListRules(t.Context(), true)
		require.NoError(t, err)
		assert.Empty(t, rules, "no sectool WebSocket rules should exist after cleanup")
	})

	t.Run("add_ws_to_server", func(t *testing.T) {
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label:   "integration-ws-to-server",
			Type:    "ws:to-server",
			IsRegex: false,
			Match:   "client-msg",
			Replace: "modified-msg",
		})
		require.NoError(t, err)
		createdRuleIDs = append(createdRuleIDs, rule.RuleID)

		assert.NotEmpty(t, rule.RuleID)
		assert.Equal(t, "integration-ws-to-server", rule.Label)
		assert.Equal(t, "ws:to-server", rule.Type)
		assert.False(t, rule.IsRegex)
		assert.Equal(t, "client-msg", rule.Match)
		assert.Equal(t, "modified-msg", rule.Replace)

		// Verify it appears in list
		rules, err := backend.ListRules(t.Context(), true)
		require.NoError(t, err)

		var found bool
		for _, r := range rules {
			if r.RuleID == rule.RuleID {
				found = true
				assert.Equal(t, rule.Label, r.Label)
				assert.Equal(t, "ws:to-server", r.Type)
				break
			}
		}
		assert.True(t, found, "created WebSocket rule should appear in list")
	})

	t.Run("add_ws_to_client", func(t *testing.T) {
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label:   "integration-ws-to-client",
			Type:    "ws:to-client",
			IsRegex: true,
			Match:   "^server-response.*$",
			Replace: "",
		})
		require.NoError(t, err)
		createdRuleIDs = append(createdRuleIDs, rule.RuleID)

		assert.Equal(t, "ws:to-client", rule.Type)
		assert.True(t, rule.IsRegex)
	})

	t.Run("add_ws_both", func(t *testing.T) {
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label:   "integration-ws-both",
			Type:    "ws:both",
			Match:   "secret",
			Replace: "REDACTED",
		})
		require.NoError(t, err)
		createdRuleIDs = append(createdRuleIDs, rule.RuleID)

		assert.Equal(t, "ws:both", rule.Type)
	})

	t.Run("update_ws_rule_by_id", func(t *testing.T) {
		// First add a rule
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label:   "integration-ws-update-id",
			Type:    "ws:to-server",
			Replace: "original",
		})
		require.NoError(t, err)
		createdRuleIDs = append(createdRuleIDs, rule.RuleID)

		// Update by ID
		updated, err := backend.UpdateRule(t.Context(), rule.RuleID, ProxyRuleInput{
			Label:   "integration-ws-updated",
			Type:    "ws:to-client",
			IsRegex: true,
			Match:   "old",
			Replace: "new",
		})
		require.NoError(t, err)

		assert.Equal(t, rule.RuleID, updated.RuleID) // ID should not change
		assert.Equal(t, "integration-ws-updated", updated.Label)
		assert.Equal(t, "ws:to-client", updated.Type)
		assert.True(t, updated.IsRegex)
	})

	t.Run("update_ws_rule_by_label", func(t *testing.T) {
		// First add a rule
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label:   "integration-ws-update-label",
			Type:    "ws:both",
			Replace: "original",
		})
		require.NoError(t, err)
		createdRuleIDs = append(createdRuleIDs, rule.RuleID)

		// Update by label
		updated, err := backend.UpdateRule(t.Context(), "integration-ws-update-label", ProxyRuleInput{
			Label:   "integration-ws-update-label-new",
			Type:    "ws:to-server",
			Replace: "updated",
		})
		require.NoError(t, err)

		assert.Equal(t, rule.RuleID, updated.RuleID)
		assert.Equal(t, "integration-ws-update-label-new", updated.Label)
		assert.Equal(t, "ws:to-server", updated.Type)
	})

	t.Run("delete_ws_rule_by_id", func(t *testing.T) {
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "integration-ws-delete-id",
			Type:  "ws:both",
		})
		require.NoError(t, err)

		err = backend.DeleteRule(t.Context(), rule.RuleID)
		require.NoError(t, err)

		// Should not appear in list
		rules, err := backend.ListRules(t.Context(), true)
		require.NoError(t, err)
		for _, r := range rules {
			assert.NotEqual(t, rule.RuleID, r.RuleID, "deleted rule should not appear in list")
		}
	})

	t.Run("delete_ws_rule_by_label", func(t *testing.T) {
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "integration-ws-delete-label",
			Type:  "ws:to-server",
		})
		require.NoError(t, err)

		err = backend.DeleteRule(t.Context(), "integration-ws-delete-label")
		require.NoError(t, err)

		// Should not appear in list
		rules, err := backend.ListRules(t.Context(), true)
		require.NoError(t, err)
		for _, r := range rules {
			assert.NotEqual(t, rule.RuleID, r.RuleID, "deleted rule should not appear in list")
		}
	})

	t.Run("ws_http_isolation", func(t *testing.T) {
		// Add a WebSocket rule
		wsRule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "integration-ws-isolation",
			Type:  "ws:both",
		})
		require.NoError(t, err)
		createdRuleIDs = append(createdRuleIDs, wsRule.RuleID)

		// Add an HTTP rule
		httpRule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "integration-http-isolation",
			Type:  "request_header",
		})
		require.NoError(t, err)
		createdRuleIDs = append(createdRuleIDs, httpRule.RuleID)

		// HTTP rule should not appear in WebSocket list
		wsRules, err := backend.ListRules(t.Context(), true)
		require.NoError(t, err)
		for _, r := range wsRules {
			assert.NotEqual(t, httpRule.RuleID, r.RuleID, "HTTP rule should not appear in WebSocket list")
		}

		// WebSocket rule should not appear in HTTP list
		httpRules, err := backend.ListRules(t.Context(), false)
		require.NoError(t, err)
		for _, r := range httpRules {
			assert.NotEqual(t, wsRule.RuleID, r.RuleID, "WebSocket rule should not appear in HTTP list")
		}
	})
}

// =============================================================================
// Rule Handler Integration Tests
// =============================================================================

// TestRuleHandlers_Integration tests the rule HTTP handlers against real Burp MCP.
func TestRuleHandlers_Integration(t *testing.T) {
	srv, cleanup := setupBurpServer(t)
	defer cleanup()

	// Clean up any stale rules first
	cleanupRulesViaHandler(t, srv)

	// Track created rules for cleanup
	var createdRuleIDs []string
	t.Cleanup(func() {
		for _, id := range createdRuleIDs {
			deleteRuleViaHandler(t, srv, id)
		}
	})

	t.Run("list_empty", func(t *testing.T) {
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{})
		require.Equal(t, 200, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var listResp RuleListResponse
		require.NoError(t, json.Unmarshal(resp.Data, &listResp))
		assert.Empty(t, listResp.Rules)
	})

	t.Run("add_rule", func(t *testing.T) {
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "handler-test-add",
			Type:    "request_header",
			Replace: "X-Handler-Test: value",
		})
		require.Equal(t, 200, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.True(t, resp.OK, "response should be OK: %s", w.Body.String())

		var addResp RuleEntry
		require.NoError(t, json.Unmarshal(resp.Data, &addResp))
		assert.NotEmpty(t, addResp.RuleID)
		assert.Equal(t, "handler-test-add", addResp.Label)
		assert.Equal(t, "request_header", addResp.Type)
		assert.Equal(t, "X-Handler-Test: value", addResp.Replace)
		createdRuleIDs = append(createdRuleIDs, addResp.RuleID)
	})

	t.Run("add_rule_validation", func(t *testing.T) {
		// Missing type should fail
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "handler-test-invalid",
			Replace: "X-Test: value",
		})
		require.Equal(t, 400, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeInvalidRequest, resp.Error.Code)
	})

	t.Run("add_rule_invalid_type", func(t *testing.T) {
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Type: "invalid_type",
		})
		require.Equal(t, 400, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Contains(t, resp.Error.Message, "invalid rule type")
	})

	t.Run("list_after_add", func(t *testing.T) {
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{})
		require.Equal(t, 200, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

		var listResp RuleListResponse
		require.NoError(t, json.Unmarshal(resp.Data, &listResp))
		require.NotEmpty(t, listResp.Rules)

		var found bool
		for _, r := range listResp.Rules {
			if r.Label == "handler-test-add" {
				found = true
				assert.Equal(t, "request_header", r.Type)
				break
			}
		}
		assert.True(t, found, "added rule should appear in list")
	})

	t.Run("list_with_limit", func(t *testing.T) {
		// Add another rule
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "handler-test-limit",
			Type:    "request_header",
			Replace: "X-Limit-Test: value",
		})
		require.Equal(t, 200, w.Code)

		var addResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &addResp))
		var add RuleEntry
		require.NoError(t, json.Unmarshal(addResp.Data, &add))
		createdRuleIDs = append(createdRuleIDs, add.RuleID)

		// List with limit=1
		w = doBurpRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{Limit: 1})
		require.Equal(t, 200, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

		var listResp RuleListResponse
		require.NoError(t, json.Unmarshal(resp.Data, &listResp))
		assert.Len(t, listResp.Rules, 1, "limit should be applied")
	})

	t.Run("update_rule", func(t *testing.T) {
		// Add a rule to update
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "handler-test-update",
			Type:    "request_header",
			Replace: "X-Original: value",
		})
		require.Equal(t, 200, w.Code)

		var addResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &addResp))
		var add RuleEntry
		require.NoError(t, json.Unmarshal(addResp.Data, &add))
		createdRuleIDs = append(createdRuleIDs, add.RuleID)

		// Update by ID
		w = doBurpRequest(t, srv, "POST", "/proxy/rule/update", RuleUpdateRequest{
			RuleID:  add.RuleID,
			Label:   "handler-test-updated",
			Type:    "request_body",
			IsRegex: true,
			Match:   "old",
			Replace: "new",
		})
		require.Equal(t, 200, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.True(t, resp.OK)

		var updateResp RuleEntry
		require.NoError(t, json.Unmarshal(resp.Data, &updateResp))
		assert.Equal(t, add.RuleID, updateResp.RuleID)
		assert.Equal(t, "handler-test-updated", updateResp.Label)
		assert.Equal(t, "request_body", updateResp.Type)
		assert.True(t, updateResp.IsRegex)
	})

	t.Run("update_not_found", func(t *testing.T) {
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/update", RuleUpdateRequest{
			RuleID:  "nonexistent-id",
			Type:    "request_header",
			Replace: "X-Test: value",
		})
		require.Equal(t, 404, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeNotFound, resp.Error.Code)
	})

	t.Run("update_validation", func(t *testing.T) {
		// Missing rule_id
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/update", RuleUpdateRequest{
			Type: "request_header",
		})
		require.Equal(t, 400, w.Code)

		// Missing type
		w = doBurpRequest(t, srv, "POST", "/proxy/rule/update", RuleUpdateRequest{
			RuleID: "some-id",
		})
		require.Equal(t, 400, w.Code)
	})

	t.Run("delete_rule", func(t *testing.T) {
		// Add a rule to delete
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "handler-test-delete",
			Type:    "request_header",
			Replace: "X-Delete-Test: value",
		})
		require.Equal(t, 200, w.Code)

		var addResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &addResp))
		var add RuleEntry
		require.NoError(t, json.Unmarshal(addResp.Data, &add))

		// Delete
		w = doBurpRequest(t, srv, "POST", "/proxy/rule/delete", RuleDeleteRequest{
			RuleID: add.RuleID,
		})
		require.Equal(t, 200, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		// Verify not in list
		w = doBurpRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{})
		require.Equal(t, 200, w.Code)

		var listResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))

		var list RuleListResponse
		require.NoError(t, json.Unmarshal(listResp.Data, &list))
		for _, r := range list.Rules {
			assert.NotEqual(t, add.RuleID, r.RuleID, "deleted rule should not appear in list")
		}
	})

	t.Run("delete_not_found", func(t *testing.T) {
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/delete", RuleDeleteRequest{
			RuleID: "nonexistent-id",
		})
		require.Equal(t, 404, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeNotFound, resp.Error.Code)
	})

	t.Run("delete_validation", func(t *testing.T) {
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/delete", RuleDeleteRequest{})
		require.Equal(t, 400, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeInvalidRequest, resp.Error.Code)
	})

	t.Run("duplicate_label", func(t *testing.T) {
		// Add first rule
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "handler-test-dup",
			Type:    "request_header",
			Replace: "X-Dup-Test: value",
		})
		require.Equal(t, 200, w.Code)

		var addResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &addResp))
		var add RuleEntry
		require.NoError(t, json.Unmarshal(addResp.Data, &add))
		createdRuleIDs = append(createdRuleIDs, add.RuleID)

		// Try to add duplicate
		w = doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "handler-test-dup",
			Type:    "request_header",
			Replace: "X-Dup-Test: value2",
		})
		require.Equal(t, 400, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Contains(t, resp.Error.Hint, "already exists")
	})

	t.Run("update_to_duplicate_label", func(t *testing.T) {
		// Add a second rule
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "handler-test-unique",
			Type:    "request_header",
			Replace: "X-Unique-Test: value",
		})
		require.Equal(t, 200, w.Code)

		var addResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &addResp))
		var add RuleEntry
		require.NoError(t, json.Unmarshal(addResp.Data, &add))
		createdRuleIDs = append(createdRuleIDs, add.RuleID)

		// Try to update it to have the same label as the dup test rule
		w = doBurpRequest(t, srv, "POST", "/proxy/rule/update", RuleUpdateRequest{
			RuleID:  add.RuleID,
			Label:   "handler-test-dup",
			Type:    "request_header",
			Replace: "X-Unique-Test: updated",
		})
		require.Equal(t, 400, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Contains(t, resp.Error.Hint, "already exists")
	})
}

// TestWSRuleHandlers_Integration tests the WebSocket rule HTTP handlers against real Burp MCP.
func TestWSRuleHandlers_Integration(t *testing.T) {
	srv, cleanup := setupBurpServer(t)
	defer cleanup()

	// Clean up any stale rules first
	cleanupRulesViaHandler(t, srv)

	// Track created rules for cleanup
	var createdRuleIDs []string
	t.Cleanup(func() {
		for _, id := range createdRuleIDs {
			deleteRuleViaHandler(t, srv, id)
		}
	})

	t.Run("list_empty", func(t *testing.T) {
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{WebSocket: true})
		require.Equal(t, 200, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var listResp RuleListResponse
		require.NoError(t, json.Unmarshal(resp.Data, &listResp))
		assert.Empty(t, listResp.Rules)
	})

	t.Run("add_ws_rule", func(t *testing.T) {
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "handler-ws-test-add",
			Type:    "ws:to-server",
			Match:   "client-message",
			Replace: "modified-message",
		})
		require.Equal(t, 200, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.True(t, resp.OK, "response should be OK: %s", w.Body.String())

		var addResp RuleEntry
		require.NoError(t, json.Unmarshal(resp.Data, &addResp))
		assert.NotEmpty(t, addResp.RuleID)
		assert.Equal(t, "handler-ws-test-add", addResp.Label)
		assert.Equal(t, "ws:to-server", addResp.Type)
		assert.Equal(t, "client-message", addResp.Match)
		assert.Equal(t, "modified-message", addResp.Replace)
		createdRuleIDs = append(createdRuleIDs, addResp.RuleID)
	})

	t.Run("add_ws_rule_all_types", func(t *testing.T) {
		// Test ws:to-client
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "handler-ws-to-client",
			Type:    "ws:to-client",
			Replace: "test",
		})
		require.Equal(t, 200, w.Code)
		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		var add RuleEntry
		require.NoError(t, json.Unmarshal(resp.Data, &add))
		assert.Equal(t, "ws:to-client", add.Type)
		createdRuleIDs = append(createdRuleIDs, add.RuleID)

		// Test ws:both
		w = doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "handler-ws-both",
			Type:    "ws:both",
			Replace: "test",
		})
		require.Equal(t, 200, w.Code)
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.NoError(t, json.Unmarshal(resp.Data, &add))
		assert.Equal(t, "ws:both", add.Type)
		createdRuleIDs = append(createdRuleIDs, add.RuleID)
	})

	t.Run("add_rule_invalid_type", func(t *testing.T) {
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Type:    "invalid_type",
			Replace: "X-Test: value",
		})
		require.Equal(t, 400, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Contains(t, resp.Error.Message, "invalid rule type")
	})

	t.Run("list_ws_after_add", func(t *testing.T) {
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{WebSocket: true})
		require.Equal(t, 200, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

		var listResp RuleListResponse
		require.NoError(t, json.Unmarshal(resp.Data, &listResp))
		require.NotEmpty(t, listResp.Rules)

		// Should find our ws:to-server rule
		var found bool
		for _, r := range listResp.Rules {
			if r.Label == "handler-ws-test-add" {
				found = true
				assert.Equal(t, "ws:to-server", r.Type)
				break
			}
		}
		assert.True(t, found, "added WebSocket rule should appear in list")
	})

	t.Run("update_ws_rule", func(t *testing.T) {
		// Add a rule to update
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "handler-ws-update",
			Type:    "ws:to-server",
			Replace: "original",
		})
		require.Equal(t, 200, w.Code)

		var addResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &addResp))
		var add RuleEntry
		require.NoError(t, json.Unmarshal(addResp.Data, &add))
		createdRuleIDs = append(createdRuleIDs, add.RuleID)

		// Update by ID
		w = doBurpRequest(t, srv, "POST", "/proxy/rule/update", RuleUpdateRequest{
			RuleID:  add.RuleID,
			Label:   "handler-ws-updated",
			Type:    "ws:to-client",
			IsRegex: true,
			Match:   "old",
			Replace: "new",
		})
		require.Equal(t, 200, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.True(t, resp.OK)

		var updateResp RuleEntry
		require.NoError(t, json.Unmarshal(resp.Data, &updateResp))
		assert.Equal(t, add.RuleID, updateResp.RuleID)
		assert.Equal(t, "handler-ws-updated", updateResp.Label)
		assert.Equal(t, "ws:to-client", updateResp.Type)
		assert.True(t, updateResp.IsRegex)
	})

	t.Run("delete_ws_rule", func(t *testing.T) {
		// Add a rule to delete
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "handler-ws-delete",
			Type:    "ws:both",
			Replace: "test",
		})
		require.Equal(t, 200, w.Code)

		var addResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &addResp))
		var add RuleEntry
		require.NoError(t, json.Unmarshal(addResp.Data, &add))

		// Delete
		w = doBurpRequest(t, srv, "POST", "/proxy/rule/delete", RuleDeleteRequest{
			RuleID: add.RuleID,
		})
		require.Equal(t, 200, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		// Verify not in list
		w = doBurpRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{WebSocket: true})
		require.Equal(t, 200, w.Code)

		var listResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))

		var list RuleListResponse
		require.NoError(t, json.Unmarshal(listResp.Data, &list))
		for _, r := range list.Rules {
			assert.NotEqual(t, add.RuleID, r.RuleID, "deleted rule should not appear in list")
		}
	})

	t.Run("ws_http_isolation", func(t *testing.T) {
		// Add a WebSocket rule
		w := doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "handler-ws-isolation",
			Type:    "ws:both",
			Replace: "test",
		})
		require.Equal(t, 200, w.Code)
		var wsResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &wsResp))
		var wsRule RuleEntry
		require.NoError(t, json.Unmarshal(wsResp.Data, &wsRule))
		createdRuleIDs = append(createdRuleIDs, wsRule.RuleID)

		// Add an HTTP rule
		w = doBurpRequest(t, srv, "POST", "/proxy/rule/add", RuleAddRequest{
			Label:   "handler-http-isolation",
			Type:    "request_header",
			Replace: "X-Test: value",
		})
		require.Equal(t, 200, w.Code)
		var httpResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &httpResp))
		var httpRule RuleEntry
		require.NoError(t, json.Unmarshal(httpResp.Data, &httpRule))
		createdRuleIDs = append(createdRuleIDs, httpRule.RuleID)

		// WebSocket rule should NOT appear in HTTP list
		w = doBurpRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{WebSocket: false})
		require.Equal(t, 200, w.Code)
		var listResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))
		var httpList RuleListResponse
		require.NoError(t, json.Unmarshal(listResp.Data, &httpList))
		for _, r := range httpList.Rules {
			assert.NotEqual(t, wsRule.RuleID, r.RuleID, "WebSocket rule should not appear in HTTP list")
		}

		// HTTP rule should NOT appear in WebSocket list
		w = doBurpRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{WebSocket: true})
		require.Equal(t, 200, w.Code)
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))
		var wsList RuleListResponse
		require.NoError(t, json.Unmarshal(listResp.Data, &wsList))
		for _, r := range wsList.Rules {
			assert.NotEqual(t, httpRule.RuleID, r.RuleID, "HTTP rule should not appear in WebSocket list")
		}
	})
}

func cleanupRulesViaHandler(t *testing.T, srv *Server) {
	t.Helper()

	// Clean up HTTP rules
	w := doBurpRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{})
	if w.Code == 200 {
		var resp APIResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err == nil && resp.OK {
			var listResp RuleListResponse
			if err := json.Unmarshal(resp.Data, &listResp); err == nil {
				for _, r := range listResp.Rules {
					deleteRuleViaHandler(t, srv, r.RuleID)
				}
			}
		}
	}

	// Clean up WebSocket rules
	w = doBurpRequest(t, srv, "POST", "/proxy/rule/list", RuleListRequest{WebSocket: true})
	if w.Code == 200 {
		var resp APIResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err == nil && resp.OK {
			var listResp RuleListResponse
			if err := json.Unmarshal(resp.Data, &listResp); err == nil {
				for _, r := range listResp.Rules {
					deleteRuleViaHandler(t, srv, r.RuleID)
				}
			}
		}
	}
}

func deleteRuleViaHandler(t *testing.T, srv *Server, ruleID string) {
	t.Helper()

	doBurpRequest(t, srv, "POST", "/proxy/rule/delete", RuleDeleteRequest{RuleID: ruleID})
}

package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-harden/llm-security-toolbox/sectool/config"
	"github.com/go-harden/llm-security-toolbox/sectool/mcpclient"
	"github.com/go-harden/llm-security-toolbox/sectool/service"
	"github.com/go-harden/llm-security-toolbox/sectool/service/testutil"
)

// Integration tests for sectool MCP client → MCP server → real backends.
//
// These tests validate end-to-end functionality through the full stack:
//   mcpclient.Client → sectool MCP server → Burp MCP backend / OAST backend
//
// Skip automatically if:
//   - Running with -short flag
//   - Burp MCP is not available

// setupIntegrationEnv creates the MCP server with real backends and returns a connected client.
// Skips if Burp is unavailable or if running in short mode.
func setupIntegrationEnv(t *testing.T) *mcpclient.Client {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Verify Burp connectivity before starting server (also acquires exclusive lock)
	burpClient := testutil.ConnectBurpSSEOrSkip(t)
	_ = burpClient.Close()

	port := findAvailablePort(t)

	// Start MCP server with real backends
	srv, err := service.NewServer(service.MCPServerFlags{
		BurpMCPURL:   config.DefaultBurpMCPURL,
		MCPPort:      port,
		WorkflowMode: service.WorkflowModeNone,
	}, nil, nil, nil)
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() { serverErr <- srv.Run(t.Context()) }()
	srv.WaitTillStarted()

	// Connect mcpclient
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	client, err := mcpclient.New(ctx, fmt.Sprintf("http://127.0.0.1:%d/mcp", port))
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = client.Close()
		srv.RequestShutdown()
		<-serverErr
	})

	return client
}

// findAvailablePort finds an available TCP port by briefly binding to port 0.
func findAvailablePort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// =============================================================================
// Proxy Tests
// =============================================================================

func TestIntegration_ProxySummary(t *testing.T) {
	client := setupIntegrationEnv(t)

	resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{})
	require.NoError(t, err)

	t.Logf("proxy_poll summary: %d aggregates", len(resp.Aggregates))
	for i, agg := range resp.Aggregates {
		if i >= 5 {
			t.Logf("  ... and %d more", len(resp.Aggregates)-5)
			break
		}
		t.Logf("  [%d] %s %s%s → %d (%d reqs)", i, agg.Method, agg.Host, agg.Path, agg.Status, agg.Count)
	}
}

func TestIntegration_ProxySummaryWithFilters(t *testing.T) {
	client := setupIntegrationEnv(t)

	t.Run("filter_by_method", func(t *testing.T) {
		resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "summary", Method: "GET"})
		require.NoError(t, err)

		for _, agg := range resp.Aggregates {
			assert.Equal(t, "GET", agg.Method)
		}
		t.Logf("GET-only summary: %d aggregates", len(resp.Aggregates))
	})

	t.Run("filter_by_status", func(t *testing.T) {
		resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "summary", Status: "200"})
		require.NoError(t, err)

		for _, agg := range resp.Aggregates {
			assert.Equal(t, 200, agg.Status)
		}
		t.Logf("status=200 summary: %d aggregates", len(resp.Aggregates))
	})

	t.Run("filter_by_host", func(t *testing.T) {
		// First get any host from unfiltered summary
		allResp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{})
		require.NoError(t, err)

		if len(allResp.Aggregates) == 0 {
			t.Skip("no proxy history")
		}

		testHost := allResp.Aggregates[0].Host
		resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "summary", Host: testHost})
		require.NoError(t, err)

		for _, agg := range resp.Aggregates {
			assert.Equal(t, testHost, agg.Host)
		}
		t.Logf("host=%s summary: %d aggregates", testHost, len(resp.Aggregates))
	})

	t.Run("summary_does_not_return_flows", func(t *testing.T) {
		resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "summary"})
		require.NoError(t, err)

		// Summary mode should not return flows (flows should be nil/empty)
		assert.Empty(t, resp.Flows)
		t.Logf("summary mode: %d aggregates, %d flows", len(resp.Aggregates), len(resp.Flows))
	})
}

func TestIntegration_ProxyList(t *testing.T) {
	client := setupIntegrationEnv(t)

	t.Run("list_requires_filters", func(t *testing.T) {
		_, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows"})
		require.Error(t, err)
	})

	t.Run("with_method_filter", func(t *testing.T) {
		resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Method: "GET", Limit: 10})
		require.NoError(t, err)

		for _, flow := range resp.Flows {
			assert.Equal(t, "GET", flow.Method)
		}
		t.Logf("GET flows: %d", len(resp.Flows))
	})

	t.Run("with_limit", func(t *testing.T) {
		resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Method: "GET", Limit: 3})
		require.NoError(t, err)
		assert.LessOrEqual(t, len(resp.Flows), 3)
	})

	t.Run("with_host_filter", func(t *testing.T) {
		// First get a host from the summary
		summary, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{})
		require.NoError(t, err)

		if len(summary.Aggregates) == 0 {
			t.Skip("no proxy history")
		}

		testHost := summary.Aggregates[0].Host
		resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Host: testHost, Limit: 5})
		require.NoError(t, err)

		for _, flow := range resp.Flows {
			assert.Contains(t, flow.Host, testHost)
		}
		t.Logf("host=%s: %d flows", testHost, len(resp.Flows))
	})

	t.Run("list_does_not_return_aggregates", func(t *testing.T) {
		resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Method: "GET", Limit: 5})
		require.NoError(t, err)

		// List mode should not return aggregates (aggregates should be nil/empty)
		assert.Empty(t, resp.Aggregates)
		t.Logf("list mode: %d flows, %d aggregates", len(resp.Flows), len(resp.Aggregates))
	})
}

func TestIntegration_ProxyGet(t *testing.T) {
	client := setupIntegrationEnv(t)

	// Get a flow ID first
	listResp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Method: "GET", Limit: 1})
	require.NoError(t, err)

	if len(listResp.Flows) == 0 {
		t.Skip("no GET requests in proxy history")
	}

	flowID := listResp.Flows[0].FlowID

	t.Run("valid_flow_id", func(t *testing.T) {
		resp, err := client.ProxyGet(t.Context(), flowID)
		require.NoError(t, err)

		assert.Equal(t, flowID, resp.FlowID)
		assert.Equal(t, "GET", resp.Method)
		assert.NotEmpty(t, resp.URL)
		assert.NotEmpty(t, resp.ReqHeaders)
		assert.True(t, strings.HasPrefix(resp.ReqHeaders, "GET "))

		t.Logf("flow %s: %s status=%d req_size=%d resp_size=%d",
			flowID, resp.URL, resp.Status, resp.ReqSize, resp.RespSize)
	})

	t.Run("invalid_flow_id", func(t *testing.T) {
		_, err := client.ProxyGet(t.Context(), "nonexistent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

// =============================================================================
// Proxy Rules
// =============================================================================

func TestIntegration_ProxyRules(t *testing.T) {
	client := setupIntegrationEnv(t)

	testLabel := fmt.Sprintf("sectool-integ-test-%d", time.Now().UnixNano())
	var createdRuleID string

	t.Run("list_initial", func(t *testing.T) {
		resp, err := client.ProxyRuleList(t.Context(), "", 0)
		require.NoError(t, err)
		t.Logf("initial rules: %d", len(resp.Rules))
	})

	t.Run("add_rule", func(t *testing.T) {
		rule, err := client.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
			Type:    service.RuleTypeRequestHeader,
			Label:   testLabel,
			Replace: "X-Integration-Test: added",
		})
		require.NoError(t, err)

		assert.NotEmpty(t, rule.RuleID)
		assert.Equal(t, testLabel, rule.Label)
		assert.Equal(t, service.RuleTypeRequestHeader, rule.Type)
		assert.Equal(t, "X-Integration-Test: added", rule.Replace)
		createdRuleID = rule.RuleID

		t.Logf("created rule: %s (%s)", rule.RuleID, rule.Label)
	})

	t.Run("list_after_add", func(t *testing.T) {
		resp, err := client.ProxyRuleList(t.Context(), "", 0)
		require.NoError(t, err)

		var found bool
		for _, r := range resp.Rules {
			if r.RuleID == createdRuleID {
				found = true
				assert.Equal(t, testLabel, r.Label)
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("update_rule", func(t *testing.T) {
		rule, err := client.ProxyRuleUpdate(t.Context(), createdRuleID, mcpclient.RuleUpdateOpts{
			Type:    service.RuleTypeRequestBody,
			Label:   testLabel + "-updated",
			Match:   "old-value",
			Replace: "new-value",
		})
		require.NoError(t, err)

		assert.Equal(t, createdRuleID, rule.RuleID)
		assert.Equal(t, testLabel+"-updated", rule.Label)
		assert.Equal(t, service.RuleTypeRequestBody, rule.Type)
		assert.Equal(t, "old-value", rule.Match)
		assert.Equal(t, "new-value", rule.Replace)
	})

	t.Run("update_by_label", func(t *testing.T) {
		rule, err := client.ProxyRuleUpdate(t.Context(), testLabel+"-updated", mcpclient.RuleUpdateOpts{
			Type:    service.RuleTypeResponseHeader,
			Replace: "X-Modified: true",
		})
		require.NoError(t, err)

		assert.Equal(t, createdRuleID, rule.RuleID)
		assert.Equal(t, service.RuleTypeResponseHeader, rule.Type)
	})

	t.Run("add_regex_rule", func(t *testing.T) {
		regexLabel := testLabel + "-regex"
		rule, err := client.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
			Type:    service.RuleTypeRequestHeader,
			Label:   regexLabel,
			IsRegex: true,
			Match:   "^X-Old:.*$",
			Replace: "X-New: replaced",
		})
		require.NoError(t, err)

		assert.True(t, rule.IsRegex)
		assert.Equal(t, "^X-Old:.*$", rule.Match)

		t.Cleanup(func() {
			_ = client.ProxyRuleDelete(t.Context(), rule.RuleID)
		})
	})

	t.Run("delete_rule", func(t *testing.T) {
		err := client.ProxyRuleDelete(t.Context(), createdRuleID)
		require.NoError(t, err)

		// Verify deleted
		resp, err := client.ProxyRuleList(t.Context(), "", 0)
		require.NoError(t, err)

		for _, r := range resp.Rules {
			assert.NotEqual(t, createdRuleID, r.RuleID)
		}
	})

	t.Run("delete_nonexistent", func(t *testing.T) {
		err := client.ProxyRuleDelete(t.Context(), "nonexistent-rule-id")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

// =============================================================================
// Replay Tests
// =============================================================================

func TestIntegration_Replay(t *testing.T) {
	client := setupIntegrationEnv(t)

	// Get a flow to replay
	listResp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Method: "GET", Limit: 1})
	require.NoError(t, err)

	if len(listResp.Flows) == 0 {
		t.Skip("no GET requests in proxy history")
	}

	flowID := listResp.Flows[0].FlowID
	t.Logf("using flow %s for replay tests", flowID)

	var replayID string

	t.Run("send_basic", func(t *testing.T) {
		resp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID: flowID,
		})
		require.NoError(t, err)

		assert.NotEmpty(t, resp.ReplayID)
		assert.NotEmpty(t, resp.Duration)
		replayID = resp.ReplayID

		t.Logf("replay %s: status=%d duration=%s", resp.ReplayID, resp.Status, resp.Duration)
	})

	t.Run("get_replay_result", func(t *testing.T) {
		if replayID == "" {
			t.Skip("no replay ID from previous test")
		}

		resp, err := client.ReplayGet(t.Context(), replayID)
		require.NoError(t, err)

		assert.Equal(t, replayID, resp.ReplayID)
		assert.NotEmpty(t, resp.RespHeaders)
		assert.True(t, strings.HasPrefix(resp.RespHeaders, "HTTP/"))

		t.Logf("replay_get %s: status=%d body_size=%d", resp.ReplayID, resp.Status, resp.RespSize)
	})

	t.Run("send_with_header_mods", func(t *testing.T) {
		resp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID:        flowID,
			AddHeaders:    []string{"X-Integration-Test: modified"},
			RemoveHeaders: []string{"Accept-Encoding"},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.ReplayID)
		t.Logf("replay with mods: status=%d", resp.Status)
	})

	t.Run("send_invalid_flow", func(t *testing.T) {
		_, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID: "nonexistent",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("get_invalid_replay", func(t *testing.T) {
		_, err := client.ReplayGet(t.Context(), "nonexistent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestIntegration_ReplayWithQueryMods(t *testing.T) {
	client := setupIntegrationEnv(t)

	// Find a flow with query params or just use any GET
	listResp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Method: "GET", Limit: 1})
	require.NoError(t, err)

	if len(listResp.Flows) == 0 {
		t.Skip("no GET requests in proxy history")
	}

	flowID := listResp.Flows[0].FlowID

	t.Run("set_query_params", func(t *testing.T) {
		resp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID:   flowID,
			SetQuery: []string{"test_param=test_value", "another=123"},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.ReplayID)
	})

	t.Run("replace_query_string", func(t *testing.T) {
		resp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID: flowID,
			Query:  "completely=new&query=string",
		})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.ReplayID)
	})
}

// =============================================================================
// Request Send Tests (new requests from scratch)
// =============================================================================

func TestIntegration_RequestSend(t *testing.T) {
	client := setupIntegrationEnv(t)

	t.Run("simple_get", func(t *testing.T) {
		resp, err := client.RequestSend(t.Context(), mcpclient.RequestSendOpts{
			URL:    "https://httpbin.org/get",
			Method: "GET",
		})
		require.NoError(t, err)

		assert.NotEmpty(t, resp.ReplayID)
		assert.Equal(t, 200, resp.Status)
		t.Logf("request_send GET: status=%d duration=%s", resp.Status, resp.Duration)
	})

	t.Run("with_headers", func(t *testing.T) {
		resp, err := client.RequestSend(t.Context(), mcpclient.RequestSendOpts{
			URL:    "https://httpbin.org/headers",
			Method: "GET",
			Headers: map[string]string{
				"X-Custom-Header": "integration-test",
				"Accept":          "application/json",
			},
		})
		require.NoError(t, err)
		assert.Equal(t, 200, resp.Status)
	})

	t.Run("post_with_body", func(t *testing.T) {
		resp, err := client.RequestSend(t.Context(), mcpclient.RequestSendOpts{
			URL:    "https://httpbin.org/post",
			Method: "POST",
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			Body: `{"test": "data", "integration": true}`,
		})
		require.NoError(t, err)
		assert.Equal(t, 200, resp.Status)
		t.Logf("request_send POST: status=%d", resp.Status)
	})
}

// =============================================================================
// OAST Tests
// =============================================================================

func TestIntegration_OAST(t *testing.T) {
	client := setupIntegrationEnv(t)

	testLabel := fmt.Sprintf("integ-test-%d", time.Now().UnixNano())
	var oastID string
	var oastDomain string

	t.Run("create_session", func(t *testing.T) {
		resp, err := client.OastCreate(t.Context(), testLabel)
		require.NoError(t, err)

		assert.NotEmpty(t, resp.OastID)
		assert.NotEmpty(t, resp.Domain)
		assert.Equal(t, testLabel, resp.Label)
		oastID = resp.OastID
		oastDomain = resp.Domain

		t.Logf("oast_create: id=%s domain=%s", resp.OastID, resp.Domain)
	})

	t.Run("list_sessions", func(t *testing.T) {
		if oastID == "" {
			t.Skip("no OAST session created")
		}

		resp, err := client.OastList(t.Context(), 0)
		require.NoError(t, err)

		var found bool
		for _, s := range resp.Sessions {
			if s.OastID == oastID {
				found = true
				assert.Equal(t, oastDomain, s.Domain)
				assert.Equal(t, testLabel, s.Label)
				break
			}
		}
		assert.True(t, found)
		t.Logf("oast_list: %d sessions", len(resp.Sessions))
	})

	t.Run("poll_no_events", func(t *testing.T) {
		if oastID == "" {
			t.Skip("no OAST session created")
		}

		resp, err := client.OastPoll(t.Context(), oastID, mcpclient.OastPollOpts{OutputMode: "events"})
		require.NoError(t, err)

		// May or may not have events depending on timing
		t.Logf("oast_poll: %d events", len(resp.Events))
	})

	t.Run("poll_with_wait", func(t *testing.T) {
		if oastID == "" {
			t.Skip("no OAST session created")
		}

		// Short wait - should return quickly with no events
		resp, err := client.OastPoll(t.Context(), oastID, mcpclient.OastPollOpts{OutputMode: "events", Wait: "200ms"})
		require.NoError(t, err)
		t.Logf("oast_poll: %d events", len(resp.Events))
	})

	t.Run("poll_invalid_session", func(t *testing.T) {
		_, err := client.OastPoll(t.Context(), "nonexistent", mcpclient.OastPollOpts{OutputMode: "events"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("delete_session", func(t *testing.T) {
		if oastID == "" {
			t.Skip("no OAST session created")
		}

		err := client.OastDelete(t.Context(), oastID)
		require.NoError(t, err)

		// Verify deleted
		resp, err := client.OastList(t.Context(), 0)
		require.NoError(t, err)

		for _, s := range resp.Sessions {
			assert.NotEqual(t, oastID, s.OastID)
		}
	})

	t.Run("delete_invalid_session", func(t *testing.T) {
		err := client.OastDelete(t.Context(), "nonexistent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestIntegration_OASTMultipleSessions(t *testing.T) {
	client := setupIntegrationEnv(t)

	// Create multiple sessions
	var sessionIDs []string
	for i := 0; i < 3; i++ {
		label := fmt.Sprintf("multi-test-%d-%d", time.Now().UnixNano(), i)
		resp, err := client.OastCreate(t.Context(), label)
		require.NoError(t, err)
		sessionIDs = append(sessionIDs, resp.OastID)
	}

	t.Cleanup(func() {
		for _, id := range sessionIDs {
			_ = client.OastDelete(t.Context(), id)
		}
	})

	// Verify all sessions exist
	listResp, err := client.OastList(t.Context(), 0)
	require.NoError(t, err)

	foundCount := 0
	for _, s := range listResp.Sessions {
		for _, id := range sessionIDs {
			if s.OastID == id {
				foundCount++
				break
			}
		}
	}
	assert.Equal(t, 3, foundCount)
}

// =============================================================================
// Concurrent Access Tests
// =============================================================================

func TestIntegration_ConcurrentOperations(t *testing.T) {
	client := setupIntegrationEnv(t)

	// Get a flow for concurrent replays
	listResp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Method: "GET", Limit: 1})
	require.NoError(t, err)

	if len(listResp.Flows) == 0 {
		t.Skip("no GET requests in proxy history")
	}

	flowID := listResp.Flows[0].FlowID

	t.Run("concurrent_replays", func(t *testing.T) {
		const numConcurrent = 5
		results := make(chan error, numConcurrent)

		for i := 0; i < numConcurrent; i++ {
			go func() {
				_, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{FlowID: flowID})
				results <- err
			}()
		}

		var errors []error
		for i := 0; i < numConcurrent; i++ {
			if err := <-results; err != nil {
				errors = append(errors, err)
			}
		}
		assert.Empty(t, errors)
	})

	t.Run("concurrent_oast_operations", func(t *testing.T) {
		const numSessions = 3
		sessionChan := make(chan string, numSessions)
		errChan := make(chan error, numSessions)

		// Create sessions concurrently
		for i := 0; i < numSessions; i++ {
			go func(idx int) {
				resp, err := client.OastCreate(t.Context(), fmt.Sprintf("concurrent-%d-%d", time.Now().UnixNano(), idx))
				if err != nil {
					errChan <- err
					return
				}
				sessionChan <- resp.OastID
			}(i)
		}

		var sessionIDs []string
		for i := 0; i < numSessions; i++ {
			select {
			case id := <-sessionChan:
				sessionIDs = append(sessionIDs, id)
			case err := <-errChan:
				t.Errorf("concurrent OAST create failed: %v", err)
			}
		}

		// Cleanup
		for _, id := range sessionIDs {
			_ = client.OastDelete(t.Context(), id)
		}
	})
}

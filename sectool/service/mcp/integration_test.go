package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/llm-security-toolbox/sectool/config"
	"github.com/go-appsec/llm-security-toolbox/sectool/service/testutil"
)

// Integration tests for Burp MCP client.
// These tests validate low-level MCP protocol communication with Burp Suite.
// For sectool MCP server tests with mock backends, see sectool/service/mcp_server_test.go.
//
// Skip automatically if Burp is not available or if running with -short flag.

func connectOrSkip(t *testing.T) *BurpClient {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testutil.AcquireBurpLock(t)

	client := New(config.DefaultBurpMCPURL)
	if err := client.Connect(t.Context()); err != nil {
		t.Skipf("Burp MCP not available at %s: %v", config.DefaultBurpMCPURL, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestBurpConnect(t *testing.T) {
	client := connectOrSkip(t)

	assert.True(t, client.IsConnected())
	assert.Equal(t, config.DefaultBurpMCPURL, client.URL())
}

func TestBurpConnectTwice(t *testing.T) {
	client := connectOrSkip(t)

	// Second connect should be no-op
	err := client.Connect(t.Context())
	require.NoError(t, err)
	assert.True(t, client.IsConnected())
}

func TestBurpGetProxyHistory_Empty(t *testing.T) {
	client := connectOrSkip(t)

	// Fetch with moderately high offset to likely get empty results
	// Using 9999 instead of 999999 to avoid potential performance issues with Burp MCP
	entries, err := client.GetProxyHistory(t.Context(), 10, 9999)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestBurpGetProxyHistory_FirstPage(t *testing.T) {
	client := connectOrSkip(t)

	entries, err := client.GetProxyHistory(t.Context(), 5, 0)
	require.NoError(t, err)

	t.Logf("Retrieved %d entries from first page", len(entries))
	for i, entry := range entries {
		// Validate structure
		assert.NotEmpty(t, entry.Request, "entry %d should have request", i)

		// Log first line of request
		firstLine := extractFirstLine(entry.Request)
		t.Logf("  [%d] Request: %s", i, firstLine)

		if entry.Response != "" {
			firstLine = extractFirstLine(entry.Response)
			t.Logf("      Response: %s", firstLine)
		}
	}
}

func TestBurpGetProxyHistory_Pagination(t *testing.T) {
	client := connectOrSkip(t)

	// Fetch first page
	page1, err := client.GetProxyHistory(t.Context(), 3, 0)
	require.NoError(t, err)

	if len(page1) < 3 {
		t.Skipf("Need at least 3 entries in proxy history for pagination test, got %d", len(page1))
	}

	// Fetch second page
	page2, err := client.GetProxyHistory(t.Context(), 3, 3)
	require.NoError(t, err)

	t.Logf("Page 1: %d entries, Page 2: %d entries", len(page1), len(page2))

	// Verify pages are different (by comparing first request lines)
	if len(page2) > 0 {
		assert.NotEqual(t,
			extractFirstLine(page1[0].Request),
			extractFirstLine(page2[0].Request),
			"pagination should return different entries")
	}
}

func TestBurpGetProxyHistoryRaw(t *testing.T) {
	client := connectOrSkip(t)

	raw, err := client.GetProxyHistoryRaw(t.Context(), 2, 0)
	require.NoError(t, err)

	t.Logf("Raw response length: %d bytes", len(raw))

	// Raw should be NDJSON format or end-of-items marker
	if raw != "" && raw != endOfItemsMarker {
		assert.True(t, strings.Contains(raw, `"request"`) || strings.Contains(raw, "Reached end"))
	}
}

func TestBurpGetProxyHistoryRegex_NoMatch(t *testing.T) {
	client := connectOrSkip(t)

	// Use a regex that's unlikely to match anything
	entries, err := client.GetProxyHistoryRegex(t.Context(), "UNLIKELYTOMATCH12345XYZ", 10, 0)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestBurpGetProxyHistoryRegex_MatchHTTP(t *testing.T) {
	client := connectOrSkip(t)

	// Match HTTP requests (very broad pattern)
	entries, err := client.GetProxyHistoryRegex(t.Context(), "HTTP/1\\.[01]", 5, 0)
	require.NoError(t, err)

	t.Logf("Regex matched %d entries", len(entries))
	for i, entry := range entries {
		assert.Contains(t, entry.Request, "HTTP/1", "entry %d should contain HTTP version", i)
	}
}

func TestBurpGetProxyHistoryRegex_MatchHost(t *testing.T) {
	client := connectOrSkip(t)

	// Match Host header
	entries, err := client.GetProxyHistoryRegex(t.Context(), "Host:", 5, 0)
	require.NoError(t, err)

	t.Logf("Host header matched %d entries", len(entries))
}

func TestBurpSetInterceptState(t *testing.T) {
	ctx := t.Context()
	client := connectOrSkip(t)

	// Turn off interception
	err := client.SetInterceptState(ctx, false)
	require.NoError(t, err)

	// Turn it back on (but immediately off to not block user's Burp)
	err = client.SetInterceptState(ctx, true)
	require.NoError(t, err)

	err = client.SetInterceptState(ctx, false)
	require.NoError(t, err)
}

func TestBurpCreateRepeaterTab(t *testing.T) {
	client := connectOrSkip(t)

	params := RepeaterTabParams{
		TabName:        "st-test",
		Content:        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		TargetHostname: "example.com",
		TargetPort:     443,
		UsesHTTPS:      true,
	}
	err := client.CreateRepeaterTab(t.Context(), params)
	require.NoError(t, err)
}

func TestBurpCreateRepeaterTab_HTTP(t *testing.T) {
	client := connectOrSkip(t)

	params := RepeaterTabParams{
		TabName:        "st-http-test",
		Content:        "GET /get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n",
		TargetHostname: "httpbin.org",
		TargetPort:     80,
		UsesHTTPS:      false,
	}
	err := client.CreateRepeaterTab(t.Context(), params)
	require.NoError(t, err)
}

func TestBurpSendHTTP1Request(t *testing.T) {
	client := connectOrSkip(t)

	params := SendRequestParams{
		Content:        "GET /get HTTP/1.1\r\nHost: httpbin.org\r\nUser-Agent: sectool-test\r\nConnection: close\r\n\r\n",
		TargetHostname: "httpbin.org",
		TargetPort:     443,
		UsesHTTPS:      true,
	}
	response, err := client.SendHTTP1Request(t.Context(), params)
	require.NoError(t, err)

	t.Logf("Response length: %d bytes", len(response))
	t.Logf("Response preview: %s", truncate(response, 500))

	// Should have HTTP response
	assert.Contains(t, response, "HTTP/")
}

func TestBurpSendHTTP1Request_HTTP(t *testing.T) {
	client := connectOrSkip(t)

	params := SendRequestParams{
		Content:        "GET /get HTTP/1.1\r\nHost: httpbin.org\r\nUser-Agent: sectool-test\r\nConnection: close\r\n\r\n",
		TargetHostname: "httpbin.org",
		TargetPort:     80,
		UsesHTTPS:      false,
	}

	response, err := client.SendHTTP1Request(t.Context(), params)
	require.NoError(t, err)

	t.Logf("HTTP Response length: %d bytes", len(response))
	assert.Contains(t, response, "HTTP/")
}

func TestBurpSendHTTP1Request_POST(t *testing.T) {
	client := connectOrSkip(t)

	body := `{"test": "data"}`
	params := SendRequestParams{
		Content: "POST /post HTTP/1.1\r\n" +
			"Host: httpbin.org\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: " + itoa(len(body)) + "\r\n" +
			"Connection: close\r\n\r\n" +
			body,
		TargetHostname: "httpbin.org",
		TargetPort:     443,
		UsesHTTPS:      true,
	}

	response, err := client.SendHTTP1Request(t.Context(), params)
	require.NoError(t, err)

	t.Logf("POST Response length: %d bytes", len(response))
	assert.Contains(t, response, "HTTP/")
	// httpbin echoes back the posted data
	assert.Contains(t, response, "test")
}

func TestBurpCloseAndReconnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	testutil.AcquireBurpLock(t)

	client := New(config.DefaultBurpMCPURL)
	if err := client.Connect(t.Context()); err != nil {
		t.Skipf("Burp MCP not available: %v", err)
	}

	assert.True(t, client.IsConnected())

	// Close
	err := client.Close()
	require.NoError(t, err)
	assert.False(t, client.IsConnected())

	// Create new client for reconnection (old client is closed)
	client2 := New(config.DefaultBurpMCPURL)
	t.Cleanup(func() { _ = client2.Close() })

	err = client2.Connect(t.Context())
	require.NoError(t, err)
	assert.True(t, client2.IsConnected())
}

func TestBurpLargeHistoryFetch(t *testing.T) {
	client := connectOrSkip(t)

	// Fetch a larger batch to test buffer handling and JSON sanitization
	entries, err := client.GetProxyHistory(t.Context(), 50, 0)
	require.NoError(t, err)

	t.Logf("Large fetch returned %d entries", len(entries))

	// Validate all entries have structure
	for i, entry := range entries {
		assert.NotEmpty(t, entry.Request, "entry %d should have request", i)
	}
}

func extractFirstLine(s string) string {
	if idx := strings.IndexAny(s, "\r\n"); idx > 0 {
		return s[:idx]
	}
	if len(s) > 100 {
		return s[:100] + "..."
	}
	return s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestBurpSendHTTP2Request(t *testing.T) {
	client := connectOrSkip(t)

	params := SendHTTP2RequestParams{
		PseudoHeaders: map[string]string{
			":method":    "GET",
			":path":      "/get",
			":authority": "httpbin.org",
			":scheme":    "https",
		},
		Headers: map[string]string{
			"User-Agent": "sectool-test",
		},
		TargetHostname: "httpbin.org",
		TargetPort:     443,
		UsesHTTPS:      true,
	}
	response, err := client.SendHTTP2Request(t.Context(), params)
	require.NoError(t, err)

	t.Logf("HTTP/2 Response length: %d bytes", len(response))
	t.Logf("HTTP/2 Response preview: %s", truncate(response, 500))

	// Should have HTTP response
	assert.Contains(t, response, "HTTP/")
}

func TestBurpSendToIntruder(t *testing.T) {
	client := connectOrSkip(t)

	params := IntruderParams{
		TabName:        "st-intruder-test",
		Content:        "GET /get?param=FUZZ HTTP/1.1\r\nHost: httpbin.org\r\n\r\n",
		TargetHostname: "httpbin.org",
		TargetPort:     443,
		UsesHTTPS:      true,
	}
	err := client.SendToIntruder(t.Context(), params)
	require.NoError(t, err)
}

func TestBurpGetProxyWebsocketHistory_Empty(t *testing.T) {
	client := connectOrSkip(t)

	// Fetch with high offset to likely get empty results
	entries, err := client.GetProxyWebsocketHistory(t.Context(), 10, 999999)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestBurpGetProxyWebsocketHistory_FirstPage(t *testing.T) {
	client := connectOrSkip(t)

	entries, err := client.GetProxyWebsocketHistory(t.Context(), 10, 0)
	require.NoError(t, err)

	t.Logf("Retrieved %d WebSocket history entries", len(entries))
	for i, entry := range entries {
		t.Logf("  [%d] %s: %s", i, entry.Direction, truncate(entry.Payload, 100))
	}
}

func TestBurpGetProxyWebsocketHistoryRaw(t *testing.T) {
	client := connectOrSkip(t)

	raw, err := client.GetProxyWebsocketHistoryRaw(t.Context(), 5, 0)
	require.NoError(t, err)

	t.Logf("Raw WebSocket history length: %d bytes", len(raw))
}

func TestBurpGetProxyWebsocketHistoryRegex_NoMatch(t *testing.T) {
	client := connectOrSkip(t)

	entries, err := client.GetProxyWebsocketHistoryRegex(t.Context(), "UNLIKELYTOMATCH12345XYZ", 10, 0)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestBurpSetTaskExecutionEngineState(t *testing.T) {
	ctx := t.Context()
	client := connectOrSkip(t)

	// Pause the engine (running=false)
	err := client.SetTaskExecutionEngineState(ctx, false)
	require.NoError(t, err)

	// Resume immediately (running=true)
	err = client.SetTaskExecutionEngineState(ctx, true)
	require.NoError(t, err)
}

func TestBurpGetActiveEditorContents(t *testing.T) {
	client := connectOrSkip(t)

	// This may return empty or error if no editor is active
	contents, err := client.GetActiveEditorContents(t.Context())
	if err != nil {
		t.Logf("GetActiveEditorContents returned error (expected if no editor active): %v", err)
		return
	}

	t.Logf("Active editor contents length: %d bytes", len(contents))
	if contents != "" {
		t.Logf("Contents preview: %s", truncate(contents, 200))
	}
}

func TestBurpSetActiveEditorContents(t *testing.T) {
	client := connectOrSkip(t)

	// This may fail if no editor is active
	testContent := "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"
	err := client.SetActiveEditorContents(t.Context(), testContent)
	if err != nil {
		t.Logf("SetActiveEditorContents returned error (expected if no editor active): %v", err)
		return
	}

	t.Log("SetActiveEditorContents succeeded")
}

func TestBurpGetMatchReplaceRules(t *testing.T) {
	client := connectOrSkip(t)

	rules, err := client.GetMatchReplaceRules(t.Context())
	require.NoError(t, err)

	t.Logf("Retrieved %d HTTP match/replace rules", len(rules))
	for i, rule := range rules {
		t.Logf("  [%d] type=%s enabled=%v comment=%q match=%q replace=%q",
			i, rule.RuleType, rule.Enabled, rule.Comment,
			truncate(rule.StringMatch, 50), truncate(rule.StringReplace, 50))
	}
}

func TestBurpGetWSMatchReplaceRules(t *testing.T) {
	client := connectOrSkip(t)

	rules, err := client.GetWSMatchReplaceRules(t.Context())
	require.NoError(t, err)

	t.Logf("Retrieved %d WebSocket match/replace rules", len(rules))
	for i, rule := range rules {
		t.Logf("  [%d] type=%s enabled=%v comment=%q",
			i, rule.RuleType, rule.Enabled, rule.Comment)
	}
}

func TestBurpSetMatchReplaceRules(t *testing.T) {
	t.Skip("tests only work if burp allows config edits")

	t.Run("add_remove", func(t *testing.T) {
		ctx := t.Context()
		client := connectOrSkip(t)

		// Get original rules to restore later
		original, err := client.GetMatchReplaceRules(ctx)
		require.NoError(t, err)
		t.Cleanup(func() {
			// Restore original rules
			_ = client.SetMatchReplaceRules(context.Background(), original)
		})

		// Add a test rule
		testRule := MatchReplaceRule{
			Category:      RuleCategoryLiteral,
			Comment:       "sectool:mcp-integration-test",
			Enabled:       true,
			RuleType:      RuleTypeRequestHeader,
			StringMatch:   "",
			StringReplace: "X-Sectool-MCP-Test: integration",
		}
		newRules := append([]MatchReplaceRule{testRule}, original...)

		err = client.SetMatchReplaceRules(ctx, newRules)
		require.NoError(t, err)

		// Verify the rule was added
		updated, err := client.GetMatchReplaceRules(ctx)
		require.NoError(t, err)

		var found bool
		for _, r := range updated {
			if r.Comment == "sectool:mcp-integration-test" {
				found = true
				assert.Equal(t, "X-Sectool-MCP-Test: integration", r.StringReplace)
				assert.True(t, r.Enabled)
				break
			}
		}
		assert.True(t, found, "test rule should be present")
		t.Log("Successfully added and verified test rule")
	})

	t.Run("regex_rule", func(t *testing.T) {
		ctx := t.Context()
		client := connectOrSkip(t)

		original, err := client.GetMatchReplaceRules(ctx)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = client.SetMatchReplaceRules(context.Background(), original)
		})

		// Add a regex rule
		testRule := MatchReplaceRule{
			Category:      RuleCategoryRegex,
			Comment:       "sectool:mcp-regex-test",
			Enabled:       true,
			RuleType:      RuleTypeRequestHeader,
			StringMatch:   "^X-Test-Header:.*$",
			StringReplace: "X-Test-Header: replaced",
		}
		newRules := append([]MatchReplaceRule{testRule}, original...)

		err = client.SetMatchReplaceRules(ctx, newRules)
		require.NoError(t, err)

		updated, err := client.GetMatchReplaceRules(ctx)
		require.NoError(t, err)

		var found bool
		for _, r := range updated {
			if r.Comment == "sectool:mcp-regex-test" {
				found = true
				assert.Equal(t, RuleCategoryRegex, r.Category)
				assert.Equal(t, "^X-Test-Header:.*$", r.StringMatch)
				break
			}
		}
		assert.True(t, found, "regex test rule should be present")
		t.Log("Successfully added regex rule")
	})

	t.Run("all_rule_types", func(t *testing.T) {
		ctx := t.Context()
		client := connectOrSkip(t)

		original, err := client.GetMatchReplaceRules(ctx)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = client.SetMatchReplaceRules(context.Background(), original)
		})

		// Test rule types that Burp MCP actually supports
		ruleTypes := []string{
			RuleTypeRequestHeader,
			RuleTypeRequestBody,
			RuleTypeResponseHeader,
			RuleTypeResponseBody,
		}

		testRules := make([]MatchReplaceRule, 0, len(ruleTypes))
		for _, rt := range ruleTypes {
			testRules = append(testRules, MatchReplaceRule{
				Category:      RuleCategoryLiteral,
				Comment:       "sectool:type-test-" + rt,
				Enabled:       false, // Disabled for safety
				RuleType:      rt,
				StringMatch:   "match-" + rt,
				StringReplace: "replace-" + rt,
			})
		}
		newRules := append(testRules, original...)

		err = client.SetMatchReplaceRules(ctx, newRules)
		require.NoError(t, err)

		updated, err := client.GetMatchReplaceRules(ctx)
		require.NoError(t, err)

		// Verify rule types were added
		foundTypes := make(map[string]bool)
		for _, r := range updated {
			if strings.HasPrefix(r.Comment, "sectool:type-test-") {
				foundTypes[r.RuleType] = true
			}
		}

		for _, rt := range ruleTypes {
			assert.True(t, foundTypes[rt], "rule type %s should be present", rt)
		}
		t.Logf("Successfully added %d rule types", len(ruleTypes))
	})
}

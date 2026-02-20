package service

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

func TestMCP_CrawlLifecycleWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, mockCrawler := setupMockMCPServer(t)

	createResult := CallMCPTool(t, mcpClient, "crawl_create", map[string]interface{}{
		"seed_urls": "https://example.com",
		"label":     "mock-crawl",
	})
	require.False(t, createResult.IsError,
		"crawl_create failed: %s", ExtractMCPText(t, createResult))

	var createResp protocol.CrawlCreateResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, createResult)), &createResp))
	require.NotEmpty(t, createResp.SessionID)

	flowID := "flow-1"
	req := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok")
	err := mockCrawler.AddFlow(createResp.SessionID, CrawlFlow{
		ID:             flowID,
		SessionID:      createResp.SessionID,
		URL:            "https://example.com/",
		Host:           "example.com",
		Path:           "/",
		Method:         "GET",
		StatusCode:     200,
		ResponseLength: 2,
		Request:        req,
		Response:       resp,
		Duration:       10 * time.Millisecond,
		DiscoveredAt:   time.Now(),
	})
	require.NoError(t, err)

	form := DiscoveredForm{
		ID:        "form-1",
		SessionID: createResp.SessionID,
		URL:       "https://example.com/login",
		Action:    "https://example.com/login",
		Method:    "POST",
		Inputs: []FormInput{
			{Name: "username", Type: "text"},
		},
		HasCSRF: true,
	}
	require.NoError(t, mockCrawler.AddForm(createResp.SessionID, form))

	crawlErr := CrawlError{
		FlowID: flowID,
		URL:    "https://example.com/bad",
		Error:  "boom",
		Status: 500,
	}
	require.NoError(t, mockCrawler.AddError(createResp.SessionID, crawlErr))

	statusResult := CallMCPTool(t, mcpClient, "crawl_status", map[string]interface{}{
		"session_id": createResp.SessionID,
	})
	require.False(t, statusResult.IsError,
		"crawl_status failed: %s", ExtractMCPText(t, statusResult))
	var statusResp protocol.CrawlStatusResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, statusResult)), &statusResp))
	assert.Equal(t, "running", statusResp.State)

	summaryResult := CallMCPTool(t, mcpClient, "crawl_poll", map[string]interface{}{
		"session_id": createResp.SessionID,
	})
	require.False(t, summaryResult.IsError,
		"crawl_poll failed: %s", ExtractMCPText(t, summaryResult))
	var summaryResp protocol.CrawlPollResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, summaryResult)), &summaryResp))
	require.NotEmpty(t, summaryResp.Aggregates)
	assert.Equal(t, "example.com", summaryResp.Aggregates[0].Host)
	assert.Equal(t, "/", summaryResp.Aggregates[0].Path)
	assert.Equal(t, "GET", summaryResp.Aggregates[0].Method)
	assert.Equal(t, 200, summaryResp.Aggregates[0].Status)

	listResult := CallMCPTool(t, mcpClient, "crawl_poll", map[string]interface{}{
		"session_id":  createResp.SessionID,
		"output_mode": "flows",
	})
	require.False(t, listResult.IsError,
		"crawl_poll failed: %s", ExtractMCPText(t, listResult))
	var listResp protocol.CrawlPollResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, listResult)), &listResp))
	require.NotEmpty(t, listResp.Flows)
	assert.Equal(t, flowID, listResp.Flows[0].FlowID)

	getResult := CallMCPTool(t, mcpClient, "flow_get", map[string]interface{}{
		"flow_id": flowID,
	})
	require.False(t, getResult.IsError,
		"flow_get failed: %s", ExtractMCPText(t, getResult))
	var getResp protocol.FlowGetResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, getResult)), &getResp))
	assert.Equal(t, flowID, getResp.FlowID)
	assert.Equal(t, 200, getResp.Status)

	formsResult := CallMCPTool(t, mcpClient, "crawl_poll", map[string]interface{}{
		"session_id":  createResp.SessionID,
		"output_mode": "forms",
	})
	require.False(t, formsResult.IsError,
		"crawl_poll failed: %s", ExtractMCPText(t, formsResult))
	var formsResp protocol.CrawlPollResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, formsResult)), &formsResp))
	require.NotEmpty(t, formsResp.Forms)

	errorsResult := CallMCPTool(t, mcpClient, "crawl_poll", map[string]interface{}{
		"session_id":  createResp.SessionID,
		"output_mode": "errors",
	})
	require.False(t, errorsResult.IsError,
		"crawl_poll failed: %s", ExtractMCPText(t, errorsResult))
	var errorsResp protocol.CrawlPollResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, errorsResult)), &errorsResp))
	require.NotEmpty(t, errorsResp.Errors)

	sessionsResult := CallMCPTool(t, mcpClient, "crawl_sessions", nil)
	require.False(t, sessionsResult.IsError,
		"crawl_sessions failed: %s", ExtractMCPText(t, sessionsResult))
	var sessionsResp protocol.CrawlSessionsResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, sessionsResult)), &sessionsResp))
	require.NotEmpty(t, sessionsResp.Sessions)

	// Test crawl_poll with filters
	listWithHostResult := CallMCPTool(t, mcpClient, "crawl_poll", map[string]interface{}{
		"session_id":  createResp.SessionID,
		"output_mode": "flows",
		"host":        "example.com",
	})
	require.False(t, listWithHostResult.IsError,
		"crawl_poll failed: %s", ExtractMCPText(t, listWithHostResult))
	var hostResp protocol.CrawlPollResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, listWithHostResult)), &hostResp))
	for _, flow := range hostResp.Flows {
		assert.Equal(t, "example.com", flow.Host)
	}

	listWithPathResult := CallMCPTool(t, mcpClient, "crawl_poll", map[string]interface{}{
		"session_id":  createResp.SessionID,
		"output_mode": "flows",
		"path":        "/*",
	})
	require.False(t, listWithPathResult.IsError,
		"crawl_poll failed: %s", ExtractMCPText(t, listWithPathResult))

	listWithMethodResult := CallMCPTool(t, mcpClient, "crawl_poll", map[string]interface{}{
		"session_id":  createResp.SessionID,
		"output_mode": "flows",
		"method":      "GET",
	})
	require.False(t, listWithMethodResult.IsError,
		"crawl_poll failed: %s", ExtractMCPText(t, listWithMethodResult))
	var methodResp protocol.CrawlPollResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, listWithMethodResult)), &methodResp))
	for _, flow := range methodResp.Flows {
		assert.Equal(t, "GET", flow.Method)
	}

	listWithStatusResult := CallMCPTool(t, mcpClient, "crawl_poll", map[string]interface{}{
		"session_id":  createResp.SessionID,
		"output_mode": "flows",
		"status":      "200",
	})
	require.False(t, listWithStatusResult.IsError,
		"crawl_poll failed: %s", ExtractMCPText(t, listWithStatusResult))
	var statusFilterResp protocol.CrawlPollResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, listWithStatusResult)), &statusFilterResp))
	for _, flow := range statusFilterResp.Flows {
		assert.Equal(t, 200, flow.Status)
	}

	listWithExcludeResult := CallMCPTool(t, mcpClient, "crawl_poll", map[string]interface{}{
		"session_id":   createResp.SessionID,
		"output_mode":  "flows",
		"exclude_host": "other.com",
	})
	require.False(t, listWithExcludeResult.IsError,
		"crawl_poll failed: %s", ExtractMCPText(t, listWithExcludeResult))
	var excludeResp protocol.CrawlPollResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, listWithExcludeResult)), &excludeResp))
	for _, flow := range excludeResp.Flows {
		assert.NotEqual(t, "other.com", flow.Host)
	}

	stopResult := CallMCPTool(t, mcpClient, "crawl_stop", map[string]interface{}{
		"session_id": createResp.SessionID,
	})
	require.False(t, stopResult.IsError,
		"crawl_stop failed: %s", ExtractMCPText(t, stopResult))
	var stopResp CrawlStopResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, stopResult)), &stopResp))
	assert.True(t, stopResp.Stopped)
}

func TestMCP_CrawlSeedWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, mockCrawler := setupMockMCPServer(t)

	createResult := CallMCPTool(t, mcpClient, "crawl_create", map[string]interface{}{
		"seed_urls": "https://example.com",
	})
	require.False(t, createResult.IsError,
		"crawl_create failed: %s", ExtractMCPText(t, createResult))

	var createResp protocol.CrawlCreateResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, createResult)), &createResp))

	statusBefore, err := mockCrawler.GetStatus(t.Context(), createResp.SessionID)
	require.NoError(t, err)
	queuedBefore := statusBefore.URLsQueued

	seedResult := CallMCPTool(t, mcpClient, "crawl_seed", map[string]interface{}{
		"session_id": createResp.SessionID,
		"seed_urls":  "https://example.com/page1,https://example.com/page2",
	})
	require.False(t, seedResult.IsError,
		"crawl_seed failed: %s", ExtractMCPText(t, seedResult))

	statusAfter, err := mockCrawler.GetStatus(t.Context(), createResp.SessionID)
	require.NoError(t, err)
	assert.Equal(t, queuedBefore+2, statusAfter.URLsQueued)
}

func TestMCP_FlowGetDecompressesGzipBody(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, mockCrawler := setupMockMCPServer(t)

	// Create crawl session
	createResp := CallMCPToolJSONOK[protocol.CrawlCreateResponse](t, mcpClient, "crawl_create", map[string]interface{}{
		"seed_urls": "https://example.com",
	})

	// Create gzip compressed response body
	const originalBody = "This is the decompressed crawl response"
	compressedBody := compressGzip(t, []byte(originalBody))

	const respHeaders = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\n\r\n"

	const flowID = "crawl-compressed-flow"
	err := mockCrawler.AddFlow(createResp.SessionID, CrawlFlow{
		ID:             flowID,
		SessionID:      createResp.SessionID,
		URL:            "https://example.com/compressed",
		Host:           "example.com",
		Path:           "/compressed",
		Method:         "GET",
		StatusCode:     200,
		ResponseLength: len(compressedBody),
		Request:        []byte("GET /compressed HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Response:       append([]byte(respHeaders), compressedBody...),
	})
	require.NoError(t, err)

	// Test full_body=true returns decompressed content
	getResult := CallMCPTool(t, mcpClient, "flow_get", map[string]interface{}{
		"flow_id":   flowID,
		"full_body": true,
	})
	require.False(t, getResult.IsError)

	var getResp protocol.FlowGetResponse
	require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, getResult)), &getResp))

	// Decode base64 body and verify it's decompressed
	decodedBody, err := base64.StdEncoding.DecodeString(getResp.RespBody)
	require.NoError(t, err)
	assert.Equal(t, originalBody, string(decodedBody))
}

func TestMCP_CrawlValidation(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, mockCrawler := setupMockMCPServer(t)

	t.Run("create_missing_seeds", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "crawl_create", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "seed")
	})

	t.Run("create_duplicate_label", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "crawl_create", map[string]interface{}{
			"seed_urls": "https://example.com",
			"label":     "dupe-label",
		})
		require.False(t, result.IsError,
			"crawl_create failed: %s", ExtractMCPText(t, result))

		result = CallMCPTool(t, mcpClient, "crawl_create", map[string]interface{}{
			"seed_urls": "https://example.com",
			"label":     "dupe-label",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "label")
	})

	t.Run("status_missing_session_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "crawl_status", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "session_id is required")
	})

	t.Run("status_invalid_session_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "crawl_status", map[string]interface{}{
			"session_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "not found")
	})

	t.Run("summary_missing_session_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "crawl_poll", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "session_id is required")
	})

	t.Run("list_missing_session_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "crawl_poll", map[string]interface{}{
			"output_mode": "flows",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "session_id is required")
	})

	t.Run("defaults_to_summary", func(t *testing.T) {
		createResult := CallMCPTool(t, mcpClient, "crawl_create", map[string]interface{}{
			"seed_urls": "https://example.com",
		})
		require.False(t, createResult.IsError,
			"crawl_create failed: %s", ExtractMCPText(t, createResult))
		var createResp protocol.CrawlCreateResponse
		require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, createResult)), &createResp))

		result := CallMCPTool(t, mcpClient, "crawl_poll", map[string]interface{}{
			"session_id": createResp.SessionID,
		})
		require.False(t, result.IsError,
			"crawl_poll failed: %s", ExtractMCPText(t, result))

		var pollResp protocol.CrawlPollResponse
		require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, result)), &pollResp))
		// Default mode is summary - should have state/duration, not forms/errors
		assert.NotEmpty(t, pollResp.State)
		assert.Nil(t, pollResp.Forms)
		assert.Nil(t, pollResp.Errors)
	})

	t.Run("summary_invalid_session_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "crawl_poll", map[string]interface{}{
			"session_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "not found")
	})

	t.Run("sessions_with_limit", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "crawl_sessions", map[string]interface{}{
			"limit": 1,
		})
		require.False(t, result.IsError,
			"crawl_sessions failed: %s", ExtractMCPText(t, result))

		var resp protocol.CrawlSessionsResponse
		require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, result)), &resp))
		assert.LessOrEqual(t, len(resp.Sessions), 1)
	})

	t.Run("get_missing_flow_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "flow_get", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "flow_id is required")
	})

	t.Run("get_invalid_flow_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "flow_get", map[string]interface{}{
			"flow_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "not found")
	})

	t.Run("stop_missing_session_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "crawl_stop", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "session_id is required")
	})

	t.Run("stop_invalid_session_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "crawl_stop", map[string]interface{}{
			"session_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "not found")
	})

	t.Run("seed_missing_session_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "crawl_seed", map[string]interface{}{
			"seed_urls": "https://example.com/new",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "session_id is required")
	})

	t.Run("seed_stopped_session", func(t *testing.T) {
		createResult := CallMCPTool(t, mcpClient, "crawl_create", map[string]interface{}{
			"seed_urls": "https://example.com",
		})
		require.False(t, createResult.IsError,
			"crawl_create failed: %s", ExtractMCPText(t, createResult))
		var createResp protocol.CrawlCreateResponse
		require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, createResult)), &createResp))

		require.NoError(t, mockCrawler.StopSession(t.Context(), createResp.SessionID))

		result := CallMCPTool(t, mcpClient, "crawl_seed", map[string]interface{}{
			"session_id": createResp.SessionID,
			"seed_urls":  "https://example.com/new",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "not running")
	})
}

func TestMCP_CrawlPollSearch(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, mockCrawler := setupMockMCPServer(t)

	createResp := CallMCPToolJSONOK[protocol.CrawlCreateResponse](t, mcpClient, "crawl_create", map[string]interface{}{
		"seed_urls": "https://example.com",
	})

	// Add a flow with searchable content
	require.NoError(t, mockCrawler.AddFlow(createResp.SessionID, CrawlFlow{
		ID:         "search-flow",
		SessionID:  createResp.SessionID,
		URL:        "https://example.com/api",
		Host:       "example.com",
		Path:       "/api",
		Method:     "GET",
		StatusCode: 200,
		Request:    []byte("GET /api HTTP/1.1\r\nHost: example.com\r\nX-Token: secret123\r\n\r\n"),
		Response:   []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nfound_keyword_here"),
		Duration:   5 * time.Millisecond,
	}))

	t.Run("search_header_regex", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.CrawlPollResponse](t, mcpClient, "crawl_poll", map[string]interface{}{
			"session_id":    createResp.SessionID,
			"output_mode":   "flows",
			"search_header": "X-Token:\\s+secret.*",
		})
		require.NotEmpty(t, resp.Flows)
		assert.Equal(t, "search-flow", resp.Flows[0].FlowID)
	})

	t.Run("search_body", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.CrawlPollResponse](t, mcpClient, "crawl_poll", map[string]interface{}{
			"session_id":  createResp.SessionID,
			"output_mode": "flows",
			"search_body": "found_keyword",
		})
		require.NotEmpty(t, resp.Flows)
	})

	t.Run("search_no_match", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.CrawlPollResponse](t, mcpClient, "crawl_poll", map[string]interface{}{
			"session_id":  createResp.SessionID,
			"output_mode": "flows",
			"search_body": "NONEXISTENT_xyz",
		})
		assert.Empty(t, resp.Flows)
	})

	t.Run("search_fallback_note", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.CrawlPollResponse](t, mcpClient, "crawl_poll", map[string]interface{}{
			"session_id":    createResp.SessionID,
			"output_mode":   "flows",
			"search_header": "[invalid",
		})
		assert.NotEmpty(t, resp.Note)
		assert.Contains(t, resp.Note, "treated as literal")
	})
}

func TestMCP_FlowGetWithCrawlScope(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, mockCrawler := setupMockMCPServer(t)

	createResp := CallMCPToolJSONOK[protocol.CrawlCreateResponse](t, mcpClient, "crawl_create", map[string]interface{}{
		"seed_urls": "https://example.com",
	})

	require.NoError(t, mockCrawler.AddFlow(createResp.SessionID, CrawlFlow{
		ID:         "scope-flow",
		SessionID:  createResp.SessionID,
		URL:        "https://example.com/scoped",
		Host:       "example.com",
		Path:       "/scoped",
		Method:     "GET",
		StatusCode: 200,
		Request:    []byte("GET /scoped HTTP/1.1\r\nHost: example.com\r\n\r\nreq body"),
		Response:   []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nresp body content"),
		Duration:   5 * time.Millisecond,
	}))

	t.Run("response_body_only", func(t *testing.T) {
		var raw map[string]interface{}
		text := CallMCPToolTextOK(t, mcpClient, "flow_get", map[string]interface{}{
			"flow_id": "scope-flow",
			"scope":   "response_body",
		})
		require.NoError(t, json.Unmarshal([]byte(text), &raw))
		assert.Contains(t, raw, "response_body")
		assert.NotContains(t, raw, "request_headers")
		assert.Contains(t, raw, "flow_id")
	})

	t.Run("pattern_matches", func(t *testing.T) {
		var raw map[string]interface{}
		text := CallMCPToolTextOK(t, mcpClient, "flow_get", map[string]interface{}{
			"flow_id": "scope-flow",
			"scope":   "response_body",
			"pattern": "resp.*content",
		})
		require.NoError(t, json.Unmarshal([]byte(text), &raw))
		assert.Contains(t, raw, "response_body")
		respBody, ok := raw["response_body"].(string)
		require.True(t, ok)
		assert.Contains(t, respBody, "resp body content")
	})

	t.Run("pattern_no_match_omits", func(t *testing.T) {
		var raw map[string]interface{}
		text := CallMCPToolTextOK(t, mcpClient, "flow_get", map[string]interface{}{
			"flow_id": "scope-flow",
			"scope":   "response_body",
			"pattern": "NONEXISTENT_xyz",
		})
		require.NoError(t, json.Unmarshal([]byte(text), &raw))
		assert.NotContains(t, raw, "response_body")
	})
}

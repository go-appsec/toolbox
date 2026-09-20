package service

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

func TestMCP_CrawlLifecycleWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, mockCrawler := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

	createResp := CallMCPToolJSONOK[protocol.CrawlCreateResponse](t, mcpClient, "crawl_create", map[string]interface{}{
		"seed_urls": "https://example.com",
		"label":     "mock-crawl",
	})
	require.NotEmpty(t, createResp.SessionID)
	sid := createResp.SessionID

	// Deterministic fixture: 5 flows (/, /page/0..2, /missing), one form, one error.
	require.NoError(t, mockCrawler.AddFlow(sid, store.CrawlFlow{
		ID: "flow-1", SessionID: sid, URL: "https://example.com/", Host: "example.com", Path: "/",
		Method: "GET", StatusCode: 200, ResponseLength: 2,
		Request:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Response: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"),
		Duration: 10 * time.Millisecond, DiscoveredAt: time.Now(),
	}))
	for i := range 3 {
		require.NoError(t, mockCrawler.AddFlow(sid, store.CrawlFlow{
			ID: fmt.Sprintf("flow-page-%d", i), SessionID: sid,
			URL: fmt.Sprintf("https://example.com/page/%d", i), Host: "example.com",
			Path: fmt.Sprintf("/page/%d", i), Method: "GET", StatusCode: 200,
			Request:  []byte(fmt.Sprintf("GET /page/%d HTTP/1.1\r\nHost: example.com\r\n\r\n", i)),
			Response: []byte("HTTP/1.1 200 OK\r\n\r\nok"),
		}))
	}
	require.NoError(t, mockCrawler.AddFlow(sid, store.CrawlFlow{
		ID: "flow-404", SessionID: sid, URL: "https://example.com/missing", Host: "example.com",
		Path: "/missing", Method: "GET", StatusCode: 404,
		Request:  []byte("GET /missing HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Response: []byte("HTTP/1.1 404 Not Found\r\n\r\nnot found"),
	}))
	require.NoError(t, mockCrawler.AddForm(sid, protocol.CrawlForm{
		FormID: "form-1", URL: "https://example.com/login", Action: "https://example.com/login",
		Method: "POST", Inputs: []protocol.FormInput{{Name: "username", Type: "text"}}, HasCSRF: true,
	}))
	require.NoError(t, mockCrawler.AddError(sid, protocol.CrawlError{
		URL: "https://example.com/bad", Error: "boom", Status: 500,
	}))

	t.Run("status_running", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.CrawlStatusResponse](t, mcpClient, "crawl_status", map[string]interface{}{
			"session_id": sid,
		})
		assert.Equal(t, "running", resp.State)
	})

	t.Run("summary_aggregates", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.CrawlPollResponse](t, mcpClient, "crawl_poll", map[string]interface{}{
			"session_id": sid,
		})
		require.Len(t, resp.Aggregates, 3) // /page/0..2 collapse into one /page/* row
		i := slices.IndexFunc(resp.Aggregates, func(a protocol.SummaryEntry) bool { return a.Path == "/" })
		require.GreaterOrEqual(t, i, 0)
		assert.Equal(t, "example.com", resp.Aggregates[i].Host)
		assert.Equal(t, "GET", resp.Aggregates[i].Method)
		assert.Equal(t, 200, resp.Aggregates[i].Status)
	})

	t.Run("flows_returns_seeded", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.CrawlPollResponse](t, mcpClient, "crawl_poll", map[string]interface{}{
			"session_id":  sid,
			"output_mode": "flows",
		})
		require.Len(t, resp.Flows, 5)
		assert.True(t, slices.ContainsFunc(resp.Flows, func(f protocol.CrawlFlow) bool { return f.FlowID == "flow-1" }))
	})

	t.Run("flow_get_crawl_flow", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.FlowGetResponse](t, mcpClient, "flow_get", map[string]interface{}{
			"flow_id": "flow-1",
		})
		assert.Equal(t, "flow-1", resp.FlowID)
		assert.Equal(t, 200, resp.Status)
	})

	t.Run("forms", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.CrawlPollResponse](t, mcpClient, "crawl_poll", map[string]interface{}{
			"session_id":  sid,
			"output_mode": "forms",
		})
		require.Len(t, resp.Forms, 1)
		assert.Equal(t, "form-1", resp.Forms[0].FormID)
		assert.Equal(t, "POST", resp.Forms[0].Method)
		assert.True(t, resp.Forms[0].HasCSRF)
		require.Len(t, resp.Forms[0].Inputs, 1)
		assert.Equal(t, "username", resp.Forms[0].Inputs[0].Name)
	})

	t.Run("errors", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.CrawlPollResponse](t, mcpClient, "crawl_poll", map[string]interface{}{
			"session_id":  sid,
			"output_mode": "errors",
		})
		require.Len(t, resp.Errors, 1)
		assert.Equal(t, "https://example.com/bad", resp.Errors[0].URL)
		assert.Equal(t, "boom", resp.Errors[0].Error)
		assert.Equal(t, 500, resp.Errors[0].Status)
	})

	t.Run("sessions_lists_created", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.CrawlSessionsResponse](t, mcpClient, "crawl_sessions", nil)
		assert.True(t, slices.ContainsFunc(resp.Sessions, func(s protocol.CrawlSession) bool { return s.SessionID == sid }))
	})

	t.Run("summary_limit", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.CrawlPollResponse](t, mcpClient, "crawl_poll", map[string]interface{}{
			"session_id": sid,
			"limit":      2,
		})
		assert.Len(t, resp.Aggregates, 2)
		assert.Equal(t, 3, resp.TotalCount) // total aggregates before truncation
	})

	t.Run("flows_pagination", func(t *testing.T) {
		// 5 flows total; limit=2 leaves 3 remaining.
		page := CallMCPToolJSONOK[protocol.CrawlPollResponse](t, mcpClient, "crawl_poll", map[string]interface{}{
			"session_id": sid, "output_mode": "flows", "limit": 2,
		})
		assert.Len(t, page.Flows, 2)
		assert.Equal(t, 3, page.RemainingCount)

		// offset consumes matches before the page: 5 - 1 - 2 = 2 remaining.
		offset := CallMCPToolJSONOK[protocol.CrawlPollResponse](t, mcpClient, "crawl_poll", map[string]interface{}{
			"session_id": sid, "output_mode": "flows", "limit": 2, "offset": 1,
		})
		assert.Len(t, offset.Flows, 2)
		assert.Equal(t, 2, offset.RemainingCount)

		// limit past the match count: nothing remaining.
		full := CallMCPToolJSONOK[protocol.CrawlPollResponse](t, mcpClient, "crawl_poll", map[string]interface{}{
			"session_id": sid, "output_mode": "flows", "limit": 10,
		})
		assert.Len(t, full.Flows, 5)
		assert.Zero(t, full.RemainingCount)
	})

	t.Run("stop", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.CrawlStopResponse](t, mcpClient, "crawl_stop", map[string]interface{}{
			"session_id": sid,
		})
		assert.True(t, resp.Stopped)
	})
}

func TestMCP_CrawlSeedWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, mockCrawler := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

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

func TestMCP_CrawlCreateOptions(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, mockCrawler := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

	create := func(t *testing.T, args map[string]interface{}) CrawlOptions {
		t.Helper()
		args["seed_urls"] = "https://example.com"
		result := CallMCPTool(t, mcpClient, "crawl_create", args)
		require.False(t, result.IsError,
			"crawl_create failed: %s", ExtractMCPText(t, result))
		return mockCrawler.lastOpts
	}

	t.Run("limits_passed_through", func(t *testing.T) {
		opts := create(t, map[string]interface{}{"max_depth": -1, "max_requests": 50})
		assert.Equal(t, -1, opts.MaxDepth)
		assert.Equal(t, 50, opts.MaxRequests)
	})

	t.Run("limits_unset_for_config", func(t *testing.T) {
		opts := create(t, map[string]interface{}{})
		assert.Zero(t, opts.MaxDepth)
		assert.Zero(t, opts.MaxRequests)
	})

	t.Run("submit_forms_unset", func(t *testing.T) {
		opts := create(t, map[string]interface{}{})
		assert.Nil(t, opts.SubmitForms)
	})

	t.Run("submit_forms_explicit", func(t *testing.T) {
		for _, want := range []bool{true, false} {
			opts := create(t, map[string]interface{}{"submit_forms": want})
			require.NotNil(t, opts.SubmitForms)
			assert.Equal(t, want, *opts.SubmitForms)
		}
	})

	t.Run("headers_unset", func(t *testing.T) {
		opts := create(t, map[string]interface{}{})
		assert.Nil(t, opts.Headers)
	})

	t.Run("headers_object", func(t *testing.T) {
		opts := create(t, map[string]interface{}{
			"headers": map[string]interface{}{"Authorization": "Bearer t", "X-Env": "test"},
		})
		assert.Equal(t, map[string]string{"Authorization": "Bearer t", "X-Env": "test"}, opts.Headers)
	})

	t.Run("headers_array", func(t *testing.T) {
		opts := create(t, map[string]interface{}{
			"headers": []interface{}{"Authorization: Bearer t"},
		})
		assert.Equal(t, map[string]string{"Authorization": "Bearer t"}, opts.Headers)
	})
}

func TestMCP_CrawlValidation(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, mockCrawler := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

	t.Run("guard_clauses", func(t *testing.T) {
		cases := []struct {
			name string
			tool string
			args map[string]interface{}
			want string
		}{
			{"create_missing_seeds", "crawl_create", map[string]interface{}{}, "seed"},
			{"status_missing_session", "crawl_status", map[string]interface{}{}, "session_id is required"},
			{"status_not_found", "crawl_status", map[string]interface{}{"session_id": "nonexistent"}, "not found"},
			{"poll_missing_session", "crawl_poll", map[string]interface{}{}, "session_id is required"},
			{"poll_flows_missing_session", "crawl_poll", map[string]interface{}{"output_mode": "flows"}, "session_id is required"},
			{"poll_not_found", "crawl_poll", map[string]interface{}{"session_id": "nonexistent"}, "not found"},
			{"stop_missing_session", "crawl_stop", map[string]interface{}{}, "session_id is required"},
			{"stop_not_found", "crawl_stop", map[string]interface{}{"session_id": "nonexistent"}, "not found"},
			{"seed_missing_session", "crawl_seed", map[string]interface{}{"seed_urls": "https://example.com/new"}, "session_id is required"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				result := CallMCPTool(t, mcpClient, tc.tool, tc.args)
				assert.True(t, result.IsError)
				assert.Contains(t, ExtractMCPText(t, result), tc.want)
			})
		}
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

	t.Run("unknown_output_mode_notes_fallback", func(t *testing.T) {
		createResult := CallMCPTool(t, mcpClient, "crawl_create", map[string]interface{}{
			"seed_urls": "https://example.com",
		})
		require.False(t, createResult.IsError,
			"crawl_create failed: %s", ExtractMCPText(t, createResult))
		var createResp protocol.CrawlCreateResponse
		require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, createResult)), &createResp))

		result := CallMCPTool(t, mcpClient, "crawl_poll", map[string]interface{}{
			"session_id":  createResp.SessionID,
			"output_mode": "form",
		})
		require.False(t, result.IsError,
			"crawl_poll failed: %s", ExtractMCPText(t, result))

		var pollResp protocol.CrawlPollResponse
		require.NoError(t, json.Unmarshal([]byte(ExtractMCPText(t, result)), &pollResp))
		assert.NotEmpty(t, pollResp.State)
		// exact wording is owned by TestNormalizeOutputMode; here just confirm it propagates
		assert.Contains(t, pollResp.Note, "unknown output_mode")
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

	_, mcpClient, _, _, mockCrawler := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

	createResp := CallMCPToolJSONOK[protocol.CrawlCreateResponse](t, mcpClient, "crawl_create", map[string]interface{}{
		"seed_urls": "https://example.com",
	})

	// Add a flow with searchable content
	require.NoError(t, mockCrawler.AddFlow(createResp.SessionID, store.CrawlFlow{
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

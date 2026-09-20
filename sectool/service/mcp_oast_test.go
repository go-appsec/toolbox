package service

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

func TestMCP_OastLifecycleWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, mockOast, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

	var oastID string

	t.Run("create", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.OastCreateResponse](t, mcpClient, "oast_create", map[string]interface{}{
			"label": "mock-oast-test",
		})

		assert.NotEmpty(t, resp.OastID)
		assert.NotEmpty(t, resp.Domain)
		assert.Equal(t, "mock-oast-test", resp.Label)
		oastID = resp.OastID
	})

	t.Run("list", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.OastListResponse](t, mcpClient, "oast_list", nil)

		found := slices.ContainsFunc(resp.Sessions, func(s protocol.OastSession) bool {
			return s.OastID == oastID
		})
		assert.True(t, found)
	})

	t.Run("list_with_limit", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.OastListResponse](t, mcpClient, "oast_list", map[string]interface{}{
			"limit": 1,
		})
		assert.LessOrEqual(t, len(resp.Sessions), 1)
	})

	t.Run("poll_with_since", func(t *testing.T) {
		// Add an event to mock backend
		mockOast.events[oastID] = append(mockOast.events[oastID], store.OastEvent{
			ID:       "event-1",
			Time:     time.Now(),
			Type:     "dns",
			SourceIP: "1.2.3.4",
		})

		// First poll to get the event (use list mode to get Events)
		firstResp := CallMCPToolJSONOK[protocol.OastPollResponse](t, mcpClient, "oast_poll", map[string]interface{}{
			"output_mode": "events",
			"oast_id":     oastID,
		})
		require.NotEmpty(t, firstResp.Events)

		// Poll with since should exclude already seen events
		resp := CallMCPToolJSONOK[protocol.OastPollResponse](t, mcpClient, "oast_poll", map[string]interface{}{
			"output_mode": "events",
			"oast_id":     oastID,
			"since":       firstResp.Events[0].EventID,
		})
		// No events after the one we specified
		assert.Empty(t, resp.Events)
	})

	t.Run("get_valid_event", func(t *testing.T) {
		mockOast.events[oastID] = append(mockOast.events[oastID], store.OastEvent{
			ID:        "event-get-test",
			Time:      time.Now(),
			Type:      "http",
			SourceIP:  "5.6.7.8",
			Subdomain: "test",
			Details: map[string]interface{}{
				"headers": "GET /callback HTTP/1.1\r\nHost: example.com",
				"body":    "test body",
			},
		})

		resp := CallMCPToolJSONOK[protocol.OastEvent](t, mcpClient, "oast_get", map[string]interface{}{
			"event_id": "event-get-test",
		})
		assert.Equal(t, "event-get-test", resp.EventID)
		assert.Equal(t, "http", resp.Type)
		assert.Equal(t, "5.6.7.8", resp.SourceIP)
		assert.Equal(t, "GET /callback HTTP/1.1\r\nHost: example.com", resp.Details["headers"])
		assert.Equal(t, "test body", resp.Details["body"])
	})

	t.Run("get_fields_target_http", func(t *testing.T) {
		mockOast.events[oastID] = append(mockOast.events[oastID], store.OastEvent{
			ID:   "event-target-http",
			Time: time.Now(),
			Type: "http",
			Details: map[string]interface{}{
				"headers": "GET /callback HTTP/1.1\r\nHost: example.com",
				"body":    "should be excluded",
			},
		})

		resp := CallMCPToolJSONOK[protocol.OastEvent](t, mcpClient, "oast_get", map[string]interface{}{
			"event_id": "event-target-http",
			"fields":   "target",
		})
		assert.Equal(t, "GET /callback HTTP/1.1", resp.Details["target"])
		assert.Nil(t, resp.Details["headers"])
		assert.Nil(t, resp.Details["body"])
	})

	t.Run("get_fields_target_and_headers", func(t *testing.T) {
		mockOast.events[oastID] = append(mockOast.events[oastID], store.OastEvent{
			ID:   "event-target-and-headers",
			Time: time.Now(),
			Type: "http",
			Details: map[string]interface{}{
				"headers": "GET /callback HTTP/1.1\r\nHost: example.com\r\nAccept: */*",
				"body":    "should be excluded",
			},
		})

		resp := CallMCPToolJSONOK[protocol.OastEvent](t, mcpClient, "oast_get", map[string]interface{}{
			"event_id": "event-target-and-headers",
			"fields":   "target,headers",
		})
		assert.Equal(t, "GET /callback HTTP/1.1", resp.Details["target"])
		assert.Equal(t, "Host: example.com\r\nAccept: */*", resp.Details["headers"])
		assert.Nil(t, resp.Details["body"])
	})

	t.Run("get_fields_headers_only", func(t *testing.T) {
		mockOast.events[oastID] = append(mockOast.events[oastID], store.OastEvent{
			ID:   "event-headers-only",
			Time: time.Now(),
			Type: "http",
			Details: map[string]interface{}{
				"headers": "GET /callback HTTP/1.1\r\nHost: example.com",
				"body":    "should be excluded",
			},
		})

		resp := CallMCPToolJSONOK[protocol.OastEvent](t, mcpClient, "oast_get", map[string]interface{}{
			"event_id": "event-headers-only",
			"fields":   "headers",
		})
		assert.Nil(t, resp.Details["target"])
		assert.Equal(t, "GET /callback HTTP/1.1\r\nHost: example.com", resp.Details["headers"])
		assert.Nil(t, resp.Details["body"])
	})

	t.Run("get_fields_body_only", func(t *testing.T) {
		mockOast.events[oastID] = append(mockOast.events[oastID], store.OastEvent{
			ID:   "event-body-only",
			Time: time.Now(),
			Type: "http",
			Details: map[string]interface{}{
				"headers": "GET / HTTP/1.1\r\nHost: example.com",
				"body":    "the body",
			},
		})

		resp := CallMCPToolJSONOK[protocol.OastEvent](t, mcpClient, "oast_get", map[string]interface{}{
			"event_id": "event-body-only",
			"fields":   "body",
		})
		assert.Nil(t, resp.Details["headers"])
		assert.Equal(t, "the body", resp.Details["body"])
	})

	t.Run("get_fields_smtp_target", func(t *testing.T) {
		mockOast.events[oastID] = append(mockOast.events[oastID], store.OastEvent{
			ID:   "event-smtp-target",
			Time: time.Now(),
			Type: "smtp",
			Details: map[string]interface{}{
				"smtp_from": "sender@example.com",
				"smtp_to":   "recipient@example.com",
				"headers":   "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: test",
				"body":      "email body",
			},
		})

		resp := CallMCPToolJSONOK[protocol.OastEvent](t, mcpClient, "oast_get", map[string]interface{}{
			"event_id": "event-smtp-target",
			"fields":   "target",
		})
		assert.Equal(t, "sender@example.com", resp.Details["smtp_from"])
		assert.Equal(t, "recipient@example.com", resp.Details["smtp_to"])
		assert.Nil(t, resp.Details["headers"])
		assert.Nil(t, resp.Details["body"])
	})

	t.Run("get_smtp_default_includes_smtp_to", func(t *testing.T) {
		mockOast.events[oastID] = append(mockOast.events[oastID], store.OastEvent{
			ID:   "event-smtp-default",
			Time: time.Now(),
			Type: "smtp",
			Details: map[string]interface{}{
				"smtp_from": "sender@example.com",
				"smtp_to":   "recipient@example.com",
				"headers":   "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: test",
				"body":      "email body",
			},
		})

		resp := CallMCPToolJSONOK[protocol.OastEvent](t, mcpClient, "oast_get", map[string]interface{}{
			"event_id": "event-smtp-default",
		})
		assert.Nil(t, resp.Details["smtp_from"])
		assert.Nil(t, resp.Details["smtp_to"])
		assert.NotNil(t, resp.Details["headers"])
		assert.NotNil(t, resp.Details["body"])
	})

	t.Run("get_fields_dns_ignores", func(t *testing.T) {
		mockOast.events[oastID] = append(mockOast.events[oastID], store.OastEvent{
			ID:      "event-dns-fields",
			Time:    time.Now(),
			Type:    "dns",
			Details: map[string]interface{}{"query_type": "A"},
		})

		resp := CallMCPToolJSONOK[protocol.OastEvent](t, mcpClient, "oast_get", map[string]interface{}{
			"event_id": "event-dns-fields",
			"fields":   "target",
		})
		assert.Equal(t, "A", resp.Details["query_type"])
	})

	t.Run("summary_limit", func(t *testing.T) {
		// Fresh session so aggregate counts are exact (the shared session accumulates
		// events across sibling subtests).
		sess := CallMCPToolJSONOK[protocol.OastCreateResponse](t, mcpClient, "oast_create", map[string]interface{}{
			"label": "oast-summary-limit",
		})
		// 3 dns from one source + 1 http + 1 smtp aggregate to 3 groups (dns count 3).
		for i := range 3 {
			mockOast.events[sess.OastID] = append(mockOast.events[sess.OastID], store.OastEvent{
				ID: fmt.Sprintf("dns-event-%d", i), Time: time.Now(), Type: "dns", SourceIP: "10.0.0.1", Subdomain: "a",
			})
		}
		mockOast.events[sess.OastID] = append(mockOast.events[sess.OastID], store.OastEvent{
			ID: "http-event-1", Time: time.Now(), Type: "http", SourceIP: "10.0.0.2", Subdomain: "b",
		})
		mockOast.events[sess.OastID] = append(mockOast.events[sess.OastID], store.OastEvent{
			ID: "smtp-event-1", Time: time.Now(), Type: "smtp", SourceIP: "10.0.0.3", Subdomain: "c",
		})

		allResp := CallMCPToolJSONOK[protocol.OastPollResponse](t, mcpClient, "oast_poll", map[string]interface{}{
			"oast_id": sess.OastID,
			"wait":    "0s",
		})
		require.Len(t, allResp.Aggregates, 3)

		limitResp := CallMCPToolJSONOK[protocol.OastPollResponse](t, mcpClient, "oast_poll", map[string]interface{}{
			"oast_id": sess.OastID,
			"wait":    "0s",
			"limit":   1,
		})
		require.Len(t, limitResp.Aggregates, 1)
		// Top aggregate keeps its full count, not truncated by the pre-aggregation limit.
		assert.Equal(t, 3, limitResp.Aggregates[0].Count)
		assert.Equal(t, 3, limitResp.TotalCount) // aggregates before truncation
	})

	t.Run("delete", func(t *testing.T) {
		_ = CallMCPToolTextOK(t, mcpClient, "oast_delete", map[string]interface{}{
			"oast_id": oastID,
		})

		// Verify deleted
		resp := CallMCPToolJSONOK[protocol.OastListResponse](t, mcpClient, "oast_list", nil)

		for _, s := range resp.Sessions {
			assert.NotEqual(t, oastID, s.OastID)
		}
	})
}

func TestMCP_OastValidation(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

	t.Run("create_duplicate_label", func(t *testing.T) {
		// First session with label
		result := CallMCPTool(t, mcpClient, "oast_create", map[string]interface{}{
			"label": "unique-oast-label",
		})
		require.False(t, result.IsError,
			"oast_create failed: %s", ExtractMCPText(t, result))

		// Second session with same label
		result = CallMCPTool(t, mcpClient, "oast_create", map[string]interface{}{
			"label": "unique-oast-label",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "label")
	})

	t.Run("poll_invalid_wait", func(t *testing.T) {
		// First create a valid session
		createResp := CallMCPToolJSONOK[protocol.OastCreateResponse](t, mcpClient, "oast_create", nil)

		result := CallMCPTool(t, mcpClient, "oast_poll", map[string]interface{}{
			"oast_id": createResp.OastID,
			"wait":    "invalid",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "invalid wait duration")
	})

	t.Run("guard_clauses", func(t *testing.T) {
		cases := []struct {
			name string
			tool string
			args map[string]interface{}
			want string
		}{
			{"poll_missing_id", "oast_poll", map[string]interface{}{}, "oast_id is required"},
			{"poll_invalid_id", "oast_poll", map[string]interface{}{"oast_id": "nonexistent"}, "not found"},
			{"get_missing_event_id", "oast_get", map[string]interface{}{}, "event_id is required"},
			{"get_invalid_fields", "oast_get", map[string]interface{}{"event_id": "any", "fields": "invalid"}, "invalid field"},
			{"get_not_found", "oast_get", map[string]interface{}{"event_id": "nonexistent"}, "event_id not found"},
			{"delete_missing_id", "oast_delete", map[string]interface{}{}, "oast_id is required"},
			{"delete_invalid_id", "oast_delete", map[string]interface{}{"oast_id": "nonexistent"}, "not found"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				result := CallMCPTool(t, mcpClient, tc.tool, tc.args)
				assert.True(t, result.IsError)
				assert.Contains(t, ExtractMCPText(t, result), tc.want)
			})
		}
	})
}

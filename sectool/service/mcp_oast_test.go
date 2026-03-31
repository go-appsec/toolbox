package service

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

func TestMCP_OastLifecycleWithMock(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, mockOast, _ := setupMockMCPServer(t, nil)

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

	pollCases := []struct {
		name string
		args map[string]interface{}
	}{
		{name: "poll_basic", args: map[string]interface{}{}},
		{name: "poll_no_wait", args: map[string]interface{}{"wait": "0s"}},
		{name: "poll_with_wait", args: map[string]interface{}{"wait": "100ms"}},
		{name: "poll_with_type_filter", args: map[string]interface{}{"type": "dns"}},
		{name: "poll_with_limit", args: map[string]interface{}{"limit": 5}},
	}
	for _, tc := range pollCases {
		t.Run(tc.name, func(t *testing.T) {
			args := make(map[string]interface{}, len(tc.args)+1)
			args["oast_id"] = oastID
			for k, v := range tc.args {
				args[k] = v
			}
			_ = CallMCPToolJSONOK[protocol.OastPollResponse](t, mcpClient, "oast_poll", args)
			// Events may be empty, but response should parse.
		})
	}

	t.Run("poll_with_since", func(t *testing.T) {
		// Add an event to mock backend
		mockOast.events[oastID] = append(mockOast.events[oastID], OastEventInfo{
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
		// Add another event
		mockOast.events[oastID] = append(mockOast.events[oastID], OastEventInfo{
			ID:        "event-get-test",
			Time:      time.Now(),
			Type:      "http",
			SourceIP:  "5.6.7.8",
			Subdomain: "test",
			Details:   map[string]interface{}{"method": "GET", "path": "/"},
		})

		resp := CallMCPToolJSONOK[protocol.OastEvent](t, mcpClient, "oast_get", map[string]interface{}{
			"event_id": "event-get-test",
		})
		assert.Equal(t, "event-get-test", resp.EventID)
		assert.Equal(t, "http", resp.Type)
		assert.Equal(t, "5.6.7.8", resp.SourceIP)
	})

	t.Run("summary_limit", func(t *testing.T) {
		// Add events that aggregate to 3 groups
		for i := 0; i < 3; i++ {
			mockOast.events[oastID] = append(mockOast.events[oastID], OastEventInfo{
				ID:        fmt.Sprintf("dns-event-%d", i),
				Time:      time.Now(),
				Type:      "dns",
				SourceIP:  "10.0.0.1",
				Subdomain: "a",
			})
		}
		mockOast.events[oastID] = append(mockOast.events[oastID], OastEventInfo{
			ID:        "http-event-1",
			Time:      time.Now(),
			Type:      "http",
			SourceIP:  "10.0.0.2",
			Subdomain: "b",
		})
		mockOast.events[oastID] = append(mockOast.events[oastID], OastEventInfo{
			ID:        "smtp-event-1",
			Time:      time.Now(),
			Type:      "smtp",
			SourceIP:  "10.0.0.3",
			Subdomain: "c",
		})

		// Without limit: should have at least 3 aggregate rows
		allResp := CallMCPToolJSONOK[protocol.OastPollResponse](t, mcpClient, "oast_poll", map[string]interface{}{
			"oast_id": oastID,
			"wait":    "0s",
		})
		require.GreaterOrEqual(t, len(allResp.Aggregates), 3)

		// With limit=1: only top aggregate row
		limitResp := CallMCPToolJSONOK[protocol.OastPollResponse](t, mcpClient, "oast_poll", map[string]interface{}{
			"oast_id": oastID,
			"wait":    "0s",
			"limit":   1,
		})
		require.Len(t, limitResp.Aggregates, 1)
		// Top aggregate should have the full count, not truncated by pre-aggregation limit
		assert.GreaterOrEqual(t, limitResp.Aggregates[0].Count, 3)
		// TotalCount indicates how many aggregates exist before truncation
		assert.GreaterOrEqual(t, limitResp.TotalCount, 3)
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

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil)

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

	t.Run("poll_missing_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "oast_poll", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "oast_id is required")
	})

	t.Run("poll_invalid_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "oast_poll", map[string]interface{}{
			"oast_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "not found")
	})

	t.Run("get_missing_event_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "oast_get", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "event_id is required")
	})

	t.Run("get_not_found", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "oast_get", map[string]interface{}{
			"event_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "event_id not found")
	})

	t.Run("delete_missing_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "oast_delete", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "oast_id is required")
	})

	t.Run("delete_invalid_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "oast_delete", map[string]interface{}{
			"oast_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "not found")
	})
}

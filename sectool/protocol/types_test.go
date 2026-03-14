package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyPollResponse_MarshalJSON(t *testing.T) {
	t.Parallel()

	t.Run("empty_aggregates", func(t *testing.T) {
		resp := ProxyPollResponse{Aggregates: []SummaryEntry{}}
		b, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &m))
		assert.Contains(t, m, "aggregates")
		assert.NotContains(t, m, "flows")
		assert.Equal(t, "[]", string(m["aggregates"]))
	})

	t.Run("empty_flows", func(t *testing.T) {
		resp := ProxyPollResponse{Flows: []FlowEntry{}}
		b, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &m))
		assert.Contains(t, m, "flows")
		assert.NotContains(t, m, "aggregates")
		assert.Equal(t, "[]", string(m["flows"]))
	})

	t.Run("nil_slices_omitted", func(t *testing.T) {
		resp := ProxyPollResponse{}
		b, err := json.Marshal(resp)
		require.NoError(t, err)
		assert.JSONEq(t, `{}`, string(b))
	})

	t.Run("with_note", func(t *testing.T) {
		resp := ProxyPollResponse{Flows: []FlowEntry{}, Note: "test note"}
		b, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &m))
		assert.Contains(t, m, "flows")
		assert.Contains(t, m, "note")
	})

	t.Run("total_count_present_when_nonzero", func(t *testing.T) {
		resp := ProxyPollResponse{Aggregates: []SummaryEntry{}, TotalCount: 42}
		b, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &m))
		assert.Contains(t, m, "total_count")
		assert.Equal(t, "42", string(m["total_count"]))
	})

	t.Run("total_count_omitted_when_zero", func(t *testing.T) {
		resp := ProxyPollResponse{Aggregates: []SummaryEntry{}}
		b, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &m))
		assert.NotContains(t, m, "total_count")
	})

	t.Run("roundtrip", func(t *testing.T) {
		resp := ProxyPollResponse{
			Flows: []FlowEntry{{FlowID: "abc", Method: "GET", Host: "example.com", Path: "/"}},
		}
		b, err := json.Marshal(resp)
		require.NoError(t, err)

		var decoded ProxyPollResponse
		require.NoError(t, json.Unmarshal(b, &decoded))
		assert.Len(t, decoded.Flows, 1)
		assert.Equal(t, "abc", decoded.Flows[0].FlowID)
	})
}

func TestOastPollResponse_MarshalJSON(t *testing.T) {
	t.Parallel()

	t.Run("empty_events", func(t *testing.T) {
		resp := OastPollResponse{Events: []OastEvent{}}
		b, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &m))
		assert.Contains(t, m, "events")
		assert.NotContains(t, m, "aggregates")
		assert.Equal(t, "[]", string(m["events"]))
	})

	t.Run("empty_aggregates", func(t *testing.T) {
		resp := OastPollResponse{Aggregates: []OastSummaryEntry{}}
		b, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &m))
		assert.Contains(t, m, "aggregates")
		assert.NotContains(t, m, "events")
	})

	t.Run("nil_slices_omitted", func(t *testing.T) {
		resp := OastPollResponse{}
		b, err := json.Marshal(resp)
		require.NoError(t, err)
		assert.JSONEq(t, `{}`, string(b))
	})

	t.Run("dropped_count_omitted_when_zero", func(t *testing.T) {
		resp := OastPollResponse{Events: []OastEvent{}}
		b, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &m))
		assert.NotContains(t, m, "dropped_count")
	})

	t.Run("dropped_count_present_when_nonzero", func(t *testing.T) {
		resp := OastPollResponse{Events: []OastEvent{}, DroppedCount: 5}
		b, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &m))
		assert.Contains(t, m, "dropped_count")
	})
}

func TestCrawlPollResponse_MarshalJSON(t *testing.T) {
	t.Parallel()

	t.Run("empty_flows", func(t *testing.T) {
		resp := CrawlPollResponse{SessionID: "s1", Flows: []CrawlFlow{}}
		b, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &m))
		assert.Contains(t, m, "session_id")
		assert.Contains(t, m, "flows")
		assert.NotContains(t, m, "aggregates")
		assert.NotContains(t, m, "forms")
		assert.NotContains(t, m, "errors")
	})

	t.Run("empty_forms", func(t *testing.T) {
		resp := CrawlPollResponse{SessionID: "s1", Forms: []CrawlForm{}}
		b, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &m))
		assert.Contains(t, m, "forms")
		assert.NotContains(t, m, "flows")
	})

	t.Run("empty_errors", func(t *testing.T) {
		resp := CrawlPollResponse{SessionID: "s1", Errors: []CrawlError{}}
		b, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &m))
		assert.Contains(t, m, "errors")
		assert.NotContains(t, m, "flows")
	})

	t.Run("summary_with_state", func(t *testing.T) {
		resp := CrawlPollResponse{
			SessionID:  "s1",
			State:      "running",
			Duration:   "5s",
			Aggregates: []SummaryEntry{},
		}
		b, err := json.Marshal(resp)
		require.NoError(t, err)

		var m map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(b, &m))
		assert.Contains(t, m, "state")
		assert.Contains(t, m, "duration")
		assert.Contains(t, m, "aggregates")
	})
}

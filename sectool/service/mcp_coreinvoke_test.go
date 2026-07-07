package service

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoreInvoke(t *testing.T) {
	t.Parallel()

	srv, _, mockHTTP, _, _ := setupMockMCPServer(t, nil)
	flowID := mockHTTP.AddProxyEntry(
		"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\n\r\n",
		"",
	)

	t.Run("dispatches_read_tool", func(t *testing.T) {
		params, err := json.Marshal(map[string]any{"output_mode": "flows", "limit": 10})
		require.NoError(t, err)
		content, isErr, err := srv.CoreInvoke(t.Context(), "proxy_poll", params)
		require.NoError(t, err)
		assert.False(t, isErr)
		assert.Contains(t, content, flowID)
	})

	t.Run("dispatches_write_tool", func(t *testing.T) {
		// write tools invocable: empty params reach handler validation, not "not permitted"
		content, isErr, err := srv.CoreInvoke(t.Context(), "proxy_rule_add", json.RawMessage(`{}`))
		require.NoError(t, err)
		assert.True(t, isErr)
		assert.Contains(t, content, "type is required")
	})

	t.Run("rejects_internal_tool", func(t *testing.T) {
		_, _, err := srv.CoreInvoke(t.Context(), InternalToolPrefix+"history_delete", json.RawMessage(`{}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not permitted")
	})

	t.Run("rejects_unknown_tool", func(t *testing.T) {
		_, _, err := srv.CoreInvoke(t.Context(), "definitely_not_a_tool", nil)
		require.Error(t, err)
	})

	t.Run("flow_get_returns_flow", func(t *testing.T) {
		params, err := json.Marshal(map[string]any{"flow_id": flowID})
		require.NoError(t, err)
		content, _, err := srv.CoreInvoke(t.Context(), "flow_get", params)
		require.NoError(t, err)
		assert.Contains(t, content, "example.com")
	})
}

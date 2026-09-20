package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

func TestMCP_HistoryDelete(t *testing.T) {
	t.Parallel()

	t.Run("no_args", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		res := CallMCPTool(t, mcpClient, "_internal_history_delete", map[string]interface{}{})
		require.True(t, res.IsError)
		assert.Contains(t, ExtractMCPText(t, res), "flow_ids is required")
	})

	t.Run("skips_note_referenced", func(t *testing.T) {
		srv, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		pid := mockHTTP.AddProxyEntry("GET / HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", "")
		require.NoError(t, srv.noteStore.Save(&store.NoteMeta{NoteID: "n1", Type: "note", FlowIDs: []string{pid}, Content: "x"}))

		resp := CallMCPToolJSONOK[protocol.HistoryDeleteResponse](t, mcpClient, "_internal_history_delete", map[string]interface{}{
			"flow_ids": []string{pid},
		})
		assert.Equal(t, 0, resp.DeletedProxy)
		assert.Equal(t, 0, resp.DeletedReplay)
		assert.Equal(t, []string{pid}, resp.Skipped)

		// Proxy entry and note both untouched
		got, err := mockHTTP.GetProxyHistory(t.Context(), 100, "")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, pid, got[0].FlowID)
		n1, ok := srv.noteStore.Get("n1")
		require.True(t, ok)
		assert.Equal(t, []string{pid}, n1.FlowIDs)
	})

	t.Run("partial_skip", func(t *testing.T) {
		srv, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		pid1 := mockHTTP.AddProxyEntry("GET / HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", "")
		pid2 := mockHTTP.AddProxyEntry("GET / HTTP/1.1\r\nHost: b\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", "")

		require.NoError(t, srv.noteStore.Save(&store.NoteMeta{NoteID: "n1", Type: "note", FlowIDs: []string{pid1}, Content: "x"}))

		resp := CallMCPToolJSONOK[protocol.HistoryDeleteResponse](t, mcpClient, "_internal_history_delete", map[string]interface{}{
			"flow_ids": []string{pid1, pid2},
		})
		assert.Equal(t, 1, resp.DeletedProxy)
		assert.Equal(t, []string{pid1}, resp.Skipped)

		// pid1 (note-protected) survives; pid2 is gone
		got, err := mockHTTP.GetProxyHistory(t.Context(), 100, "")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, pid1, got[0].FlowID)
	})

	t.Run("note_on_child_retains_parent", func(t *testing.T) {
		srv, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		pid := mockHTTP.AddProxyEntry("GET /s HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 101 Switching Protocols\r\n\r\n", "")
		cid := mockHTTP.AddProxyChildEntry(pid, "FRAME / HTTP/1.1\r\n\r\n")
		require.NoError(t, srv.noteStore.Save(&store.NoteMeta{NoteID: "n1", Type: "note", FlowIDs: []string{cid}, Content: "x"}))

		resp := CallMCPToolJSONOK[protocol.HistoryDeleteResponse](t, mcpClient, "_internal_history_delete", map[string]interface{}{
			"flow_ids": []string{pid},
		})
		assert.Equal(t, 0, resp.DeletedProxy)
		assert.Equal(t, []string{pid}, resp.Skipped)

		// deleting the parent would cascade over the noted child, so it survives
		_, err := mockHTTP.GetProxyEntry(t.Context(), pid)
		assert.NoError(t, err)
	})

	t.Run("note_on_grandchild_retains_parent", func(t *testing.T) {
		srv, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		pid := mockHTTP.AddProxyEntry("GET /s HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 101 Switching Protocols\r\n\r\n", "")
		cid := mockHTTP.AddProxyChildEntry(pid, "FRAME / HTTP/1.1\r\n\r\n")
		gid := mockHTTP.AddProxyChildEntry(cid, "FRAME / HTTP/1.1\r\n\r\n")
		require.NoError(t, srv.noteStore.Save(&store.NoteMeta{NoteID: "n1", Type: "note", FlowIDs: []string{gid}, Content: "x"}))

		resp := CallMCPToolJSONOK[protocol.HistoryDeleteResponse](t, mcpClient, "_internal_history_delete", map[string]interface{}{
			"flow_ids": []string{pid},
		})
		assert.Equal(t, 0, resp.DeletedProxy)
		assert.Equal(t, []string{pid}, resp.Skipped)
	})

	t.Run("unnoted_children_delete_parent", func(t *testing.T) {
		_, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		pid := mockHTTP.AddProxyEntry("GET /s HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 101 Switching Protocols\r\n\r\n", "")
		mockHTTP.AddProxyChildEntry(pid, "FRAME / HTTP/1.1\r\n\r\n")

		resp := CallMCPToolJSONOK[protocol.HistoryDeleteResponse](t, mcpClient, "_internal_history_delete", map[string]interface{}{
			"flow_ids": []string{pid},
		})
		assert.Equal(t, 1, resp.DeletedProxy)
		assert.Empty(t, resp.Skipped)
	})

	t.Run("no_replay_cascade", func(t *testing.T) {
		srv, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		pid := mockHTTP.AddProxyEntry("GET / HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", "")
		srv.replayHistoryStore.Store(&store.ReplayHistoryEntry{
			ReplayHistoryMeta: store.ReplayHistoryMeta{
				FlowID:       "r1",
				SourceFlowID: pid,
				CreatedAt:    time.Now(),
			},
		})

		resp := CallMCPToolJSONOK[protocol.HistoryDeleteResponse](t, mcpClient, "_internal_history_delete", map[string]interface{}{
			"flow_ids": []string{pid},
		})
		assert.Equal(t, 1, resp.DeletedProxy)
		assert.Equal(t, 0, resp.DeletedReplay)

		// Replay survives
		r1, ok := srv.replayHistoryStore.Get("r1")
		require.True(t, ok)
		assert.Equal(t, pid, r1.SourceFlowID)
	})

	t.Run("unknown_ids_noop", func(t *testing.T) {
		_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		resp := CallMCPToolJSONOK[protocol.HistoryDeleteResponse](t, mcpClient, "_internal_history_delete", map[string]interface{}{
			"flow_ids": []string{"missing1", "missing2"},
		})
		assert.Equal(t, 0, resp.DeletedProxy)
		assert.Equal(t, 0, resp.DeletedReplay)
	})

	t.Run("mixed_proxy_and_replay", func(t *testing.T) {
		srv, mcpClient, mockHTTP, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

		pid1 := mockHTTP.AddProxyEntry("GET / HTTP/1.1\r\nHost: a\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", "")
		pid2 := mockHTTP.AddProxyEntry("GET / HTTP/1.1\r\nHost: b\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", "")

		srv.replayHistoryStore.Store(&store.ReplayHistoryEntry{
			ReplayHistoryMeta: store.ReplayHistoryMeta{
				FlowID:    "r1",
				CreatedAt: time.Now(),
			},
		})
		srv.replayHistoryStore.Store(&store.ReplayHistoryEntry{
			ReplayHistoryMeta: store.ReplayHistoryMeta{
				FlowID:    "r2",
				CreatedAt: time.Now(),
			},
		})

		resp := CallMCPToolJSONOK[protocol.HistoryDeleteResponse](t, mcpClient, "_internal_history_delete", map[string]interface{}{
			"flow_ids": []string{pid1, "r1", "missing"},
		})
		assert.Equal(t, 1, resp.DeletedProxy)
		assert.Equal(t, 1, resp.DeletedReplay)

		// Survivors remain
		_, ok := srv.replayHistoryStore.Get("r2")
		assert.True(t, ok)
		got, err := mockHTTP.GetProxyHistory(t.Context(), 100, "")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, pid2, got[0].FlowID)
	})
}

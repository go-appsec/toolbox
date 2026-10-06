package notes

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

func TestNoteContentCell(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"single_line", "short content", "short content"},
		{"collapses_whitespace", "line one\nline two\ttabbed", "line one line two tabbed"},
		{"truncates_long", strings.Repeat("a", 100), strings.Repeat("a", 57) + "..."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, contentCell(tc.in))
		})
	}
}

// startNotesServer boots a notes-enabled MCP server on an ephemeral port and returns its URL.
func startNotesServer(t *testing.T) string {
	t.Helper()

	backend, err := service.NewNativeProxyBackend(t.Context(), 0, t.TempDir(), 0, store.MemProvider, proxy.TimeoutConfig{}, false)
	require.NoError(t, err)

	srv, err := service.NewServerWithStorageDir(service.MCPServerFlags{
		MCPPort:      -1,
		WorkflowMode: protocol.WorkflowModeNone,
		ConfigPath:   filepath.Join(t.TempDir(), "config.json"),
		Notes:        true,
	}, t.TempDir(), backend, nil, nil)
	require.NoError(t, err)
	srv.SetQuietLogging()

	go func() { _ = srv.Run(t.Context()) }()
	srv.WaitTillStarted()
	t.Cleanup(srv.RequestShutdown)

	return "http://" + srv.MCPAddr() + "/mcp"
}

func TestNotesClientLifecycle(t *testing.T) {
	t.Parallel()

	client, err := mcpclient.Connect(t.Context(), startNotesServer(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	seedNote := func(noteType, content string) protocol.NoteEntry {
		t.Helper()
		var note protocol.NoteEntry
		require.NoError(t, client.CallToolJSON(t.Context(), "notes_save", map[string]interface{}{
			"type":    noteType,
			"content": content,
		}, &note))
		return note
	}
	noteA := seedNote("finding", "XSS in search parameter")
	noteB := seedNote("note", "Interesting endpoint")
	require.NotEqual(t, noteA.NoteID, noteB.NoteID)

	t.Run("list_all", func(t *testing.T) {
		resp, err := client.NotesList(t.Context(), mcpclient.NotesListOpts{})
		require.NoError(t, err)
		assert.Len(t, resp.Notes, 2)
	})

	t.Run("list_filter_type", func(t *testing.T) {
		resp, err := client.NotesList(t.Context(), mcpclient.NotesListOpts{Type: "finding"})
		require.NoError(t, err)
		require.Len(t, resp.Notes, 1)
		assert.Equal(t, noteA.NoteID, resp.Notes[0].NoteID)
	})

	t.Run("list_filter_contains", func(t *testing.T) {
		resp, err := client.NotesList(t.Context(), mcpclient.NotesListOpts{Contains: "endpoint"})
		require.NoError(t, err)
		require.Len(t, resp.Notes, 1)
		assert.Equal(t, noteB.NoteID, resp.Notes[0].NoteID)
	})

	t.Run("list_filter_flow_ids_no_match", func(t *testing.T) {
		resp, err := client.NotesList(t.Context(), mcpclient.NotesListOpts{FlowIDs: []string{"nonexistent"}})
		require.NoError(t, err)
		assert.Empty(t, resp.Notes)
	})

	t.Run("get_found", func(t *testing.T) {
		note, err := client.NotesGet(t.Context(), noteB.NoteID)
		require.NoError(t, err)
		assert.Equal(t, noteB.NoteID, note.NoteID)
		assert.Equal(t, "note", note.Type)
		assert.Equal(t, "Interesting endpoint", note.Content)
	})

	t.Run("get_not_found", func(t *testing.T) {
		_, err := client.NotesGet(t.Context(), "bogus")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "note not found")
	})

	t.Run("delete_found", func(t *testing.T) {
		require.NoError(t, client.NotesDelete(t.Context(), noteA.NoteID))

		resp, err := client.NotesList(t.Context(), mcpclient.NotesListOpts{})
		require.NoError(t, err)
		require.Len(t, resp.Notes, 1)
		assert.Equal(t, noteB.NoteID, resp.Notes[0].NoteID)
	})

	t.Run("delete_not_found", func(t *testing.T) {
		err := client.NotesDelete(t.Context(), noteA.NoteID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "note not found")
	})
}

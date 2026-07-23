package service

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

// setupNotesEnabledServer creates an MCP server with notes enabled for testing.
func setupNotesEnabledServer(t *testing.T) (*Server, *mcpclient.Client, *mockHttpBackend, *mockCrawlerBackend) {
	t.Helper()

	mockHTTP := newMockHttpBackend()
	mockOast := newMockOastBackend()
	mockCrawler := newMockCrawlerBackend()

	configPath := filepath.Join(t.TempDir(), "config.json")

	srv, err := NewServerWithStorageDir(MCPServerFlags{
		MCPPort:      -1,
		WorkflowMode: protocol.WorkflowModeNone,
		ConfigPath:   configPath,
		Notes:        true,
	}, t.TempDir(), mockHTTP, mockOast, mockCrawler)
	require.NoError(t, err)
	srv.SetQuietLogging()

	go func() { _ = srv.Run(t.Context()) }()
	srv.WaitTillStarted()

	require.NotNil(t, srv.mcpServer)

	mcpClient, err := mcpclient.NewInProcessClient(srv.mcpServer.server)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	_, err = mcpClient.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ClientInfo: mcp.Implementation{
				Name:    "sectool-test",
				Version: "1.0.0",
			},
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
		},
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = mcpClient.Close()
		srv.RequestShutdown()
	})

	return srv, mcpClient, mockHTTP, mockCrawler
}

func TestMCP_NotesLifecycle(t *testing.T) {
	t.Parallel()

	srv, client, mockHTTP, _ := setupNotesEnabledServer(t)

	// Add a proxy entry so we have a valid flow_id
	mockHTTP.AddProxyEntry(
		"GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
		"",
	)

	// Get a flow_id via proxy_poll
	pollResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, client, "proxy_poll", map[string]interface{}{
		"output_mode": "flows",
		"host":        "example.com",
	})
	require.Len(t, pollResp.Flows, 1)
	flowID := pollResp.Flows[0].FlowID

	t.Run("create", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.NoteEntry](t, client, "notes_save", map[string]interface{}{
			"type":     "finding",
			"flow_ids": flowID,
			"content":  "XSS in search parameter",
		})
		assert.NotEmpty(t, resp.NoteID)
		assert.Equal(t, "finding", resp.Type)
		assert.Equal(t, []string{flowID}, resp.FlowIDs)
		assert.Equal(t, "XSS in search parameter", resp.Content)
		assert.Equal(t, 1, srv.noteStore.Count())
	})

	t.Run("list", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.NotesListResponse](t, client, "notes_list", nil)
		require.Len(t, resp.Notes, 1)
		assert.Equal(t, "finding", resp.Notes[0].Type)
		assert.Equal(t, "XSS in search parameter", resp.Notes[0].Content)
	})

	t.Run("update", func(t *testing.T) {
		// Get the note_id
		listResp := CallMCPToolJSONOK[protocol.NotesListResponse](t, client, "notes_list", nil)
		noteID := listResp.Notes[0].NoteID

		resp := CallMCPToolJSONOK[protocol.NoteEntry](t, client, "notes_save", map[string]interface{}{
			"note_id": noteID,
			"content": "Confirmed XSS — reflected without encoding",
		})
		assert.Equal(t, noteID, resp.NoteID)
		assert.Equal(t, "Confirmed XSS — reflected without encoding", resp.Content)
		assert.Equal(t, "finding", resp.Type) // unchanged

		assert.Equal(t, 1, srv.noteStore.Count())
	})

	t.Run("delete", func(t *testing.T) {
		listResp := CallMCPToolJSONOK[protocol.NotesListResponse](t, client, "notes_list", nil)
		noteID := listResp.Notes[0].NoteID

		CallMCPToolJSONOK[protocol.NoteDeleteResponse](t, client, "notes_save", map[string]interface{}{
			"note_id": noteID,
		})

		assert.Equal(t, 0, srv.noteStore.Count())
	})

	t.Run("invalid_flow_id", func(t *testing.T) {
		result := CallMCPTool(t, client, "notes_save", map[string]interface{}{
			"type":     "finding",
			"flow_ids": "nonexistent",
			"content":  "test",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "flow_id not found")
	})

	t.Run("not_found", func(t *testing.T) {
		result := CallMCPTool(t, client, "notes_save", map[string]interface{}{
			"note_id": "nonexistent",
			"content": "test",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "note not found")
	})
}

func TestMCP_NotesInProxyFlowListing(t *testing.T) {
	t.Parallel()

	srv, client, mockHTTP, _ := setupNotesEnabledServer(t)

	// Add proxy entries
	mockHTTP.AddProxyEntry(
		"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
		"",
	)
	mockHTTP.AddProxyEntry(
		"GET /api/admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\n\r\nDenied",
		"",
	)

	// Get flow IDs
	pollResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, client, "proxy_poll", map[string]interface{}{
		"output_mode": "flows",
		"host":        "example.com",
	})
	require.Len(t, pollResp.Flows, 2)
	flowID1 := pollResp.Flows[0].FlowID

	// Create a note for the first flow
	noteResp := CallMCPToolJSONOK[protocol.NoteEntry](t, client, "notes_save", map[string]interface{}{
		"type":     "finding",
		"flow_ids": flowID1,
		"content":  "IDOR vulnerability",
	})
	_ = noteResp

	// Poll again and verify notes are attached
	pollResp2 := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, client, "proxy_poll", map[string]interface{}{
		"output_mode": "flows",
		"host":        "example.com",
	})
	require.Len(t, pollResp2.Flows, 2)

	// First flow should have notes
	require.Len(t, pollResp2.Flows[0].Notes, 1)
	assert.Equal(t, "finding", pollResp2.Flows[0].Notes[0].Type)
	assert.Equal(t, "IDOR vulnerability", pollResp2.Flows[0].Notes[0].Content)

	// Second flow should have no notes
	assert.Empty(t, pollResp2.Flows[1].Notes)

	// Notes should not appear when notes are in the store but queried via a non-notes server
	_ = srv
}

func TestMCP_NotesInCrawlFlowListing(t *testing.T) {
	t.Parallel()

	_, client, _, mockCrawler := setupNotesEnabledServer(t)

	// Create a crawl session with a flow
	sess, err := mockCrawler.CreateSession(t.Context(), CrawlOptions{
		Label: "test-crawl",
		Seeds: []CrawlSeed{{URL: "http://example.com"}},
	})
	require.NoError(t, err)

	require.NoError(t, mockCrawler.AddFlow(sess.ID, CrawlFlow{
		ID:             "crawl-f1",
		SessionID:      sess.ID,
		Method:         "GET",
		Host:           "example.com",
		Path:           "/page",
		StatusCode:     200,
		ResponseLength: 100,
		Duration:       50 * time.Millisecond,
		Request:        []byte("GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Response:       []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest"),
	}))

	// Create a note for the crawl flow
	noteResp := CallMCPToolJSONOK[protocol.NoteEntry](t, client, "notes_save", map[string]interface{}{
		"type":     "note",
		"flow_ids": "crawl-f1",
		"content":  "Interesting endpoint",
	})
	_ = noteResp

	// Poll crawl flows
	var crawlResp protocol.CrawlPollResponse
	text := CallMCPToolTextOK(t, client, "crawl_poll", map[string]interface{}{
		"session_id":  "test-crawl",
		"output_mode": "flows",
	})
	require.NoError(t, json.Unmarshal([]byte(text), &crawlResp))

	require.Len(t, crawlResp.Flows, 1)
	require.Len(t, crawlResp.Flows[0].Notes, 1)
	assert.Equal(t, "note", crawlResp.Flows[0].Notes[0].Type)
	assert.Equal(t, "Interesting endpoint", crawlResp.Flows[0].Notes[0].Content)
}

func TestMCP_NotesToolsRegistered(t *testing.T) {
	t.Parallel()

	_, client, _, _ := setupNotesEnabledServer(t)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	result, err := client.ListTools(ctx, mcp.ListToolsRequest{})
	require.NoError(t, err)

	toolNames := make([]string, len(result.Tools))
	for i, tool := range result.Tools {
		toolNames[i] = tool.Name
	}

	assert.Contains(t, toolNames, "notes_save")
	assert.Contains(t, toolNames, "notes_list")
}

func TestMCP_NotesToolsNotRegisteredWithoutFlag(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t, nil, protocol.WorkflowModeNone)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	result, err := mcpClient.ListTools(ctx, mcp.ListToolsRequest{})
	require.NoError(t, err)

	for _, tool := range result.Tools {
		assert.NotEqual(t, "notes_save", tool.Name)
		assert.NotEqual(t, "notes_list", tool.Name)
	}
}

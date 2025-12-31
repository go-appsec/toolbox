package service

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// testServerWithMCP creates a test server with mock MCP and returns cleanup func.
func testServerWithMCP(t *testing.T) (*Server, *TestMCPServer) {
	t.Helper()

	mockMCP := NewTestMCPServer(t)
	workDir := t.TempDir()

	srv, err := NewServer(DaemonFlags{
		WorkDir:    workDir,
		BurpMCPURL: mockMCP.URL(),
	})
	require.NoError(t, err)

	// Start server in background
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Run(t.Context())
	}()
	srv.WaitTillStarted()

	t.Cleanup(func() {
		srv.RequestShutdown()
		<-serverErr
	})

	return srv, mockMCP
}

// doRequest is a helper to make HTTP requests to the server.
func doRequest(t *testing.T, srv *Server, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()

	var reqBody bytes.Buffer
	if body != nil {
		err := json.NewEncoder(&reqBody).Encode(body)
		require.NoError(t, err)
	}

	req := httptest.NewRequest(method, path, &reqBody)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.routes().ServeHTTP(w, req)
	return w
}

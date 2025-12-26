package service

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractRequestMeta(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		raw    string
		method string
		host   string
		path   string
	}{
		{
			name:   "simple GET",
			raw:    "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
			method: "GET",
			host:   "example.com",
			path:   "/api/users",
		},
		{
			name:   "POST with port",
			raw:    "POST /login HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n",
			method: "POST",
			host:   "api.example.com:8080",
			path:   "/login",
		},
		{
			name:   "with query string",
			raw:    "GET /search?q=test&page=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n",
			method: "GET",
			host:   "example.com",
			path:   "/search?q=test&page=1",
		},
		{
			name:   "lowercase host header",
			raw:    "GET / HTTP/1.1\r\nhost: lowercase.com\r\n\r\n",
			method: "GET",
			host:   "lowercase.com",
			path:   "/",
		},
		{
			name:   "malformed - no crash",
			raw:    "garbage",
			method: "",
			host:   "",
			path:   "",
		},
		{
			name:   "empty string",
			raw:    "",
			method: "",
			host:   "",
			path:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, host, path := extractRequestMeta(tt.raw)
			assert.Equal(t, tt.method, method)
			assert.Equal(t, tt.host, host)
			assert.Equal(t, tt.path, path)
		})
	}
}

func TestSplitHeadersBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		raw         string
		wantHeaders string
		wantBody    string
	}{
		{
			name:        "simple request with body",
			raw:         "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody here",
			wantHeaders: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantBody:    "body here",
		},
		{
			name:        "no body",
			raw:         "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantHeaders: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantBody:    "",
		},
		{
			name:        "binary body",
			raw:         "POST / HTTP/1.1\r\n\r\n\x00\x01\x02",
			wantHeaders: "POST / HTTP/1.1\r\n\r\n",
			wantBody:    "\x00\x01\x02",
		},
		{
			name:        "no separator",
			raw:         "malformed request",
			wantHeaders: "malformed request",
			wantBody:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers, body := splitHeadersBody([]byte(tt.raw))
			assert.Equal(t, tt.wantHeaders, string(headers))
			assert.Equal(t, tt.wantBody, string(body))
		})
	}
}

func TestGlobToRegex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		glob     string
		expected string
	}{
		{"*.example.com", `.*\.example\.com`},
		{"api.example.com", `api\.example\.com`},
		{"test?", `test.`},
		{"*.*.com", `.*\..*\.com`},
		{"plain", `plain`},
		{"path/to/*", `path/to/.*`},
		{"[bracket]", `\[bracket\]`},
		{"(paren)", `\(paren\)`},
	}

	for _, tt := range tests {
		t.Run(tt.glob, func(t *testing.T) {
			assert.Equal(t, tt.expected, globToRegex(tt.glob))
		})
	}
}

func TestMatchesGlob(t *testing.T) {
	t.Parallel()

	tests := []struct {
		s       string
		pattern string
		match   bool
	}{
		{"api.example.com", "*.example.com", true},
		{"example.com", "*.example.com", false},
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "api.*.com", true},
		{"test1", "test?", true},
		{"test12", "test?", false},
		{"anything", "", true}, // empty pattern matches all
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.pattern, func(t *testing.T) {
			assert.Equal(t, tt.match, matchesGlob(tt.s, tt.pattern))
		})
	}
}

func TestParseCommaSeparated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected []string
	}{
		{"GET,POST,PUT", []string{"GET", "POST", "PUT"}},
		{"GET, POST, PUT", []string{"GET", "POST", "PUT"}},
		{"GET", []string{"GET"}},
		{"", nil},
		{" , , ", []string{}}, // empty entries are filtered, but result is empty slice not nil
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseCommaSeparated(tt.input))
		})
	}
}

func TestParseStatusCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected []int
	}{
		{"200,302,404", []int{200, 302, 404}},
		{"200, 404", []int{200, 404}},
		{"500", []int{500}},
		{"", nil},
		{"invalid", []int{}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseStatusCodes(tt.input))
		})
	}
}

func TestTruncatePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path   string
		maxLen int
		want   string
	}{
		{"/short", 100, "/short"},
		{"/very/long/path/that/exceeds/the/maximum/length", 20, "/very/long/path/t..."},
		{"", 10, ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, truncatePath(tt.path, tt.maxLen))
		})
	}
}

func TestPreviewBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		body   []byte
		maxLen int
		want   string
	}{
		{"empty", []byte{}, 100, ""},
		{"utf8 short", []byte("hello world"), 100, "hello world"},
		{"utf8 truncate", []byte("hello world"), 5, "hello..."},
		{"binary", []byte{0x00, 0x01, 0xff}, 100, "<BINARY>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, previewBody(tt.body, tt.maxLen))
		})
	}
}

func TestAggregateByTuple(t *testing.T) {
	t.Parallel()

	entries := []flowEntry{
		{method: "GET", host: "example.com", path: "/api", status: 200},
		{method: "GET", host: "example.com", path: "/api", status: 200},
		{method: "GET", host: "example.com", path: "/api", status: 200},
		{method: "POST", host: "example.com", path: "/api", status: 201},
		{method: "GET", host: "other.com", path: "/", status: 200},
	}

	result := aggregateByTuple(entries)

	// Should have 3 unique tuples
	assert.Len(t, result, 3)

	// First entry should have highest count (3)
	assert.Equal(t, 3, result[0].Count)
	assert.Equal(t, "GET", result[0].Method)
	assert.Equal(t, "example.com", result[0].Host)
	assert.Equal(t, 200, result[0].Status)
}

func TestHandleProxyList(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		w := doRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var listResp ProxyListResponse
		require.NoError(t, json.Unmarshal(resp.Data, &listResp))
		assert.Empty(t, listResp.Aggregates)
		assert.Empty(t, listResp.Flows)
	})

	t.Run("aggregate", func(t *testing.T) {
		srv, mockMCP, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		// Add some proxy history entries
		mockMCP.AddProxyEntries(
			MakeProxyEntry("GET", "/api/users", "example.com", 200, "ok"),
			MakeProxyEntry("GET", "/api/users", "example.com", 200, "ok"),
			MakeProxyEntry("POST", "/api/users", "example.com", 201, "created"),
			MakeProxyEntry("GET", "/other", "other.com", 404, "not found"),
		)

		w := doRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var listResp ProxyListResponse
		require.NoError(t, json.Unmarshal(resp.Data, &listResp))

		// Should have aggregates (no filters = aggregate mode)
		assert.NotEmpty(t, listResp.Aggregates)
		assert.Empty(t, listResp.Flows)

		// First entry should have highest count
		assert.Equal(t, 2, listResp.Aggregates[0].Count)
		assert.Equal(t, "GET", listResp.Aggregates[0].Method)
		assert.Equal(t, "example.com", listResp.Aggregates[0].Host)
	})

	t.Run("filters", func(t *testing.T) {
		srv, mockMCP, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		mockMCP.AddProxyEntries(
			MakeProxyEntry("GET", "/api/users", "example.com", 200, "ok"),
			MakeProxyEntry("POST", "/api/users", "example.com", 201, "created"),
			MakeProxyEntry("GET", "/other", "other.com", 404, "not found"),
		)

		// Filter by method
		w := doRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{Method: "GET"})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var listResp ProxyListResponse
		require.NoError(t, json.Unmarshal(resp.Data, &listResp))

		// Should have flows (filters = flow mode)
		assert.Empty(t, listResp.Aggregates)
		assert.NotEmpty(t, listResp.Flows)

		// All flows should be GET
		for _, flow := range listResp.Flows {
			assert.Equal(t, "GET", flow.Method)
		}
	})

	t.Run("host_filter", func(t *testing.T) {
		srv, mockMCP, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		mockMCP.AddProxyEntries(
			MakeProxyEntry("GET", "/api", "api.example.com", 200, "ok"),
			MakeProxyEntry("GET", "/web", "www.example.com", 200, "ok"),
			MakeProxyEntry("GET", "/other", "other.com", 200, "ok"),
		)

		// Filter by host glob
		w := doRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{Host: "*.example.com"})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

		var listResp ProxyListResponse
		require.NoError(t, json.Unmarshal(resp.Data, &listResp))

		// Should only have example.com hosts
		assert.Len(t, listResp.Flows, 2)
		for _, flow := range listResp.Flows {
			assert.Contains(t, flow.Host, "example.com")
		}
	})

	t.Run("exclude_host", func(t *testing.T) {
		srv, mockMCP, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		mockMCP.AddProxyEntries(
			MakeProxyEntry("GET", "/api", "api.example.com", 200, "ok"),
			MakeProxyEntry("GET", "/other", "other.com", 200, "ok"),
		)

		// Exclude example.com
		w := doRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{
			ExcludeHost: "*.example.com",
			Method:      "GET", // Need a filter to get flows
		})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

		var listResp ProxyListResponse
		require.NoError(t, json.Unmarshal(resp.Data, &listResp))

		// Should only have other.com
		assert.Len(t, listResp.Flows, 1)
		assert.Equal(t, "other.com", listResp.Flows[0].Host)
	})
}

func TestHandleProxyExport(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		srv, mockMCP, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		mockMCP.AddProxyEntry(
			"GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>test</html>",
			"test note",
		)

		// First list to get a flow ID
		w := doRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{Method: "GET"})
		require.Equal(t, http.StatusOK, w.Code)

		var listAPIResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listAPIResp))
		var listResp ProxyListResponse
		require.NoError(t, json.Unmarshal(listAPIResp.Data, &listResp))
		require.Len(t, listResp.Flows, 1)

		flowID := listResp.Flows[0].FlowID

		// Export the flow
		w = doRequest(t, srv, "POST", "/proxy/export", ProxyExportRequest{FlowID: flowID})

		assert.Equal(t, http.StatusOK, w.Code)

		var exportAPIResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &exportAPIResp))
		assert.True(t, exportAPIResp.OK)

		var exportResp ProxyExportResponse
		require.NoError(t, json.Unmarshal(exportAPIResp.Data, &exportResp))

		assert.NotEmpty(t, exportResp.BundleID)
		assert.NotEmpty(t, exportResp.BundlePath)

		// Verify bundle files exist
		assert.FileExists(t, filepath.Join(exportResp.BundlePath, "request.http"))
		assert.FileExists(t, filepath.Join(exportResp.BundlePath, "body.bin"))
		assert.FileExists(t, filepath.Join(exportResp.BundlePath, "request.meta.json"))
	})

	t.Run("body_not_corrupted", func(t *testing.T) {
		// Regression test: verify body.bin is not corrupted by header manipulation.
		// Previously, splitHeadersBody returned slices sharing the same underlying array,
		// and append() to headers could overwrite body data.
		srv, mockMCP, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		bodyContent := `{"user":"test","token":"abc123xyz"}`
		mockMCP.AddProxyEntry(
			"POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n"+bodyContent,
			"HTTP/1.1 200 OK\r\n\r\n",
			"",
		)

		// List to get flow ID
		w := doRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{Method: "POST"})
		require.Equal(t, http.StatusOK, w.Code)

		var listAPIResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listAPIResp))
		var listResp ProxyListResponse
		require.NoError(t, json.Unmarshal(listAPIResp.Data, &listResp))
		require.Len(t, listResp.Flows, 1)

		// Export the flow
		w = doRequest(t, srv, "POST", "/proxy/export", ProxyExportRequest{FlowID: listResp.Flows[0].FlowID})
		require.Equal(t, http.StatusOK, w.Code)

		var exportAPIResp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &exportAPIResp))
		var exportResp ProxyExportResponse
		require.NoError(t, json.Unmarshal(exportAPIResp.Data, &exportResp))

		// Read body.bin and verify it matches original body exactly
		bodyPath := filepath.Join(exportResp.BundlePath, "body.bin")
		actualBody, err := os.ReadFile(bodyPath)
		require.NoError(t, err)
		assert.Equal(t, bodyContent, string(actualBody), "body.bin should not be corrupted by header placeholder insertion")
	})

	t.Run("not_found", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		w := doRequest(t, srv, "POST", "/proxy/export", ProxyExportRequest{FlowID: "nonexistent"})

		assert.Equal(t, http.StatusNotFound, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeNotFound, resp.Error.Code)
	})

	t.Run("missing_id", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		w := doRequest(t, srv, "POST", "/proxy/export", ProxyExportRequest{})

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeInvalidRequest, resp.Error.Code)
	})
}

func TestApplyClientFilters(t *testing.T) {
	t.Parallel()

	entries := []flowEntry{
		{offset: 0, method: "GET", host: "api.example.com", path: "/users", status: 200, request: "GET /users"},
		{offset: 1, method: "POST", host: "api.example.com", path: "/users", status: 201, request: "POST /users"},
		{offset: 2, method: "GET", host: "other.com", path: "/page", status: 404, request: "GET /page"},
		{offset: 3, method: "DELETE", host: "api.example.com", path: "/users/1", status: 204, request: "DELETE /users/1"},
	}

	t.Run("filter by method", func(t *testing.T) {
		req := &ProxyListRequest{Method: "GET"}
		result := applyClientFilters(entries, req, nil, 0)
		assert.Len(t, result, 2)
		for _, e := range result {
			assert.Equal(t, "GET", e.method)
		}
	})

	t.Run("filter by status", func(t *testing.T) {
		req := &ProxyListRequest{Status: "200,201"}
		result := applyClientFilters(entries, req, nil, 0)
		assert.Len(t, result, 2)
	})

	t.Run("filter by host glob", func(t *testing.T) {
		req := &ProxyListRequest{Host: "*.example.com"}
		result := applyClientFilters(entries, req, nil, 0)
		assert.Len(t, result, 3)
	})

	t.Run("exclude host", func(t *testing.T) {
		req := &ProxyListRequest{ExcludeHost: "other.com", Method: "GET"}
		result := applyClientFilters(entries, req, nil, 0)
		assert.Len(t, result, 1)
		assert.Equal(t, "api.example.com", result[0].host)
	})

	t.Run("exclude path", func(t *testing.T) {
		req := &ProxyListRequest{ExcludePath: "/users*", Method: "GET,POST,DELETE"}
		result := applyClientFilters(entries, req, nil, 0)
		assert.Len(t, result, 1)
		assert.Equal(t, "/page", result[0].path)
	})
}

func TestReadResponseBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantStatus int
		wantProto  string
		wantErr    bool
	}{
		{
			name:       "http/1.1 response",
			input:      "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
			wantStatus: 200,
			wantProto:  "HTTP/1.1",
		},
		{
			name:       "http/1.0 response",
			input:      "HTTP/1.0 404 Not Found\r\n\r\n",
			wantStatus: 404,
			wantProto:  "HTTP/1.0",
		},
		{
			name:       "http/2 normalized and parsed",
			input:      "HTTP/2 200\r\nContent-Type: text/html\r\n\r\n",
			wantStatus: 200,
			wantProto:  "HTTP/2.0",
		},
		{
			name:       "http/2 with reason phrase",
			input:      "HTTP/2 301 Moved Permanently\r\nLocation: /new\r\n\r\n",
			wantStatus: 301,
			wantProto:  "HTTP/2.0",
		},
		{
			name:       "http/2.0 already normalized",
			input:      "HTTP/2.0 204 No Content\r\n\r\n",
			wantStatus: 204,
			wantProto:  "HTTP/2.0",
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "malformed response",
			input:   "not a valid http response",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := readResponseBytes([]byte(tt.input))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equal(t, tt.wantStatus, resp.StatusCode)
			assert.Equal(t, tt.wantProto, resp.Proto)
		})
	}
}

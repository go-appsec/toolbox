package service

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpdateContentLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers string
		length  int
		want    string
	}{
		{
			name:    "update existing",
			headers: "GET / HTTP/1.1\r\nContent-Length: 10\r\n\r\n",
			length:  42,
			want:    "GET / HTTP/1.1\r\nContent-Length: 42\r\n\r\n",
		},
		{
			name:    "add missing",
			headers: "POST / HTTP/1.1\r\nHost: x\r\n\r\n",
			length:  100,
			want:    "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n",
		},
		{
			name:    "zero length no add",
			headers: "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
			length:  0,
			want:    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		},
		{
			name:    "case insensitive",
			headers: "POST / HTTP/1.1\r\ncontent-length: 5\r\n\r\n",
			length:  20,
			want:    "POST / HTTP/1.1\r\nContent-Length: 20\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(updateContentLength([]byte(tt.headers), tt.length)))
		})
	}
}

func TestSetHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers string
		hName   string
		hValue  string
		want    string
	}{
		{
			name:    "add new header",
			headers: "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
			hName:   "Authorization",
			hValue:  "Bearer token",
			want:    "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer token\r\n\r\n",
		},
		{
			name:    "replace existing",
			headers: "GET / HTTP/1.1\r\nHost: old.com\r\n\r\n",
			hName:   "Host",
			hValue:  "new.com",
			want:    "GET / HTTP/1.1\r\nHost: new.com\r\n\r\n",
		},
		{
			name:    "case insensitive replace",
			headers: "GET / HTTP/1.1\r\nhost: old.com\r\n\r\n",
			hName:   "Host",
			hValue:  "new.com",
			want:    "GET / HTTP/1.1\r\nHost: new.com\r\n\r\n",
		},
		{
			name:    "replace first header",
			headers: "GET / HTTP/1.1\r\nHost: old.com\r\nCookie: abc\r\nAccept: */*\r\n\r\n",
			hName:   "Host",
			hValue:  "new.com",
			want:    "GET / HTTP/1.1\r\nHost: new.com\r\nCookie: abc\r\nAccept: */*\r\n\r\n",
		},
		{
			name:    "replace middle header",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nCookie: old\r\nAccept: */*\r\n\r\n",
			hName:   "Cookie",
			hValue:  "new",
			want:    "GET / HTTP/1.1\r\nHost: x\r\nCookie: new\r\nAccept: */*\r\n\r\n",
		},
		{
			name:    "replace last header",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nCookie: abc\r\nAccept: old\r\n\r\n",
			hName:   "Accept",
			hValue:  "application/json",
			want:    "GET / HTTP/1.1\r\nHost: x\r\nCookie: abc\r\nAccept: application/json\r\n\r\n",
		},
		{
			name:    "header with extra whitespace",
			headers: "GET / HTTP/1.1\r\nHost:   old.com  \r\n\r\n",
			hName:   "Host",
			hValue:  "new.com",
			want:    "GET / HTTP/1.1\r\nHost: new.com\r\n\r\n",
		},
		{
			name:    "header with tab",
			headers: "GET / HTTP/1.1\r\nHost:\told.com\r\n\r\n",
			hName:   "Host",
			hValue:  "new.com",
			want:    "GET / HTTP/1.1\r\nHost: new.com\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(setHeader([]byte(tt.headers), tt.hName, tt.hValue)))
		})
	}
}

func TestRemoveHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers string
		hName   string
		want    string
	}{
		{
			name:    "remove existing",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nCookie: abc\r\n\r\n",
			hName:   "Cookie",
			want:    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		},
		{
			name:    "case insensitive",
			headers: "GET / HTTP/1.1\r\nHost: x\r\ncookie: abc\r\n\r\n",
			hName:   "Cookie",
			want:    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		},
		{
			name:    "header not present - no change",
			headers: "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
			hName:   "Cookie",
			want:    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		},
		{
			name:    "remove first header",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nCookie: abc\r\nAccept: */*\r\n\r\n",
			hName:   "Host",
			want:    "GET / HTTP/1.1\r\nCookie: abc\r\nAccept: */*\r\n\r\n",
		},
		{
			name:    "remove middle header",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nCookie: abc\r\nAccept: */*\r\n\r\n",
			hName:   "Cookie",
			want:    "GET / HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n",
		},
		{
			name:    "remove last header",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nCookie: abc\r\nAccept: */*\r\n\r\n",
			hName:   "Accept",
			want:    "GET / HTTP/1.1\r\nHost: x\r\nCookie: abc\r\n\r\n",
		},
		{
			name:    "remove header with whitespace",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nCookie:   abc  \r\n\r\n",
			hName:   "Cookie",
			want:    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(removeHeader([]byte(tt.headers), tt.hName)))
		})
	}
}

func TestApplyHeaderModifications(t *testing.T) {
	t.Parallel()

	headers := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\n\r\n")

	req := &ReplaySendRequest{
		RemoveHeaders: []string{"Cookie"},
		AddHeaders:    []string{"Authorization: Bearer token"},
		Target:        "https://new.example.com",
	}

	newHeaders := applyHeaderModifications(headers, req)

	// Should have removed Cookie
	assert.NotContains(t, string(newHeaders), "Cookie:")

	// Should have added Authorization
	assert.Contains(t, string(newHeaders), "Authorization: Bearer token")

	// Should have updated Host from target
	assert.Contains(t, string(newHeaders), "Host: new.example.com")

	// Content-Length is updated separately, verify it works
	newHeaders = updateContentLength(newHeaders, 9)
	assert.Contains(t, string(newHeaders), "Content-Length: 9")
}

func TestValidateRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		raw       string
		hasErrors bool
	}{
		{
			name:      "valid request",
			raw:       "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			hasErrors: false,
		},
		{
			name:      "content length mismatch",
			raw:       "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n\r\nshort",
			hasErrors: true,
		},
		{
			name:      "invalid request",
			raw:       "invalid garbage request",
			hasErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := validateRequest([]byte(tt.raw))
			hasErrors := slices.ContainsFunc(issues, func(i validationIssue) bool { return i.Severity == "error" })
			if tt.hasErrors {
				assert.True(t, hasErrors)
			} else {
				assert.False(t, hasErrors, "expected no errors but got: %v", issues)
			}
		})
	}
}

func TestParseTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		raw       string
		override  string
		wantHost  string
		wantPort  int
		wantHTTPS bool
	}{
		{
			name:      "from host header",
			raw:       "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			override:  "",
			wantHost:  "example.com",
			wantPort:  443,
			wantHTTPS: true,
		},
		{
			name:      "from host header with port",
			raw:       "GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n",
			override:  "",
			wantHost:  "example.com",
			wantPort:  8080,
			wantHTTPS: true,
		},
		{
			name:      "override https",
			raw:       "GET / HTTP/1.1\r\nHost: old.com\r\n\r\n",
			override:  "https://new.com:9443",
			wantHost:  "new.com",
			wantPort:  9443,
			wantHTTPS: true,
		},
		{
			name:      "override http",
			raw:       "GET / HTTP/1.1\r\nHost: old.com\r\n\r\n",
			override:  "http://new.com",
			wantHost:  "new.com",
			wantPort:  80,
			wantHTTPS: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, usesHTTPS := parseTarget([]byte(tt.raw), tt.override)
			assert.Equal(t, tt.wantHost, host)
			assert.Equal(t, tt.wantPort, port)
			assert.Equal(t, tt.wantHTTPS, usesHTTPS)
		})
	}
}

func TestParseBurpResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{
			name:    "valid response",
			raw:     `HttpRequestResponse{httpRequest=GET / HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>body</html>, messageAnnotations=Annotations{}}`,
			wantErr: false,
		},
		{
			name:    "no httpResponse",
			raw:     `HttpRequestResponse{httpRequest=GET / HTTP/1.1}`,
			wantErr: true,
		},
		{
			name:    "no HTTP/ in response",
			raw:     `HttpRequestResponse{httpRequest=GET / HTTP/1.1, httpResponse=invalid, messageAnnotations=Annotations{}}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers, body, err := parseBurpResponse(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, headers)
				_ = body // body may be empty
			}
		})
	}
}

func TestFormatIssues(t *testing.T) {
	t.Parallel()

	issues := []validationIssue{
		{Check: "parse", Severity: "error", Detail: "invalid syntax"},
		{Check: "host", Severity: "warning", Detail: "missing Host header"},
	}

	result := formatIssues(issues)

	assert.Contains(t, result, "parse")
	assert.Contains(t, result, "error")
	assert.Contains(t, result, "invalid syntax")
	assert.Contains(t, result, "host")
	assert.Contains(t, result, "warning")
}

func TestBundleRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Write bundle
	headers := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n")
	body := []byte(`{"key": "value"}`)
	meta := &bundleMeta{
		BundleID:   "test123",
		URL:        "https://example.com/api",
		Method:     "POST",
		BodyIsUTF8: true,
		BodySize:   len(body),
	}

	err := writeBundle(dir, headers, body, meta)
	require.NoError(t, err)

	readHeaders, readBody, readMeta, err := readBundle(dir)
	require.NoError(t, err)

	assert.Contains(t, string(readHeaders), "POST /api HTTP/1.1")
	assert.Contains(t, string(readHeaders), bodyPlaceholder)
	assert.Equal(t, body, readBody)
	assert.Equal(t, "test123", readMeta.BundleID)
	assert.Equal(t, "POST", readMeta.Method)
	assert.True(t, readMeta.BodyIsUTF8)

	// Reconstruct
	reconstructed := reconstructRequest(readHeaders, readBody)
	assert.Contains(t, string(reconstructed), "POST /api HTTP/1.1")
	assert.Contains(t, string(reconstructed), `{"key": "value"}`)
	assert.NotContains(t, string(reconstructed), bodyPlaceholder)
}

func TestHandleReplaySend(t *testing.T) {
	t.Parallel()

	t.Run("from_bundle", func(t *testing.T) {
		srv, mockMCP, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		// Create a bundle manually
		bundleDir := filepath.Join(t.TempDir(), "test-bundle")
		require.NoError(t, os.MkdirAll(bundleDir, 0755))

		headers := []byte("GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n")
		body := []byte("")
		meta := &bundleMeta{
			BundleID: "test123",
			URL:      "https://example.com/api/test",
			Method:   "GET",
		}
		require.NoError(t, writeBundle(bundleDir, headers, body, meta))

		mockMCP.SetSendResponse(`HttpRequestResponse{httpRequest=GET /api/test HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"status": "ok"}, messageAnnotations=Annotations{}}`)

		w := doRequest(t, srv, "POST", "/replay/send", ReplaySendRequest{BundlePath: bundleDir})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var replayResp ReplaySendResponse
		require.NoError(t, json.Unmarshal(resp.Data, &replayResp))

		assert.NotEmpty(t, replayResp.ReplayID)
		assert.NotEmpty(t, replayResp.Duration)
		assert.Equal(t, 200, replayResp.Status)
	})

	t.Run("from_id", func(t *testing.T) {
		srv, mockMCP, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		mockMCP.AddProxyEntry(
			"GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\noriginal",
			"",
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

		mockMCP.SetSendResponse(`HttpRequestResponse{httpRequest=GET /api/test HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\n\r\nreplayed, messageAnnotations=Annotations{}}`)

		// Replay from flow ID
		w = doRequest(t, srv, "POST", "/replay/send", ReplaySendRequest{FlowID: flowID})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var replayResp ReplaySendResponse
		require.NoError(t, json.Unmarshal(resp.Data, &replayResp))

		assert.NotEmpty(t, replayResp.ReplayID)
		assert.Equal(t, 200, replayResp.Status)
	})

	t.Run("header_modify", func(t *testing.T) {
		srv, mockMCP, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		// Create a bundle
		bundleDir := filepath.Join(t.TempDir(), "test-bundle")
		require.NoError(t, os.MkdirAll(bundleDir, 0755))

		headers := []byte("GET /api HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc\r\n\r\n")
		require.NoError(t, writeBundle(bundleDir, headers, nil, &bundleMeta{BundleID: "test"}))

		mockMCP.SetSendResponse(
			`HttpRequestResponse{httpRequest=modified, httpResponse=HTTP/1.1 200 OK\r\n\r\nok, messageAnnotations=Annotations{}}`,
		)

		w := doRequest(t, srv, "POST", "/replay/send", ReplaySendRequest{
			BundlePath:    bundleDir,
			AddHeaders:    []string{"Authorization: Bearer token"},
			RemoveHeaders: []string{"Cookie"},
		})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)
	})

	t.Run("from_file_complete", func(t *testing.T) {
		srv, mockMCP, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		// Create a file with a complete request (headers + body)
		tmpFile := filepath.Join(t.TempDir(), "request.http")
		completeRequest := "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\n{\"foo\":\"bar\"}"
		require.NoError(t, os.WriteFile(tmpFile, []byte(completeRequest), 0644))

		mockMCP.SetSendResponse(`HttpRequestResponse{httpRequest=POST /api HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\n\r\nok, messageAnnotations=Annotations{}}`)

		w := doRequest(t, srv, "POST", "/replay/send", ReplaySendRequest{FilePath: tmpFile})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var replayResp ReplaySendResponse
		require.NoError(t, json.Unmarshal(resp.Data, &replayResp))
		assert.Equal(t, 200, replayResp.Status)
	})

	t.Run("from_file_with_body", func(t *testing.T) {
		srv, mockMCP, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		tmpDir := t.TempDir()

		// Create headers file with placeholder
		headersFile := filepath.Join(tmpDir, "request.http")
		headers := "POST /api HTTP/1.1\r\nHost: example.com\r\n" + bodyPlaceholder + "\n"
		require.NoError(t, os.WriteFile(headersFile, []byte(headers), 0644))

		// Create separate body file
		bodyFile := filepath.Join(tmpDir, "body.bin")
		body := `{"merged":"body"}`
		require.NoError(t, os.WriteFile(bodyFile, []byte(body), 0644))

		mockMCP.SetSendResponse(`HttpRequestResponse{httpRequest=POST /api HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\n\r\nok, messageAnnotations=Annotations{}}`)

		w := doRequest(t, srv, "POST", "/replay/send", ReplaySendRequest{
			FilePath: headersFile,
			BodyPath: bodyFile,
		})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var replayResp ReplaySendResponse
		require.NoError(t, json.Unmarshal(resp.Data, &replayResp))
		assert.Equal(t, 200, replayResp.Status)
	})

	t.Run("no_input", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		w := doRequest(t, srv, "POST", "/replay/send", ReplaySendRequest{})

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeInvalidRequest, resp.Error.Code)
	})

	t.Run("id_not_found", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		w := doRequest(t, srv, "POST", "/replay/send", ReplaySendRequest{FlowID: "nonexistent"})

		assert.Equal(t, http.StatusNotFound, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeNotFound, resp.Error.Code)
	})
}

func TestHandleReplayGet(t *testing.T) {
	t.Parallel()

	t.Run("not_found", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		w := doRequest(t, srv, "POST", "/replay/get", ReplayGetRequest{ReplayID: "test123"})

		assert.Equal(t, http.StatusNotFound, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeNotFound, resp.Error.Code)
	})
}

func TestWriteResponseToBundle(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	respHeaders := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
	respBody := []byte("<html>test</html>")

	err := writeResponseToBundle(dir, respHeaders, respBody)
	require.NoError(t, err)

	// Verify files exist
	assert.FileExists(t, filepath.Join(dir, "response.http"))
	assert.FileExists(t, filepath.Join(dir, "response.body.bin"))

	// Verify content
	headerContent, err := os.ReadFile(filepath.Join(dir, "response.http"))
	require.NoError(t, err)
	assert.Equal(t, respHeaders, headerContent)

	bodyContent, err := os.ReadFile(filepath.Join(dir, "response.body.bin"))
	require.NoError(t, err)
	assert.Equal(t, respBody, bodyContent)
}

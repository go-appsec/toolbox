package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/llm-security-toolbox/sectool/service/store"
)

func newTestHTTP1Handler(t *testing.T) *http1Handler {
	t.Helper()

	history := newHistoryStore(store.NewMemStorage())
	t.Cleanup(history.Close)
	return &http1Handler{history: history}
}

func TestExtractTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		path     string
		headers  []Header
		wantHost string
		wantPort int
		wantTLS  bool
		wantErr  string
	}{
		// proxy form cases
		{
			name:     "http_default_port",
			path:     "http://example.com/path",
			wantHost: "example.com",
			wantPort: 80,
			wantTLS:  false,
		},
		{
			name:     "http_custom_port",
			path:     "http://example.com:8080/path",
			wantHost: "example.com",
			wantPort: 8080,
			wantTLS:  false,
		},
		{
			name:     "https_default_port",
			path:     "https://example.com/path",
			wantHost: "example.com",
			wantPort: 443,
			wantTLS:  true,
		},
		{
			name:     "https_custom_port",
			path:     "https://example.com:8443/path",
			wantHost: "example.com",
			wantPort: 8443,
			wantTLS:  true,
		},
		// host header cases
		{
			name:     "host_only",
			path:     "/path",
			headers:  []Header{{Name: "Host", Value: "example.com"}},
			wantHost: "example.com",
			wantPort: 80,
			wantTLS:  false,
		},
		{
			name:     "host_with_port",
			path:     "/path",
			headers:  []Header{{Name: "Host", Value: "example.com:8080"}},
			wantHost: "example.com",
			wantPort: 8080,
			wantTLS:  false,
		},
		// IPv6 cases
		{
			name:     "ipv6_brackets_http",
			path:     "/path",
			headers:  []Header{{Name: "Host", Value: "[::1]"}},
			wantHost: "::1",
			wantPort: 80,
			wantTLS:  false,
		},
		{
			name:     "ipv6_brackets_with_port",
			path:     "/path",
			headers:  []Header{{Name: "Host", Value: "[::1]:8080"}},
			wantHost: "::1",
			wantPort: 8080,
			wantTLS:  false,
		},
		{
			name:     "ipv6_proxy_form",
			path:     "http://[::1]:8080/path",
			wantHost: "::1",
			wantPort: 8080,
			wantTLS:  false,
		},
		// error cases
		{
			name:    "no_host",
			path:    "/path",
			wantErr: "no Host header",
		},
		{
			name:    "empty_host_header",
			path:    "/path",
			headers: []Header{{Name: "Host", Value: ""}},
			wantErr: "no Host header",
		},
		// edge cases
		{
			name:     "host_with_trailing_dot",
			path:     "/path",
			headers:  []Header{{Name: "Host", Value: "example.com."}},
			wantHost: "example.com.",
			wantPort: 80,
			wantTLS:  false,
		},
		{
			name:     "localhost",
			path:     "/path",
			headers:  []Header{{Name: "Host", Value: "localhost"}},
			wantHost: "localhost",
			wantPort: 80,
			wantTLS:  false,
		},
		{
			name:     "localhost_with_port",
			path:     "/path",
			headers:  []Header{{Name: "Host", Value: "localhost:8080"}},
			wantHost: "localhost",
			wantPort: 8080,
			wantTLS:  false,
		},
		{
			name:     "ipv4_localhost",
			path:     "/path",
			headers:  []Header{{Name: "Host", Value: "127.0.0.1:3000"}},
			wantHost: "127.0.0.1",
			wantPort: 3000,
			wantTLS:  false,
		},
		{
			name:     "http_proxy_no_path",
			path:     "http://example.com",
			wantHost: "example.com",
			wantPort: 80,
			wantTLS:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHTTP1Handler(t)

			req := &RawHTTP1Request{
				Method:  "GET",
				Path:    tt.path,
				Version: "HTTP/1.1",
				Headers: tt.headers,
			}

			target, err := h.extractTarget(req)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantHost, target.Hostname)
			assert.Equal(t, tt.wantPort, target.Port)
			assert.Equal(t, tt.wantTLS, target.UsesHTTPS)
		})
	}
}

func TestRewriteToOriginForm(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		inputPath   string
		inputQuery  string
		target      *Target
		wantPath    string
		wantHostHdr string
	}{
		{
			name:       "proxy_form_to_origin",
			inputPath:  "http://example.com/api/users",
			inputQuery: "id=123",
			target: &Target{
				Hostname:  "example.com",
				Port:      80,
				UsesHTTPS: false,
			},
			wantPath:    "/api/users",
			wantHostHdr: "example.com",
		},
		{
			name:       "https_proxy_form",
			inputPath:  "https://secure.example.com:8443/path",
			inputQuery: "",
			target: &Target{
				Hostname:  "secure.example.com",
				Port:      8443,
				UsesHTTPS: true,
			},
			wantPath:    "/path",
			wantHostHdr: "secure.example.com:8443",
		},
		{
			name:       "already_origin_form",
			inputPath:  "/already/origin",
			inputQuery: "",
			target: &Target{
				Hostname:  "example.com",
				Port:      80,
				UsesHTTPS: false,
			},
			wantPath:    "/already/origin",
			wantHostHdr: "example.com",
		},
		{
			name:       "root_path",
			inputPath:  "http://example.com",
			inputQuery: "",
			target: &Target{
				Hostname:  "example.com",
				Port:      80,
				UsesHTTPS: false,
			},
			wantPath:    "/",
			wantHostHdr: "example.com",
		},
		{
			name:       "non_standard_http_port",
			inputPath:  "/path",
			inputQuery: "",
			target: &Target{
				Hostname:  "example.com",
				Port:      8080,
				UsesHTTPS: false,
			},
			wantPath:    "/path",
			wantHostHdr: "example.com:8080",
		},
		{
			name:       "query_only_in_path",
			inputPath:  "http://example.com?foo=bar",
			inputQuery: "",
			target: &Target{
				Hostname:  "example.com",
				Port:      80,
				UsesHTTPS: false,
			},
			wantPath:    "/",
			wantHostHdr: "example.com",
		},
		{
			name:       "path_with_fragment",
			inputPath:  "http://example.com/page#section",
			inputQuery: "",
			target: &Target{
				Hostname:  "example.com",
				Port:      80,
				UsesHTTPS: false,
			},
			wantPath:    "/page", // url.Parse puts fragments in u.Fragment, not u.Path
			wantHostHdr: "example.com",
		},
		{
			name:       "ipv6_host",
			inputPath:  "/api",
			inputQuery: "",
			target: &Target{
				Hostname:  "::1",
				Port:      8080,
				UsesHTTPS: false,
			},
			wantPath:    "/api",
			wantHostHdr: "::1:8080", // no brackets added by rewriteToOriginForm
		},
		{
			name:       "standard_https_port",
			inputPath:  "/secure",
			inputQuery: "",
			target: &Target{
				Hostname:  "secure.example.com",
				Port:      443,
				UsesHTTPS: true,
			},
			wantPath:    "/secure",
			wantHostHdr: "secure.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHTTP1Handler(t)

			req := &RawHTTP1Request{
				Method:  "GET",
				Path:    tt.inputPath,
				Query:   tt.inputQuery,
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "original.host"},
				},
			}

			h.rewriteToOriginForm(req, tt.target)

			assert.Equal(t, tt.wantPath, req.Path)
			assert.Equal(t, tt.wantHostHdr, req.GetHeader("Host"))
		})
	}
}

func TestParseHostPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		hostPort  string
		usesHTTPS bool
		wantHost  string
		wantPort  int
		wantErr   bool
	}{
		{
			name:      "host_only_http",
			hostPort:  "example.com",
			usesHTTPS: false,
			wantHost:  "example.com",
			wantPort:  80,
		},
		{
			name:      "host_only_https",
			hostPort:  "example.com",
			usesHTTPS: true,
			wantHost:  "example.com",
			wantPort:  443,
		},
		{
			name:      "host_with_port",
			hostPort:  "example.com:8080",
			usesHTTPS: false,
			wantHost:  "example.com",
			wantPort:  8080,
		},
		{
			name:      "ipv4_with_port",
			hostPort:  "192.168.1.1:9000",
			usesHTTPS: false,
			wantHost:  "192.168.1.1",
			wantPort:  9000,
		},
		{
			name:     "invalid_port",
			hostPort: "example.com:abc",
			wantErr:  true,
		},
		{
			name:      "ipv6_brackets_with_port",
			hostPort:  "[::1]:8080",
			usesHTTPS: false,
			wantHost:  "::1",
			wantPort:  8080,
		},
		{
			name:      "ipv6_brackets_no_port",
			hostPort:  "[::1]",
			usesHTTPS: false,
			wantHost:  "::1",
			wantPort:  80,
		},
		{
			name:      "ipv6_full_with_port",
			hostPort:  "[2001:db8::1]:443",
			usesHTTPS: true,
			wantHost:  "2001:db8::1",
			wantPort:  443,
		},
		{
			name:      "port_zero",
			hostPort:  "example.com:0",
			usesHTTPS: false,
			wantHost:  "example.com",
			wantPort:  0,
		},
		{
			name:      "high_port",
			hostPort:  "example.com:65535",
			usesHTTPS: false,
			wantHost:  "example.com",
			wantPort:  65535,
		},
		// Note: parseHostPort intentionally doesn't validate port ranges
		// to support security testing scenarios with unusual port values
		{
			name:      "port_out_of_range",
			hostPort:  "example.com:99999",
			usesHTTPS: false,
			wantHost:  "example.com",
			wantPort:  99999,
		},
		{
			name:      "negative_port",
			hostPort:  "example.com:-1",
			usesHTTPS: false,
			wantHost:  "example.com",
			wantPort:  -1,
		},
		{
			name:      "empty_string",
			hostPort:  "",
			usesHTTPS: false,
			wantHost:  "",
			wantPort:  80,
		},
		{
			name:      "colon_only",
			hostPort:  ":",
			usesHTTPS: false,
			wantErr:   true,
		},
		{
			name:      "ipv6_no_brackets",
			hostPort:  "::1",
			usesHTTPS: false,
			wantHost:  "::1",
			wantPort:  80,
		},
		{
			name:      "ipv6_unclosed_bracket",
			hostPort:  "[::1",
			usesHTTPS: false,
			wantHost:  "::1", // TrimPrefix/TrimSuffix removes brackets
			wantPort:  80,
		},
		{
			name:      "subdomain_with_hyphen",
			hostPort:  "my-api.example-service.com:8080",
			usesHTTPS: false,
			wantHost:  "my-api.example-service.com",
			wantPort:  8080,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHTTP1Handler(t)

			target, err := h.parseHostPort(tt.hostPort, tt.usesHTTPS)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantHost, target.Hostname)
			assert.Equal(t, tt.wantPort, target.Port)
			assert.Equal(t, tt.usesHTTPS, target.UsesHTTPS)
		})
	}
}

func TestSendError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		code       int
		message    string
		wantStatus string
		wantBody   string
	}{
		{
			name:       "bad_request",
			code:       400,
			message:    "Bad Request",
			wantStatus: "400 Bad Request",
			wantBody:   "Bad Request\n",
		},
		{
			name:       "bad_gateway",
			code:       502,
			message:    "Bad Gateway",
			wantStatus: "502 Bad Gateway",
			wantBody:   "Bad Gateway\n",
		},
		{
			name:       "internal_error",
			code:       500,
			message:    "Internal Server Error",
			wantStatus: "500 Internal Server Error",
			wantBody:   "Internal Server Error\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHTTP1Handler(t)

			// Use a pipe to capture the response
			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				_ = clientConn.Close()
				_ = serverConn.Close()
			})

			go h.sendError(serverConn, tt.code, tt.message)

			// Read the response
			buf := make([]byte, 1024)
			n, err := clientConn.Read(buf)
			require.NoError(t, err)

			response := string(buf[:n])

			// Verify response format
			assert.Contains(t, response, "HTTP/1.1 "+tt.wantStatus)
			assert.Contains(t, response, "Content-Type: text/plain")
			assert.Contains(t, response, "Connection: close")
			assert.Contains(t, response, tt.wantBody)
		})
	}
}

func TestStoreEntry(t *testing.T) {
	t.Parallel()

	t.Run("stores_request_response", func(t *testing.T) {
		h := newTestHTTP1Handler(t)

		req := &RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []Header{{Name: "Host", Value: "example.com"}},
		}
		resp := &RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Body:       []byte("response body"),
		}
		startTime := time.Now()

		h.storeEntry(req, resp, startTime)

		// Verify entry was stored
		assert.Equal(t, 1, h.history.Count())

		entry, ok := h.history.Get(0)
		require.True(t, ok)
		assert.Equal(t, "http/1.1", entry.Protocol)
		assert.Equal(t, "GET", entry.Request.Method)
		assert.Equal(t, 200, entry.Response.StatusCode)
	})

	t.Run("stores_entry_with_nil_response", func(t *testing.T) {
		h := newTestHTTP1Handler(t)

		req := &RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []Header{{Name: "Host", Value: "example.com"}},
		}
		startTime := time.Now()

		h.storeEntry(req, nil, startTime)

		assert.Equal(t, 1, h.history.Count())

		entry, ok := h.history.Get(0)
		require.True(t, ok)
		assert.Nil(t, entry.Response)
	})
}

package proxy

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

func TestMustBufferResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers types.Headers
		want    bool
	}{
		{"compressed", types.Headers{{Name: "Content-Encoding", Value: "gzip"}, {Name: "Content-Length", Value: "10"}}, true},
		{"content_length", types.Headers{{Name: "Content-Length", Value: "10"}}, true},
		{"chunked", types.Headers{{Name: "Transfer-Encoding", Value: "chunked"}}, false},
		{"chunked_over_length", types.Headers{{Name: "Transfer-Encoding", Value: "chunked"}, {Name: "Content-Length", Value: "10"}}, false},
		{"close_delimited", types.Headers{{Name: "Content-Type", Value: "text/event-stream"}}, false},
		{"invalid_content_length", types.Headers{{Name: "Content-Length", Value: "notanumber"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &types.RawHTTP1Response{StatusCode: 200, Headers: tt.headers}
			assert.Equal(t, tt.want, mustBufferResponse(resp))
		})
	}
}

func newTestHTTP1Handler(t *testing.T) *http1Handler {
	t.Helper()

	history := newHistoryStore(store.NewMemStorage())
	t.Cleanup(history.Close)
	return &http1Handler{history: history, reg: &protocol.Registry{}}
}

// firstEntry returns the oldest Flow in h. Test helper for offset-free assertions.
func firstEntry(t *testing.T, h *HistoryStore) *types.Flow {
	t.Helper()

	entries := h.Page(1, "")
	require.Len(t, entries, 1)
	return entries[0]
}

func TestExtractTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		path     string
		headers  []types.Header
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
			headers:  []types.Header{{Name: "Host", Value: "example.com"}},
			wantHost: "example.com",
			wantPort: 80,
			wantTLS:  false,
		},
		{
			name:     "host_with_port",
			path:     "/path",
			headers:  []types.Header{{Name: "Host", Value: "example.com:8080"}},
			wantHost: "example.com",
			wantPort: 8080,
			wantTLS:  false,
		},
		// IPv6 cases
		{
			name:     "ipv6_brackets_http",
			path:     "/path",
			headers:  []types.Header{{Name: "Host", Value: "[::1]"}},
			wantHost: "::1",
			wantPort: 80,
			wantTLS:  false,
		},
		{
			name:     "ipv6_brackets_with_port",
			path:     "/path",
			headers:  []types.Header{{Name: "Host", Value: "[::1]:8080"}},
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
			headers: []types.Header{{Name: "Host", Value: ""}},
			wantErr: "no Host header",
		},
		// edge cases
		{
			name:     "host_with_trailing_dot",
			path:     "/path",
			headers:  []types.Header{{Name: "Host", Value: "example.com."}},
			wantHost: "example.com.",
			wantPort: 80,
			wantTLS:  false,
		},
		{
			name:     "localhost",
			path:     "/path",
			headers:  []types.Header{{Name: "Host", Value: "localhost"}},
			wantHost: "localhost",
			wantPort: 80,
			wantTLS:  false,
		},
		{
			name:     "localhost_with_port",
			path:     "/path",
			headers:  []types.Header{{Name: "Host", Value: "localhost:8080"}},
			wantHost: "localhost",
			wantPort: 8080,
			wantTLS:  false,
		},
		{
			name:     "ipv4_localhost",
			path:     "/path",
			headers:  []types.Header{{Name: "Host", Value: "127.0.0.1:3000"}},
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

			req := &types.RawHTTP1Request{
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
		target      *types.Target
		wantPath    string
		wantHostHdr string
	}{
		{
			name:       "proxy_form_to_origin",
			inputPath:  "http://example.com/api/users",
			inputQuery: "id=123",
			target: &types.Target{
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
			target: &types.Target{
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
			target: &types.Target{
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
			target: &types.Target{
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
			target: &types.Target{
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
			target: &types.Target{
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
			target: &types.Target{
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
			target: &types.Target{
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
			target: &types.Target{
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

			req := &types.RawHTTP1Request{
				Method:  "GET",
				Path:    tt.inputPath,
				Query:   tt.inputQuery,
				Version: "HTTP/1.1",
				Headers: []types.Header{
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
			// Use a pipe to capture the response
			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				_ = clientConn.Close()
				_ = serverConn.Close()
			})

			go sendError(serverConn, tt.code, tt.message)

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

		req := &types.RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []types.Header{{Name: "Host", Value: "example.com"}},
		}
		resp := &types.RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Body:       []byte("response body"),
		}
		startTime := time.Now()

		h.storeEntry(&types.Target{Hostname: "example.com", Port: 80}, req, resp, nil, startTime)

		// Verify entry was stored
		assert.Equal(t, 1, h.history.Count())

		entry := firstEntry(t, h.history)
		assert.Equal(t, "http/1.1", entry.ProtocolTag)
		assert.Equal(t, "GET", entry.Request.Method)
		assert.Equal(t, 200, entry.Response.StatusCode)
		assert.Equal(t, "http", entry.Scheme)
		assert.Equal(t, 80, entry.Port)
	})

	t.Run("records_https_scheme", func(t *testing.T) {
		h := newTestHTTP1Handler(t)

		req := &types.RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []types.Header{{Name: "Host", Value: "example.com"}},
		}
		startTime := time.Now()

		h.storeEntry(&types.Target{Hostname: "example.com", Port: 8443, UsesHTTPS: true}, req, nil, nil, startTime)

		entry := firstEntry(t, h.history)
		assert.Equal(t, "https", entry.Scheme)
		assert.Equal(t, 8443, entry.Port)
	})

	t.Run("stores_entry_with_nil_response", func(t *testing.T) {
		h := newTestHTTP1Handler(t)

		req := &types.RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []types.Header{{Name: "Host", Value: "example.com"}},
		}
		startTime := time.Now()

		h.storeEntry(&types.Target{Hostname: "example.com", Port: 80}, req, nil, nil, startTime)

		assert.Equal(t, 1, h.history.Count())

		entry := firstEntry(t, h.history)
		assert.Nil(t, entry.Response)
	})
}

func TestHandleSinglePlainHTTPInterim(t *testing.T) {
	t.Parallel()

	// Upstream that emits a 103 interim response before the final 200.
	var lc net.ListenConfig
	upstream, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = upstream.Close() })

	go func() {
		conn, aerr := upstream.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		br := bufio.NewReader(conn)
		for { // drain request headers
			line, rerr := br.ReadString('\n')
			if rerr != nil || line == "\r\n" {
				break
			}
		}
		_, _ = conn.Write([]byte("HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n"))
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi"))
	}()

	h := newTestHTTP1Handler(t)
	clientConn, proxyConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })

	go func() {
		h.handleExchange(t.Context(), proxyConn, bufio.NewReader(proxyConn), h1Exchange{logParseErrors: true})
		_ = proxyConn.Close()
	}()

	_, err = clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + upstream.Addr().String() + "\r\n\r\n"))
	require.NoError(t, err)

	respData, err := io.ReadAll(clientConn)
	require.NoError(t, err)
	respStr := string(respData)
	assert.Contains(t, respStr, "103 Early Hints")
	assert.Contains(t, respStr, "200 OK")
	assert.Less(t, strings.Index(respStr, "103"), strings.Index(respStr, "200 OK"))

	require.Equal(t, 1, h.history.Count())
	entry := firstEntry(t, h.history)
	require.NotNil(t, entry.Response)
	assert.Equal(t, 200, entry.Response.StatusCode)
	require.Len(t, entry.InterimResponses, 1)
	assert.Equal(t, 103, entry.InterimResponses[0].StatusCode)
}

// mockInterceptor serves resp when host and path match exactly (case-sensitive), so a
// caller that fails to lowercase the host misses the responder.
type mockInterceptor struct {
	host string
	path string
	resp *InterceptedResponse
}

func (m *mockInterceptor) InterceptRequest(host string, _ int, path, _ string) *InterceptedResponse {
	if host == m.host && path == m.path {
		return m.resp
	}
	return nil
}

func TestHandleExchange(t *testing.T) {
	t.Parallel()

	const cannedBody = "intercepted"
	newHandler := func(t *testing.T) *http1Handler {
		t.Helper()
		h := newTestHTTP1Handler(t)
		h.responseInterceptor = &mockInterceptor{
			host: "example.com",
			path: "/canned",
			resp: &InterceptedResponse{
				StatusCode: 200,
				Headers:    types.Headers{{Name: "Content-Type", Value: "text/plain"}},
				Body:       []byte(cannedBody),
			},
		}
		return h
	}

	// case-variant Host must still resolve the lowercase-registered responder on both
	// the plain (target derived from request) and TLS (target preset) entry paths
	paths := []struct {
		name    string
		newExch func(t *testing.T) h1Exchange
	}{
		{"plain", func(_ *testing.T) h1Exchange { return h1Exchange{logParseErrors: true} }},
		{"tls", func(t *testing.T) h1Exchange {
			t.Helper()
			up, upEnd := net.Pipe()
			t.Cleanup(func() { _ = up.Close(); _ = upEnd.Close() })
			return h1Exchange{
				target:   &types.Target{Hostname: "Example.COM", Port: 443, UsesHTTPS: true},
				upstream: &upstreamPair{conn: up, reader: bufio.NewReader(up)},
			}
		}},
	}
	for _, p := range paths {
		t.Run("case_variant_host_"+p.name, func(t *testing.T) {
			h := newHandler(t)
			clientConn, proxyConn := net.Pipe()
			t.Cleanup(func() { _ = clientConn.Close() })

			go func() {
				h.handleExchange(t.Context(), proxyConn, bufio.NewReader(proxyConn), p.newExch(t))
				_ = proxyConn.Close()
			}()

			_, err := clientConn.Write([]byte("GET /canned HTTP/1.1\r\nHost: Example.COM\r\n\r\n"))
			require.NoError(t, err)

			respData, err := io.ReadAll(clientConn)
			require.NoError(t, err)
			assert.Contains(t, string(respData), "200")
			assert.Contains(t, string(respData), cannedBody)

			// flow is stored before the client reacts to the response
			require.Equal(t, 1, h.history.Count())
			assert.Equal(t, 200, firstEntry(t, h.history).Response.StatusCode)
		})
	}

	t.Run("intercepted_write_deadline", func(t *testing.T) {
		h := newHandler(t)
		h.timeouts = TimeoutConfig{WriteTimeout: 50 * time.Millisecond}

		clientConn, proxyConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })

		done := make(chan struct{})
		go func() {
			h.handleExchange(t.Context(), proxyConn, bufio.NewReader(proxyConn), h1Exchange{logParseErrors: true})
			close(done)
		}()

		_, err := clientConn.Write([]byte("GET /canned HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		require.NoError(t, err)

		// client never reads; the write deadline must unblock the handler goroutine
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("handleExchange hung on intercepted write without a deadline")
		}
		assert.Equal(t, 1, h.history.Count())
	})
}

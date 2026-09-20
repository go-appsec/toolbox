package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
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

// fakeNetError is a net.Error with a controllable Timeout result.
type fakeNetError struct{ timeout bool }

func (e fakeNetError) Error() string   { return "fake net error" }
func (e fakeNetError) Timeout() bool   { return e.timeout }
func (e fakeNetError) Temporary() bool { return false }

func TestStreamAnnotations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		clientErr    error
		readErr      error
		bodyComplete bool
		wantReason   any
	}{
		{"client_disconnect", io.EOF, fakeNetError{timeout: true}, false, reasonClientDisconnect},
		{"complete", nil, nil, true, nil},
		{"stream_idle", nil, fakeNetError{timeout: true}, false, reasonStreamIdle},
		{"upstream_error", nil, io.ErrUnexpectedEOF, false, reasonUpstreamError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ann := streamAnnotations(tt.clientErr, tt.readErr, tt.bodyComplete, false)
			if tt.wantReason == nil {
				assert.Nil(t, ann)
				return
			}
			assert.Equal(t, tt.wantReason, ann[annStreamReason])
			assert.Equal(t, true, ann[annStreamTruncated])
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

// startUpstream serves one connection: it reads a full request, publishes it on the
// returned channel, then writes resp. Returns the listener address.
func startUpstream(t *testing.T, resp string) (string, <-chan *types.RawHTTP1Request) {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	reqCh := make(chan *types.RawHTTP1Request, 1)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		req, perr := ParseRequest(conn, false)
		if perr != nil {
			return
		}
		reqCh <- req
		_, _ = conn.Write([]byte(resp))
	}()
	return ln.Addr().String(), reqCh
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
			wantHostHdr: "[::1]:8080", // IPv6 literal is bracketed
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
		// parseHostPort intentionally doesn't validate port ranges to support
		// security testing scenarios with unusual port values
		{
			name:      "port_out_of_range",
			hostPort:  "example.com:99999",
			usesHTTPS: false,
			wantHost:  "example.com",
			wantPort:  99999,
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

		h.storeEntry(&types.Target{Hostname: "example.com", Port: 80}, req, resp, nil, startTime, nil)

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

		h.storeEntry(&types.Target{Hostname: "example.com", Port: 8443, UsesHTTPS: true}, req, nil, nil, startTime, nil)

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

		h.storeEntry(&types.Target{Hostname: "example.com", Port: 80}, req, nil, nil, startTime, nil)

		assert.Equal(t, 1, h.history.Count())

		entry := firstEntry(t, h.history)
		assert.Nil(t, entry.Response)
	})
}

func TestExpectsContinue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version string
		headers types.Headers
		want    bool
	}{
		{"content_length_body", "HTTP/1.1", types.Headers{{Name: "Expect", Value: "100-continue"}, {Name: "Content-Length", Value: "5"}}, true},
		{"chunked_body", "HTTP/1.1", types.Headers{{Name: "Expect", Value: "100-continue"}, {Name: "Transfer-Encoding", Value: "chunked"}}, true},
		{"case_variant_header", "HTTP/1.1", types.Headers{{Name: "expect", Value: "100-Continue"}, {Name: "Content-Length", Value: "5"}}, true},
		{"compound_expectation", "HTTP/1.1", types.Headers{{Name: "Expect", Value: "100-continue, extend"}, {Name: "Content-Length", Value: "5"}}, true},
		{"trailing_expectation", "HTTP/1.1", types.Headers{{Name: "Expect", Value: "extend,100-continue"}, {Name: "Content-Length", Value: "5"}}, true},
		{"no_body", "HTTP/1.1", types.Headers{{Name: "Expect", Value: "100-continue"}}, false},
		{"zero_content_length", "HTTP/1.1", types.Headers{{Name: "Expect", Value: "100-continue"}, {Name: "Content-Length", Value: "0"}}, false},
		{"http10_client", "HTTP/1.0", types.Headers{{Name: "Expect", Value: "100-continue"}, {Name: "Content-Length", Value: "5"}}, false},
		{"other_expectation", "HTTP/1.1", types.Headers{{Name: "Expect", Value: "other"}, {Name: "Content-Length", Value: "5"}}, false},
		{"no_expect_header", "HTTP/1.1", types.Headers{{Name: "Content-Length", Value: "5"}}, false},
		// first Expect header wins, matching Headers.Get
		{"duplicate_expect_first_match", "HTTP/1.1", types.Headers{{Name: "Expect", Value: "100-continue"}, {Name: "Expect", Value: "other"}, {Name: "Content-Length", Value: "5"}}, true},
		{"duplicate_expect_first_other", "HTTP/1.1", types.Headers{{Name: "Expect", Value: "other"}, {Name: "Expect", Value: "100-continue"}, {Name: "Content-Length", Value: "5"}}, false},
		// "Expect : 100-continue" parses as a name with trailing space
		{"space_before_colon", "HTTP/1.1", types.Headers{{Name: "Expect ", Value: "100-continue"}, {Name: "Content-Length", Value: "5"}}, false},
		// obs-fold continuation joins with a space
		{"obs_fold_value", "HTTP/1.1", types.Headers{{Name: "Expect", Value: "100- continue"}, {Name: "Content-Length", Value: "5"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.RawHTTP1Request{Method: "POST", Version: tt.version, Headers: tt.headers}
			assert.Equal(t, tt.want, expectsContinue(req))
		})
	}
}

// mockInterceptor serves resp when host and path match exactly (case-sensitive), so a
// caller that fails to lowercase the host misses the responder.
type mockInterceptor struct {
	host string
	path string
	resp *InterceptedResponse
}

func (m *mockInterceptor) InterceptRequest(host, path, _ string) *InterceptedResponse {
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

	// a TLS tunnel with no reachable upstream serves a matching responder, else 502s
	t.Run("no_upstream_serves_responder", func(t *testing.T) {
		h := newHandler(t)
		clientConn, proxyConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })

		go func() {
			h.handleExchange(t.Context(), proxyConn, bufio.NewReader(proxyConn), h1Exchange{
				target: &types.Target{Hostname: "example.com", Port: 443, UsesHTTPS: true},
			})
			_ = proxyConn.Close()
		}()

		_, err := clientConn.Write([]byte("GET /canned HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		require.NoError(t, err)

		respData, err := io.ReadAll(clientConn)
		require.NoError(t, err)
		assert.Contains(t, string(respData), "200")
		assert.Contains(t, string(respData), cannedBody)
	})

	t.Run("no_upstream_no_responder_502", func(t *testing.T) {
		h := newHandler(t)
		clientConn, proxyConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })

		go func() {
			h.handleExchange(t.Context(), proxyConn, bufio.NewReader(proxyConn), h1Exchange{
				target: &types.Target{Hostname: "example.com", Port: 443, UsesHTTPS: true},
			})
			_ = proxyConn.Close()
		}()

		_, err := clientConn.Write([]byte("GET /miss HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		require.NoError(t, err)

		respData, err := io.ReadAll(clientConn)
		require.NoError(t, err)
		assert.Contains(t, string(respData), "502")
	})

	// runExpect drives one exchange against upstreamResp, holding the request body back
	// until the client has read the interim response. Returns the interim line, the
	// remaining client-visible bytes, and the handler.
	runExpect := func(t *testing.T, upstreamResp string) (*http1Handler, string, string) {
		t.Helper()

		addr, reqCh := startUpstream(t, upstreamResp)
		h := newTestHTTP1Handler(t)
		clientConn, proxyConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })

		go func() {
			h.handleExchange(t.Context(), proxyConn, bufio.NewReader(proxyConn), h1Exchange{logParseErrors: true})
			_ = proxyConn.Close()
		}()

		_, err := clientConn.Write([]byte("POST /u HTTP/1.1\r\nHost: " + addr +
			"\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n"))
		require.NoError(t, err)

		cr := bufio.NewReader(clientConn)
		interimLine, err := cr.ReadString('\n')
		require.NoError(t, err)
		blank, err := cr.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "\r\n", blank)

		_, err = clientConn.Write([]byte("Hello"))
		require.NoError(t, err)

		rest, err := io.ReadAll(cr)
		require.NoError(t, err)

		select {
		case req := <-reqCh:
			assert.Equal(t, []byte("Hello"), req.Body)
			assert.Equal(t, "100-continue", req.GetHeader("Expect")) // forwarded unchanged
		case <-time.After(2 * time.Second):
			t.Fatal("upstream never received the request")
		}
		return h, interimLine, string(rest)
	}

	t.Run("expect_continue_sent_before_body", func(t *testing.T) {
		h, interim, rest := runExpect(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

		assert.Equal(t, "HTTP/1.1 100 Continue\r\n", interim)
		assert.Contains(t, rest, "200 OK")
		assert.Contains(t, rest, "ok")

		require.Equal(t, 1, h.history.Count())
		entry := firstEntry(t, h.history)
		assert.Equal(t, []byte("Hello"), entry.Request.Body)
		require.Len(t, entry.InterimResponses, 1)
		assert.Equal(t, 100, entry.InterimResponses[0].Message.StatusCode)
		assert.Equal(t, types.InterimSourceProxy, entry.InterimResponses[0].Source)
		assert.True(t, entry.InterimResponses[0].Relayed)
	})

	t.Run("expect_continue_upstream_dup_suppressed", func(t *testing.T) {
		h, interim, rest := runExpect(t, "HTTP/1.1 100 Continue\r\n\r\n"+
			"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")

		assert.Equal(t, "HTTP/1.1 100 Continue\r\n", interim)
		assert.NotContains(t, rest, "100 Continue") // upstream copy recorded, not relayed
		assert.Contains(t, rest, "200 OK")

		entry := firstEntry(t, h.history)
		require.Len(t, entry.InterimResponses, 2)
		assert.Equal(t, types.InterimSourceProxy, entry.InterimResponses[0].Source)
		assert.True(t, entry.InterimResponses[0].Relayed)
		assert.Equal(t, 100, entry.InterimResponses[1].Message.StatusCode)
		assert.Equal(t, types.InterimSourceOrigin, entry.InterimResponses[1].Source)
		assert.False(t, entry.InterimResponses[1].Relayed) // recorded, withheld from the client
	})

	t.Run("expect_continue_upstream_417", func(t *testing.T) {
		h, interim, rest := runExpect(t, "HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

		assert.Equal(t, "HTTP/1.1 100 Continue\r\n", interim)
		assert.Contains(t, rest, "417 Expectation Failed")
		assert.Equal(t, 417, firstEntry(t, h.history).Response.StatusCode)
	})

	t.Run("expect_continue_body_read_deadline", func(t *testing.T) {
		h := newTestHTTP1Handler(t)
		h.timeouts = TimeoutConfig{ReadTimeout: 50 * time.Millisecond}

		clientConn, proxyConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })

		done := make(chan struct{})
		go func() {
			h.handleExchange(t.Context(), proxyConn, bufio.NewReader(proxyConn), h1Exchange{logParseErrors: true})
			close(done)
		}()

		_, err := clientConn.Write([]byte("POST /u HTTP/1.1\r\nHost: example.com" +
			"\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n"))
		require.NoError(t, err)

		cr := bufio.NewReader(clientConn)
		line, err := cr.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "HTTP/1.1 100 Continue\r\n", line)

		// body never sent; the read deadline must unblock the handler goroutine
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("handleExchange hung waiting for a body that never arrived")
		}
	})

	t.Run("expect_continue_client_closes", func(t *testing.T) {
		h := newTestHTTP1Handler(t)
		clientConn, proxyConn := net.Pipe()

		done := make(chan struct{})
		go func() {
			h.handleExchange(t.Context(), proxyConn, bufio.NewReader(proxyConn), h1Exchange{logParseErrors: true})
			close(done)
		}()

		_, err := clientConn.Write([]byte("POST /u HTTP/1.1\r\nHost: example.com" +
			"\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n"))
		require.NoError(t, err)

		cr := bufio.NewReader(clientConn)
		line, err := cr.ReadString('\n')
		require.NoError(t, err)
		require.Equal(t, "HTTP/1.1 100 Continue\r\n", line)

		// closing without the framed body ends the exchange, nothing captured
		require.NoError(t, clientConn.Close())
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("handleExchange hung after the client closed")
		}
		assert.Equal(t, 0, h.history.Count())
	})

	t.Run("expect_continue_mirrors_bare_lf", func(t *testing.T) {
		addr, _ := startUpstream(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		h := newTestHTTP1Handler(t)
		clientConn, proxyConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })

		go func() {
			h.handleExchange(t.Context(), proxyConn, bufio.NewReader(proxyConn), h1Exchange{logParseErrors: true})
			_ = proxyConn.Close()
		}()

		_, err := clientConn.Write([]byte("POST /u HTTP/1.1\nHost: " + addr +
			"\nContent-Length: 5\nExpect: 100-continue\n\n"))
		require.NoError(t, err)

		buf := make([]byte, len("HTTP/1.1 100 Continue\n\n"))
		_, err = io.ReadFull(clientConn, buf)
		require.NoError(t, err)
		assert.Equal(t, "HTTP/1.1 100 Continue\n\n", string(buf))

		_, err = clientConn.Write([]byte("Hello"))
		require.NoError(t, err)
		_, err = io.ReadAll(clientConn)
		require.NoError(t, err)

		entry := firstEntry(t, h.history)
		require.Len(t, entry.InterimResponses, 1)
		assert.Equal(t, types.EndingBareLF, entry.InterimResponses[0].Message.FirstLineEnding)
	})

	t.Run("malformed_expect_forwarded_verbatim", func(t *testing.T) {
		addr, reqCh := startUpstream(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		h := newTestHTTP1Handler(t)
		clientConn, proxyConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })

		go func() {
			h.handleExchange(t.Context(), proxyConn, bufio.NewReader(proxyConn), h1Exchange{logParseErrors: true})
			_ = proxyConn.Close()
		}()

		// space before the colon: no local 100, upstream decides
		_, err := clientConn.Write([]byte("POST /u HTTP/1.1\r\nHost: " + addr +
			"\r\nContent-Length: 5\r\nExpect : 100-continue\r\n\r\nHello"))
		require.NoError(t, err)

		respData, err := io.ReadAll(clientConn)
		require.NoError(t, err)
		assert.NotContains(t, string(respData), "100 Continue")

		select {
		case req := <-reqCh:
			var buf bytes.Buffer
			assert.Contains(t, string(req.SerializeRaw(&buf)), "Expect : 100-continue")
		case <-time.After(2 * time.Second):
			t.Fatal("upstream never received the request")
		}
	})

	t.Run("no_expect_header_no_continue", func(t *testing.T) {
		addr, _ := startUpstream(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		h := newTestHTTP1Handler(t)
		clientConn, proxyConn := net.Pipe()
		t.Cleanup(func() { _ = clientConn.Close() })

		go func() {
			h.handleExchange(t.Context(), proxyConn, bufio.NewReader(proxyConn), h1Exchange{logParseErrors: true})
			_ = proxyConn.Close()
		}()

		_, err := clientConn.Write([]byte("POST /u HTTP/1.1\r\nHost: " + addr +
			"\r\nContent-Length: 5\r\n\r\nHello"))
		require.NoError(t, err)

		respData, err := io.ReadAll(clientConn)
		require.NoError(t, err)
		assert.NotContains(t, string(respData), "100 Continue")
		assert.Contains(t, string(respData), "200 OK")
		assert.Empty(t, firstEntry(t, h.history).InterimResponses)
	})

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
		require.Equal(t, 1, h.history.Count())
		entry := firstEntry(t, h.history)
		require.NotNil(t, entry.Response)
		assert.Equal(t, 200, entry.Response.StatusCode)
		assert.Equal(t, cannedBody, string(entry.Response.Body))
	})

	t.Run("interim_103_origin_relayed", func(t *testing.T) {
		// upstream emits a 103 interim response before the final 200
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
		assert.Equal(t, 103, entry.InterimResponses[0].Message.StatusCode)
		assert.Equal(t, types.InterimSourceOrigin, entry.InterimResponses[0].Source)
		assert.True(t, entry.InterimResponses[0].Relayed)
	})

	t.Run("buffered_upstream_reset_mid_body", func(t *testing.T) {
		const partial = "data one partial"
		// Content-Length declares more than is sent, then the conn resets
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
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 4096\r\n\r\n"+partial)
			if tcp, ok := conn.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0) // deferred Close sends RST, not a clean EOF
			}
		}()

		h := newTestHTTP1Handler(t)
		h.ruleApplier = replaceBodyRuleApplier{find: []byte("x"), replace: []byte("y")} // body rules + Content-Length force buffering
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
		assert.Contains(t, string(respData), "502") // synthetic gateway error, not a bare close

		entry := firstEntry(t, h.history)
		require.NotNil(t, entry.Response) // head kept despite the body failure
		assert.Contains(t, string(entry.Response.Body), partial)
		assert.Equal(t, reasonUpstreamError, entry.Annotations[annStreamReason])
		assert.Equal(t, true, entry.Annotations[annStreamTruncated])
	})
}

// syncBuf is a concurrency-safe byte sink for reading a streamed response.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// chunkedTrickleUpstream accepts one connection, sends a chunked response head
// and the first chunk, then waits on gate before sending the second chunk and a
// terminator carrying trailer (a "Name: value\r\n" block, may be empty). Returns
// the listener address.
func chunkedTrickleUpstream(t *testing.T, gate <-chan struct{}, trailer string) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		br := bufio.NewReader(conn)
		for { // drain the request head
			line, rerr := br.ReadString('\n')
			if rerr != nil || line == "\r\n" {
				break
			}
		}

		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
		writeChunk(conn, "data: one\n\n")
		<-gate
		writeChunk(conn, "data: two\n\n")
		_, _ = io.WriteString(conn, "0\r\n"+trailer+"\r\n")
	}()

	return ln.Addr().String()
}

func writeChunk(w io.Writer, payload string) {
	_, _ = io.WriteString(w, fmt.Sprintf("%x\r\n%s\r\n", len(payload), payload))
}

// chunkedTruncatedUpstream sends a chunked head and one full chunk, then writes
// trailing before closing. Returns the listener address.
func chunkedTruncatedUpstream(t *testing.T, trailing string) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		br := bufio.NewReader(conn)
		for { // drain the request head
			line, rerr := br.ReadString('\n')
			if rerr != nil || line == "\r\n" {
				break
			}
		}

		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
		writeChunk(conn, "data: one\n\n")
		if trailing != "" {
			_, _ = io.WriteString(conn, trailing)
		}
	}()

	return ln.Addr().String()
}

// newStreamingProxy starts a ready-to-accept proxy server, cleaned up on test end.
func newStreamingProxy(t *testing.T, applier types.RuleApplier) *ProxyServer {
	t.Helper()

	proxy, err := NewProxyServer(t.Context(), 0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), TimeoutConfig{}, false)
	require.NoError(t, err)
	if applier != nil {
		proxy.SetRuleApplier(applier)
	}
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })
	require.NoError(t, proxy.WaitReady(t.Context()))
	return proxy
}

// dialProxyGET dials the proxy and sends an absolute-form GET for upstreamAddr+path.
func dialProxyGET(t *testing.T, proxy *ProxyServer, upstreamAddr, path string) net.Conn {
	t.Helper()

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", proxy.Addr())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.Write([]byte("GET http://" + upstreamAddr + path + " HTTP/1.1\r\nHost: " + upstreamAddr + "\r\n\r\n"))
	require.NoError(t, err)
	return conn
}

// replaceBodyRuleApplier mutates response bodies (per unit) by replacing find with replace.
type replaceBodyRuleApplier struct {
	find, replace []byte
}

func (replaceBodyRuleApplier) ApplyRequestRules(r *types.RawHTTP1Request) *types.RawHTTP1Request {
	return r
}
func (replaceBodyRuleApplier) ApplyResponseRules(r *types.RawHTTP1Response) *types.RawHTTP1Response {
	return r
}
func (replaceBodyRuleApplier) ApplyRequestBodyOnlyRules(b []byte, _ types.Headers) ([]byte, error) {
	return b, nil
}
func (a replaceBodyRuleApplier) ApplyResponseBodyOnlyRules(b []byte, _ types.Headers) []byte {
	return bytes.ReplaceAll(b, a.find, a.replace)
}
func (replaceBodyRuleApplier) ApplyRequestHeaderOnlyRules(h types.Headers) types.Headers  { return h }
func (replaceBodyRuleApplier) ApplyResponseHeaderOnlyRules(h types.Headers) types.Headers { return h }
func (replaceBodyRuleApplier) ApplyWSRules(p []byte, _ string) []byte                     { return p }
func (replaceBodyRuleApplier) HasBodyRules(isRequest bool) bool                           { return !isRequest }

func TestHTTP1Streaming(t *testing.T) {
	t.Parallel()

	t.Run("in_progress_then_complete", func(t *testing.T) {
		cases := []struct {
			name    string
			trailer string // trailer block on the terminator, empty for none
		}{
			{"no_trailers", ""},
			{"with_trailers", "Trailer: foo\r\n"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				gate := make(chan struct{})
				upstreamAddr := chunkedTrickleUpstream(t, gate, tc.trailer)
				proxy := newStreamingProxy(t, nil)
				conn := dialProxyGET(t, proxy, upstreamAddr, "/events")

				received := &syncBuf{}
				go func() { _, _ = io.Copy(received, conn) }()

				// First chunk reaches the client before the upstream sends the second
				require.Eventually(t, func() bool {
					return strings.Contains(received.String(), "data: one")
				}, 2*time.Second, 10*time.Millisecond)
				assert.NotContains(t, received.String(), "data: two")

				// History shows the flow in progress with the partial body
				var flowID string
				require.Eventually(t, func() bool {
					flows := proxy.History().Page(1, "")
					if len(flows) != 1 || flows[0].Response == nil {
						return false
					}
					flowID = flows[0].FlowID
					return flows[0].CompletedAt.IsZero() && strings.Contains(string(flows[0].Response.Body), "one")
				}, 2*time.Second, 10*time.Millisecond)

				// Release the second chunk
				close(gate)

				require.Eventually(t, func() bool {
					return strings.Contains(received.String(), "data: two")
				}, 2*time.Second, 10*time.Millisecond)

				// a well-terminated trailer block completes cleanly, without truncation
				if tc.trailer != "" {
					assert.Contains(t, received.String(), "0\r\n"+tc.trailer+"\r\n")
				}

				// History now shows the completed flow with the full body
				require.Eventually(t, func() bool {
					flow, ok := proxy.History().Get(flowID)
					if !ok || flow.Response == nil {
						return false
					}
					body := string(flow.Response.Body)
					return !flow.CompletedAt.IsZero() && flow.Annotations[annStreamTruncated] == nil &&
						strings.Contains(body, "one") && strings.Contains(body, "two")
				}, 2*time.Second, 10*time.Millisecond)
			})
		}
	})

	t.Run("body_rules_mutate_stream", func(t *testing.T) {
		gate := make(chan struct{})
		close(gate) // send both chunks immediately
		upstreamAddr := chunkedTrickleUpstream(t, gate, "")
		proxy := newStreamingProxy(t, replaceBodyRuleApplier{find: []byte("one"), replace: []byte("ONE")})
		conn := dialProxyGET(t, proxy, upstreamAddr, "/events")

		received := &syncBuf{}
		go func() { _, _ = io.Copy(received, conn) }()

		// Per-unit rule mutates the streamed body on the wire
		require.Eventually(t, func() bool {
			return strings.Contains(received.String(), "data: ONE") && strings.Contains(received.String(), "data: two")
		}, 2*time.Second, 10*time.Millisecond)

		// History stores the mutated body
		require.Eventually(t, func() bool {
			flows := proxy.History().Page(1, "")
			if len(flows) != 1 || flows[0].Response == nil || flows[0].CompletedAt.IsZero() {
				return false
			}
			return strings.Contains(string(flows[0].Response.Body), "ONE")
		}, 2*time.Second, 10*time.Millisecond)
	})

	t.Run("truncated", func(t *testing.T) {
		cases := []struct {
			name     string
			trailing string
			wantRaw  string // extra bytes replayed to the client before close
		}{
			{"between_chunks", "", ""},
			{"malformed_size_line", "zz\r\n", "zz"},
			{"mid_chunk", "a\r\ndata", ""},
			{"trailers_truncated", "0\r\nTrailer: foo\r\n", "Trailer: foo"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				upstreamAddr := chunkedTruncatedUpstream(t, tc.trailing)
				proxy := newStreamingProxy(t, nil)
				conn := dialProxyGET(t, proxy, upstreamAddr, "/events")

				// io.Copy returns when the proxy closes the truncated connection
				received := &syncBuf{}
				_, _ = io.Copy(received, conn)

				assert.Contains(t, received.String(), "data: one")
				assert.NotContains(t, received.String(), "0\r\n\r\n")
				if tc.wantRaw != "" {
					assert.Contains(t, received.String(), tc.wantRaw)
				}

				require.Eventually(t, func() bool {
					flows := proxy.History().Page(1, "")
					if len(flows) != 1 || flows[0].CompletedAt.IsZero() {
						return false
					}
					ann := flows[0].Annotations
					return ann[annStreamReason] == reasonUpstreamError && ann[annStreamTruncated] == true
				}, 2*time.Second, 10*time.Millisecond)
			})
		}
	})
}

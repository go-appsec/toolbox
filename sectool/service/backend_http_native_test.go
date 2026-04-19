package service

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sectool/service/testutil"
)

func TestNativeProxyBackend_CreateAndServe(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)

	go func() { _ = backend.Serve() }()
	t.Cleanup(func() { _ = backend.Close() })

	addr := backend.Addr()
	assert.Contains(t, addr, "127.0.0.1:")
	assert.NotEqual(t, "127.0.0.1:0", addr)
}

func TestNativeProxyBackend_GetProxyHistory(t *testing.T) {
	t.Parallel()

	// Start test server
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(testServer.Close)

	// Start native proxy backend
	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	go func() { _ = backend.Serve() }()
	t.Cleanup(func() { _ = backend.Close() })

	// Configure client to use proxy
	proxyURL, _ := url.Parse("http://" + backend.Addr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Make request through proxy
	resp, err := client.Get(testServer.URL + "/test")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	testutil.WaitForCount(t, func() int { return backend.server.History().Count() }, 1)

	entries, err := backend.GetProxyHistory(t.Context(), 10, 0)
	require.NoError(t, err)

	assert.Len(t, entries, 1)
	assert.Contains(t, entries[0].Request, "GET")
	assert.Contains(t, entries[0].Response, "200")
}

func TestNativeProxyBackend_GetProxyHistoryMeta(t *testing.T) {
	t.Parallel()

	// Start test server
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("OK"))
	}))
	t.Cleanup(testServer.Close)

	// Start native proxy backend
	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	go func() { _ = backend.Serve() }()
	t.Cleanup(func() { _ = backend.Close() })

	// Configure client to use proxy
	proxyURL, _ := url.Parse("http://" + backend.Addr())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Make request through proxy
	resp, err := client.Get(testServer.URL + "/test?q=1")
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	testutil.WaitForCount(t, func() int { return backend.server.History().Count() }, 1)

	metas, err := backend.GetProxyHistoryMeta(t.Context(), 10, 0)
	require.NoError(t, err)

	assert.Len(t, metas, 1)
	assert.Equal(t, "GET", metas[0].Method)
	assert.Equal(t, 200, metas[0].Status)
	assert.Contains(t, metas[0].Path, "/test")
	assert.NotEmpty(t, metas[0].Host)
	assert.Equal(t, "http/1.1", metas[0].Protocol)
}

func TestNativeProxyBackend_Rules_CRUD(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	// Add rule
	rule, err := backend.AddRule(t.Context(), protocol.RuleEntry{
		Label:   "test-rule",
		Type:    RuleTypeRequestHeader,
		IsRegex: false,
		Find:    "old-value",
		Replace: "new-value",
	})
	require.NoError(t, err)
	assert.Equal(t, "test-rule", rule.Label)
	assert.Equal(t, RuleTypeRequestHeader, rule.Type)
	assert.Equal(t, "old-value", rule.Find)

	// List rules
	rules, err := backend.ListRules(t.Context(), false)
	require.NoError(t, err)
	assert.Len(t, rules, 1)

	// Delete rule
	err = backend.DeleteRule(t.Context(), "test-rule")
	require.NoError(t, err)

	// Verify deleted
	rules, err = backend.ListRules(t.Context(), false)
	require.NoError(t, err)
	assert.Empty(t, rules)
}

func TestNativeProxyBackend_Rules_Persistence(t *testing.T) {
	t.Parallel()

	ruleStorage := store.NewMemStorage()

	// Create backend and add rules
	backend1, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), ruleStorage, store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)

	_, err = backend1.AddRule(t.Context(), protocol.RuleEntry{
		Label:   "http-rule",
		Type:    RuleTypeRequestHeader,
		IsRegex: false,
		Find:    "old",
		Replace: "new",
	})
	require.NoError(t, err)

	_, err = backend1.AddRule(t.Context(), protocol.RuleEntry{
		Label:   "ws-rule",
		Type:    "ws:both",
		IsRegex: true,
		Find:    `\d+`,
		Replace: "NUM",
	})
	require.NoError(t, err)

	require.NoError(t, backend1.Close())

	// Create new backend with same ruleStorage - rules should be loaded
	backend2, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), ruleStorage, store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend2.Close() })

	httpRules, err := backend2.ListRules(t.Context(), false)
	require.NoError(t, err)
	require.Len(t, httpRules, 1)
	assert.Equal(t, "http-rule", httpRules[0].Label)
	assert.Equal(t, "old", httpRules[0].Find)

	wsRules, err := backend2.ListRules(t.Context(), true)
	require.NoError(t, err)
	require.Len(t, wsRules, 1)
	assert.Equal(t, "ws-rule", wsRules[0].Label)
	assert.True(t, wsRules[0].IsRegex)

	// Verify regex was recompiled by applying WS rule
	modified := backend2.ApplyWSRules([]byte("id=42"), "ws:both")
	assert.Equal(t, "id=NUM", string(modified))
}

func TestNativeProxyBackend_Rules_DeletePersists(t *testing.T) {
	t.Parallel()

	ruleStorage := store.NewMemStorage()

	backend1, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), ruleStorage, store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)

	_, err = backend1.AddRule(t.Context(), protocol.RuleEntry{
		Label: "to-delete", Type: RuleTypeRequestHeader,
		IsRegex: false, Find: "a", Replace: "b",
	})
	require.NoError(t, err)
	_, err = backend1.AddRule(t.Context(), protocol.RuleEntry{
		Label: "to-keep", Type: RuleTypeRequestBody,
		IsRegex: false, Find: "c", Replace: "d",
	})
	require.NoError(t, err)

	err = backend1.DeleteRule(t.Context(), "to-delete")
	require.NoError(t, err)
	require.NoError(t, backend1.Close())

	// New backend should only see the surviving rule
	backend2, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), ruleStorage, store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend2.Close() })

	rules, err := backend2.ListRules(t.Context(), false)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "to-keep", rules[0].Label)
}

func TestNativeProxyBackend_Rules_LabelUniqueness(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	// Add first rule
	_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
		Label:   "unique-label",
		Type:    RuleTypeRequestHeader,
		IsRegex: false,
		Find:    "a",
		Replace: "b",
	})
	require.NoError(t, err)

	// Try to add duplicate label
	_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
		Label:   "unique-label",
		Type:    RuleTypeRequestHeader,
		IsRegex: false,
		Find:    "c",
		Replace: "d",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrLabelExists)
}

func TestNativeProxyBackend_Rules_InvalidType(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
		Type:    "invalid_type",
		IsRegex: false,
		Find:    "a",
		Replace: "b",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid rule type")
}

func TestNativeProxyBackend_Rules_Regex(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	// Valid regex
	rule, err := backend.AddRule(t.Context(), protocol.RuleEntry{
		Type:    RuleTypeRequestHeader,
		IsRegex: true,
		Find:    `\d+`,
		Replace: "NUMBER",
	})
	require.NoError(t, err)
	assert.True(t, rule.IsRegex)

	// Invalid regex
	_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
		Type:    RuleTypeRequestHeader,
		IsRegex: true,
		Find:    `[invalid`,
		Replace: "x",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex")
}

func TestNativeProxyBackend_SendRequest(t *testing.T) {
	t.Parallel()

	// Start test server
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "response")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("Hello from server"))
	}))
	t.Cleanup(testServer.Close)

	// Parse test server URL
	serverURL, err := url.Parse(testServer.URL)
	require.NoError(t, err)

	// Create backend (doesn't need to serve for SendRequest)
	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	// Send request directly (not through proxy)
	rawReq := []byte("GET /test HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
	result, err := backend.SendRequest(t.Context(), "test", SendRequestInput{
		RawRequest: rawReq,
		Target: Target{
			Hostname:  serverURL.Hostname(),
			Port:      mustParsePort(t, serverURL.Port()),
			UsesHTTPS: false,
		},
	})
	require.NoError(t, err)

	assert.Contains(t, string(result.Headers), "200")
	assert.Contains(t, string(result.Headers), "X-Test: response")
	assert.Equal(t, "Hello from server", string(result.Body))

	// Verify Headers does NOT contain the body (regression test)
	assert.NotContains(t, string(result.Headers), "Hello from server")
	// Headers should end with header terminator
	assert.True(t, bytes.HasSuffix(result.Headers, []byte("\r\n\r\n")))
}

func TestNativeProxyBackend_SendRequest_AppliesRules(t *testing.T) {
	t.Parallel()

	t.Run("request_header_rule", func(t *testing.T) {
		t.Parallel()

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Received", r.Header.Get("X-Rule-Added"))
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		serverURL, err := url.Parse(testServer.URL)
		require.NoError(t, err)

		backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Type:    RuleTypeRequestHeader,
			Replace: "X-Rule-Added: from-rule\r\n",
		})
		require.NoError(t, err)

		rawReq := []byte("GET /test HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		result, err := backend.SendRequest(t.Context(), "test", SendRequestInput{
			RawRequest: rawReq,
			Target: Target{
				Hostname:  serverURL.Hostname(),
				Port:      mustParsePort(t, serverURL.Port()),
				UsesHTTPS: false,
			},
		})
		require.NoError(t, err)
		assert.Contains(t, string(result.Headers), "X-Received: from-rule")

		// ModifiedRequest should contain the post-rule request with the appended header
		require.NotNil(t, result.ModifiedRequest)
		assert.Contains(t, string(result.ModifiedRequest), "X-Rule-Added: from-rule")
	})

	t.Run("no_rules_unchanged", func(t *testing.T) {
		t.Parallel()

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("OK"))
		}))
		t.Cleanup(testServer.Close)

		serverURL, err := url.Parse(testServer.URL)
		require.NoError(t, err)

		backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		rawReq := []byte("GET /test HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		result, err := backend.SendRequest(t.Context(), "test", SendRequestInput{
			RawRequest: rawReq,
			Target: Target{
				Hostname:  serverURL.Hostname(),
				Port:      mustParsePort(t, serverURL.Port()),
				UsesHTTPS: false,
			},
		})
		require.NoError(t, err)
		assert.Contains(t, string(result.Headers), "200")
		assert.Equal(t, "OK", string(result.Body))

		// No rules means ModifiedRequest should be nil
		assert.Nil(t, result.ModifiedRequest)
	})

	t.Run("rules_no_match", func(t *testing.T) {
		t.Parallel()

		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		serverURL, err := url.Parse(testServer.URL)
		require.NoError(t, err)

		backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		// Add a rule that won't match
		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Type:    RuleTypeRequestHeader,
			Find:    "X-Nonexistent: value",
			Replace: "X-Replaced: value",
		})
		require.NoError(t, err)

		rawReq := []byte("GET /test HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
		result, err := backend.SendRequest(t.Context(), "test", SendRequestInput{
			RawRequest: rawReq,
			Target: Target{
				Hostname:  serverURL.Hostname(),
				Port:      mustParsePort(t, serverURL.Port()),
				UsesHTTPS: false,
			},
		})
		require.NoError(t, err)

		// Rules exist but didn't match - ModifiedRequest should be nil
		assert.Nil(t, result.ModifiedRequest)
	})
}

func TestNativeProxyBackend_Close(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	// Close should succeed
	err = backend.Close()
	require.NoError(t, err)

	// Double close should be safe
	err = backend.Close()
	require.NoError(t, err)
}

func TestNativeProxyBackend_HTTPS_Proxy(t *testing.T) {
	t.Parallel()

	// Start HTTPS test server
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-HTTPS", "true")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("Secure response"))
	}))
	t.Cleanup(testServer.Close)

	// Start native proxy backend
	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	go func() { _ = backend.Serve() }()
	t.Cleanup(func() { _ = backend.Close() })

	// Client trusting our CA and the test server's CA
	proxyURL, _ := url.Parse("http://" + backend.Addr())
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: testServer.Client().Transport.(*http.Transport).TLSClientConfig,
	}
	// Also trust our proxy's CA
	transport.TLSClientConfig.InsecureSkipVerify = true

	client := &http.Client{Transport: transport}

	// Make HTTPS request through proxy
	resp, err := client.Get(testServer.URL + "/secure")
	require.NoError(t, err)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "true", resp.Header.Get("X-HTTPS"))
	assert.Equal(t, "Secure response", string(body))
}

// mustParsePort parses a port string or returns 80 as default
func mustParsePort(t *testing.T, portStr string) int {
	t.Helper()
	if portStr == "" {
		return 80
	}
	var port int
	_, err := fmt.Sscanf(portStr, "%d", &port)
	require.NoError(t, err)
	return port
}

// =============================================================================
// Rule Application Tests
// =============================================================================

func TestApplyRequestRules(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir() // shared so CA cert is generated once

	t.Run("header_literal", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "header-rule",
			Type:    RuleTypeRequestHeader,
			IsRegex: false,
			Find:    "old-value",
			Replace: "new-value",
		})
		require.NoError(t, err)

		req := &proxy.RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []proxy.Header{
				{Name: "Host", Value: "example.com"},
				{Name: "X-Test", Value: "old-value"},
			},
		}

		modified := backend.ApplyRequestRules(req)

		assert.Equal(t, "new-value", modified.GetHeader("X-Test"))
	})

	t.Run("header_regex", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "regex-header-rule",
			Type:    RuleTypeRequestHeader,
			IsRegex: true,
			Find:    `\d+`,
			Replace: "NUMBER",
		})
		require.NoError(t, err)

		req := &proxy.RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []proxy.Header{
				{Name: "Host", Value: "example.com"},
				{Name: "X-ID", Value: "user-12345-session"},
			},
		}

		modified := backend.ApplyRequestRules(req)

		assert.Equal(t, "user-NUMBER-session", modified.GetHeader("X-ID"))
	})

	t.Run("body_literal", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "body-rule",
			Type:    RuleTypeRequestBody,
			IsRegex: false,
			Find:    "secret",
			Replace: "REDACTED",
		})
		require.NoError(t, err)

		req := &proxy.RawHTTP1Request{
			Method:  "POST",
			Path:    "/api",
			Version: "HTTP/1.1",
			Headers: []proxy.Header{
				{Name: "Host", Value: "example.com"},
				{Name: "Content-Length", Value: "27"},
			},
			Body: []byte(`{"password":"secret123"}`),
		}

		modified := backend.ApplyRequestRules(req)

		assert.Contains(t, string(modified.Body), "REDACTED123")
		// Content-Length should be updated
		assert.Equal(t, "26", modified.GetHeader("Content-Length"))
	})

	t.Run("no_matching_rules", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "no-match-rule",
			Type:    RuleTypeRequestHeader,
			IsRegex: false,
			Find:    "nonexistent",
			Replace: "replacement",
		})
		require.NoError(t, err)

		req := &proxy.RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []proxy.Header{
				{Name: "Host", Value: "example.com"},
				{Name: "X-Test", Value: "unchanged"},
			},
		}

		modified := backend.ApplyRequestRules(req)

		assert.Equal(t, "unchanged", modified.GetHeader("X-Test"))
	})

	t.Run("strips_unsupported_accept_encoding", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "resp-body",
			Type:    RuleTypeResponseBody,
			Find:    "false",
			Replace: "true",
		})
		require.NoError(t, err)

		req := &proxy.RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []proxy.Header{
				{Name: "Host", Value: "example.com"},
				{Name: "Accept-Encoding", Value: "gzip, deflate, br, zstd, snappy"},
			},
		}

		modified := backend.ApplyRequestRules(req)

		// snappy should be stripped; gzip, deflate, br, zstd are supported
		assert.Equal(t, "gzip, deflate, br, zstd", modified.GetHeader("Accept-Encoding"))
	})

	t.Run("preserves_accept_encoding", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "req-header-only",
			Type:    RuleTypeRequestHeader,
			Replace: "X-Test: value",
		})
		require.NoError(t, err)

		req := &proxy.RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []proxy.Header{
				{Name: "Host", Value: "example.com"},
				{Name: "Accept-Encoding", Value: "gzip, deflate, br, snappy"},
			},
		}

		modified := backend.ApplyRequestRules(req)

		// No response body rules, Accept-Encoding left as-is
		assert.Equal(t, "gzip, deflate, br, snappy", modified.GetHeader("Accept-Encoding"))
	})

	t.Run("multiple_rules", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		// Add multiple rules - they should apply in order
		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "rule1",
			Type:    RuleTypeRequestHeader,
			IsRegex: false,
			Find:    "AAA",
			Replace: "BBB",
		})
		require.NoError(t, err)

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "rule2",
			Type:    RuleTypeRequestHeader,
			IsRegex: false,
			Find:    "BBB",
			Replace: "CCC",
		})
		require.NoError(t, err)

		req := &proxy.RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []proxy.Header{
				{Name: "X-Test", Value: "AAA"},
			},
		}

		modified := backend.ApplyRequestRules(req)

		// AAA -> BBB -> CCC (both rules should apply in sequence)
		assert.Equal(t, "CCC", modified.GetHeader("X-Test"))
	})

	t.Run("empty_body", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "body-rule",
			Type:    RuleTypeRequestBody,
			IsRegex: false,
			Find:    "test",
			Replace: "replaced",
		})
		require.NoError(t, err)

		// Request with no body
		req := &proxy.RawHTTP1Request{
			Method:  "GET",
			Path:    "/test",
			Version: "HTTP/1.1",
			Headers: []proxy.Header{
				{Name: "Host", Value: "example.com"},
			},
		}

		// Should not panic or error with empty body
		modified := backend.ApplyRequestRules(req)

		assert.Empty(t, modified.Body)
	})

	t.Run("compressed_body", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "body-rule",
			Type:    RuleTypeRequestBody,
			IsRegex: false,
			Find:    "secret",
			Replace: "HIDDEN",
		})
		require.NoError(t, err)

		// Create gzip-compressed request body
		originalBody := []byte(`{"password":"secret123"}`)
		compressedBody, err := proxy.Compress(originalBody, "gzip")
		require.NoError(t, err)

		req := &proxy.RawHTTP1Request{
			Method:  "POST",
			Path:    "/api",
			Version: "HTTP/1.1",
			Headers: []proxy.Header{
				{Name: "Host", Value: "example.com"},
				{Name: "Content-Encoding", Value: "gzip"},
				{Name: "Content-Length", Value: strconv.Itoa(len(compressedBody))},
			},
			Body: compressedBody,
		}

		modified := backend.ApplyRequestRules(req)

		// Decompress and verify the rule was applied
		decompressed, wasCompressed := proxy.Decompress(modified.Body, "gzip")
		assert.True(t, wasCompressed)
		assert.Contains(t, string(decompressed), "HIDDEN123")
		assert.NotContains(t, string(decompressed), "secret")
	})
}

func TestApplyResponseRules(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir() // shared so CA cert is generated once

	t.Run("header_literal", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "resp-header-rule",
			Type:    RuleTypeResponseHeader,
			IsRegex: false,
			Find:    "Apache/2.4",
			Replace: "Hidden",
		})
		require.NoError(t, err)

		resp := &proxy.RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Headers: []proxy.Header{
				{Name: "Server", Value: "Apache/2.4"},
				{Name: "Content-Type", Value: "text/html"},
			},
		}

		modified := backend.ApplyResponseRules(resp)

		assert.Equal(t, "Hidden", modified.GetHeader("Server"))
	})

	t.Run("body_literal", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "resp-body-rule",
			Type:    RuleTypeResponseBody,
			IsRegex: false,
			Find:    "internal-error-code-123",
			Replace: "error",
		})
		require.NoError(t, err)

		resp := &proxy.RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 500,
			StatusText: "Internal Server Error",
			Headers: []proxy.Header{
				{Name: "Content-Type", Value: "text/plain"},
				{Name: "Content-Length", Value: "35"},
			},
			Body: []byte("Error: internal-error-code-123 here"),
		}

		modified := backend.ApplyResponseRules(resp)

		assert.Equal(t, "Error: error here", string(modified.Body))
		assert.Equal(t, "17", modified.GetHeader("Content-Length"))
	})

	t.Run("compressed_body", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "compressed-body-rule",
			Type:    RuleTypeResponseBody,
			IsRegex: false,
			Find:    "secret",
			Replace: "HIDDEN",
		})
		require.NoError(t, err)

		// Create gzip-compressed body
		originalBody := []byte("The secret data is here")
		compressedBody, err := proxy.Compress(originalBody, "gzip")
		require.NoError(t, err)

		resp := &proxy.RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Headers: []proxy.Header{
				{Name: "Content-Encoding", Value: "gzip"},
				{Name: "Content-Length", Value: strconv.Itoa(len(compressedBody))},
			},
			Body: compressedBody,
		}

		modified := backend.ApplyResponseRules(resp)

		// Decompress the result to verify
		decompressed, wasCompressed := proxy.Decompress(modified.Body, "gzip")
		assert.True(t, wasCompressed)
		assert.Equal(t, "The HIDDEN data is here", string(decompressed))
	})

	t.Run("brotli_body", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "brotli-body-rule",
			Type:    RuleTypeResponseBody,
			IsRegex: false,
			Find:    "false",
			Replace: "true",
		})
		require.NoError(t, err)

		originalBody := []byte(`{"admin": false}`)
		compressedBody, err := proxy.Compress(originalBody, "br")
		require.NoError(t, err)

		resp := &proxy.RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Headers: []proxy.Header{
				{Name: "Content-Encoding", Value: "br"},
				{Name: "Content-Length", Value: strconv.Itoa(len(compressedBody))},
			},
			Body: compressedBody,
		}

		modified := backend.ApplyResponseRules(resp)

		decompressed, wasCompressed := proxy.Decompress(modified.Body, "br")
		assert.True(t, wasCompressed)
		assert.Equal(t, `{"admin": true}`, string(decompressed))
	})

	t.Run("invalid_brotli_skips_rules", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "body-rule",
			Type:    RuleTypeResponseBody,
			IsRegex: false,
			Find:    "test",
			Replace: "MODIFIED",
		})
		require.NoError(t, err)

		// Invalid brotli data - decompression should fail, body unchanged
		fakeCompressed := []byte{0x1b, 0x03, 0x00, 0xf8, 0xff}
		originalBody := slices.Clone(fakeCompressed)

		resp := &proxy.RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Headers: []proxy.Header{
				{Name: "Content-Encoding", Value: "br"},
				{Name: "Content-Length", Value: strconv.Itoa(len(fakeCompressed))},
			},
			Body: fakeCompressed,
		}

		modified := backend.ApplyResponseRules(resp)

		assert.Equal(t, originalBody, modified.Body)
	})

	t.Run("multiple_encoding_skips_rules", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "body-rule",
			Type:    RuleTypeResponseBody,
			IsRegex: false,
			Find:    "test",
			Replace: "MODIFIED",
		})
		require.NoError(t, err)

		// Multiple encodings should be skipped
		fakeBody := []byte("some test data")
		originalBody := slices.Clone(fakeBody)

		resp := &proxy.RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Headers: []proxy.Header{
				{Name: "Content-Encoding", Value: "gzip, br"},
				{Name: "Content-Length", Value: strconv.Itoa(len(fakeBody))},
			},
			Body: fakeBody,
		}

		modified := backend.ApplyResponseRules(resp)

		// Body should be unchanged since multiple encodings are unsupported
		assert.Equal(t, originalBody, modified.Body)
	})
}

func TestApplyWSRules(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir() // shared so CA cert is generated once

	t.Run("to_server", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		// Add WebSocket rule for to-server direction
		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "ws-to-server-rule",
			Type:    "ws:to-server",
			IsRegex: false,
			Find:    "client-secret",
			Replace: "REDACTED",
		})
		require.NoError(t, err)

		payload := []byte(`{"message":"client-secret"}`)

		// Should apply to ws:to-server
		modified := backend.ApplyWSRules(payload, "ws:to-server")
		assert.Contains(t, string(modified), "REDACTED")

		// Should not apply to ws:to-client
		unmodified := backend.ApplyWSRules(payload, "ws:to-client")
		assert.Equal(t, string(payload), string(unmodified))
	})

	t.Run("to_client", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		// Add WebSocket rule for to-client direction
		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "ws-to-client-rule",
			Type:    "ws:to-client",
			IsRegex: false,
			Find:    "server-internal",
			Replace: "public",
		})
		require.NoError(t, err)

		payload := []byte(`{"data":"server-internal-info"}`)

		// Should apply to ws:to-client
		modified := backend.ApplyWSRules(payload, "ws:to-client")
		assert.Contains(t, string(modified), "public-info")

		// Should not apply to ws:to-server
		unmodified := backend.ApplyWSRules(payload, "ws:to-server")
		assert.Equal(t, string(payload), string(unmodified))
	})

	t.Run("both_directions", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		// Add WebSocket rule for both directions
		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "ws-both-rule",
			Type:    "ws:both",
			IsRegex: false,
			Find:    "timestamp",
			Replace: "TS",
		})
		require.NoError(t, err)

		payload := []byte(`{"timestamp":"123456"}`)

		// Should apply to both directions
		toServer := backend.ApplyWSRules(payload, "ws:to-server")
		assert.Contains(t, string(toServer), "TS")

		toClient := backend.ApplyWSRules(payload, "ws:to-client")
		assert.Contains(t, string(toClient), "TS")
	})

	t.Run("regex", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		// Add regex WebSocket rule
		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "ws-regex-rule",
			Type:    "ws:both",
			IsRegex: true,
			Find:    `"id":\s*\d+`,
			Replace: `"id": 0`,
		})
		require.NoError(t, err)

		payload := []byte(`{"id": 12345, "data": "test"}`)

		modified := backend.ApplyWSRules(payload, "ws:to-server")
		assert.Contains(t, string(modified), `"id": 0`)
	})
}

func TestApplyMatchReplaceRule(t *testing.T) {
	t.Parallel()

	compiled, err := regexp.Compile(`\b\d{4}\b`)
	require.NoError(t, err)

	tests := []struct {
		name            string
		rule            nativeStoredRule
		input           string
		caseInsensitive bool
		want            string
	}{
		{
			name:  "literal_replace",
			rule:  nativeStoredRule{Find: "old", Replace: "new"},
			input: "This old text has old values",
			want:  "This new text has new values",
		},
		{
			name:  "regex_replace",
			rule:  nativeStoredRule{IsRegex: true, Find: `\b\d{4}\b`, Replace: "YEAR", compiled: compiled},
			input: "Year 2024 and 1999 are mentioned",
			want:  "Year YEAR and YEAR are mentioned",
		},
		{
			name:  "no_match",
			rule:  nativeStoredRule{Find: "nonexistent", Replace: "replacement"},
			input: "This text has no matches",
			want:  "This text has no matches",
		},
		{
			name:  "body_append",
			rule:  nativeStoredRule{Replace: "&appended=true"},
			input: "username=admin&password=test123",
			want:  "username=admin&password=test123&appended=true",
		},
		{
			name:            "header_append",
			rule:            nativeStoredRule{Replace: "X-Added: value\r\n"},
			input:           "Content-Type: text/plain\r\n",
			caseInsensitive: true,
			want:            "Content-Type: text/plain\r\nX-Added: value\r\n",
		},
		{
			name:            "header_append_no_trailing_crlf",
			rule:            nativeStoredRule{Replace: "X-Added: value\r\n"},
			input:           "Content-Type: text/plain",
			caseInsensitive: true,
			want:            "Content-Type: text/plain\r\nX-Added: value\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(applyMatchReplaceRule([]byte(tt.input), tt.rule, tt.caseInsensitive)))
		})
	}
}

func TestParseHeadersFromText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  []proxy.Header
	}{
		{
			name:  "single_header",
			input: "Content-Type: text/plain\r\n",
			want: []proxy.Header{
				{Name: "Content-Type", Value: "text/plain"},
			},
		},
		{
			name:  "multiple_headers",
			input: "Host: example.com\r\nContent-Type: application/json\r\nX-Custom: value\r\n",
			want: []proxy.Header{
				{Name: "Host", Value: "example.com"},
				{Name: "Content-Type", Value: "application/json"},
				{Name: "X-Custom", Value: "value"},
			},
		},
		{
			name:  "header_with_spaces",
			input: "X-Test:   value with spaces   \r\n",
			want: []proxy.Header{
				{Name: "X-Test", Value: "value with spaces"},
			},
		},
		{
			name:  "empty_value",
			input: "X-Empty:\r\n",
			want: []proxy.Header{
				{Name: "X-Empty", Value: ""},
			},
		},
		{
			name:  "malformed_no_colon",
			input: "MalformedHeader\r\nValid: value\r\n",
			want: []proxy.Header{
				{Name: "Valid", Value: "value"},
			},
		},
		{
			name:  "empty_input",
			input: "",
			want:  []proxy.Header{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseHeadersFromText([]byte(tt.input)))
		})
	}
}

func TestApplyRequestBodyOnlyRules(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir() // shared so CA cert is generated once

	t.Run("compression", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		// Add body rule
		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "body-rule",
			Type:    RuleTypeRequestBody,
			IsRegex: false,
			Find:    "token",
			Replace: "REDACTED",
		})
		require.NoError(t, err)

		// Create gzip-compressed body
		originalBody := []byte(`{"auth":"token123"}`)
		compressedBody, err := proxy.Compress(originalBody, "gzip")
		require.NoError(t, err)

		headers := []proxy.Header{
			{Name: "Content-Encoding", Value: "gzip"},
		}

		modified, modErr := backend.ApplyRequestBodyOnlyRules(compressedBody, headers)
		require.NoError(t, modErr)

		// Decompress and verify the rule was applied
		decompressed, wasCompressed := proxy.Decompress(modified, "gzip")
		assert.True(t, wasCompressed)
		assert.Contains(t, string(decompressed), "REDACTED123")
	})

	t.Run("invalid_compressed", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "body-rule",
			Type:    RuleTypeRequestBody,
			IsRegex: false,
			Find:    "test",
			Replace: "MODIFIED",
		})
		require.NoError(t, err)

		// Invalid brotli data - decompression fails, body unchanged
		fakeCompressed := []byte{0x1b, 0x03, 0x00, 0xf8, 0xff}
		originalBody := slices.Clone(fakeCompressed)

		headers := []proxy.Header{
			{Name: "Content-Encoding", Value: "br"},
		}

		modified, modErr := backend.ApplyRequestBodyOnlyRules(fakeCompressed, headers)
		require.NoError(t, modErr)
		assert.Equal(t, originalBody, modified)
	})

	t.Run("no_encoding", func(t *testing.T) {
		backend, err := NewNativeProxyBackend(0, configDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		// Add body rule
		_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
			Label:   "body-rule",
			Type:    RuleTypeRequestBody,
			IsRegex: false,
			Find:    "original",
			Replace: "modified",
		})
		require.NoError(t, err)

		body := []byte(`{"data":"original-value"}`)
		headers := []proxy.Header{} // no Content-Encoding

		modified, modErr := backend.ApplyRequestBodyOnlyRules(body, headers)
		require.NoError(t, modErr)

		assert.JSONEq(t, `{"data":"modified-value"}`, string(modified))
	})
}

package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/go-appsec/llm-security-toolbox/sectool/service/proxy"
	"github.com/go-appsec/llm-security-toolbox/sectool/service/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNativeProxyBackend_CreateAndServe(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
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
	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
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
	_ = resp.Body.Close()

	// Wait for history to be recorded
	time.Sleep(100 * time.Millisecond)

	// Get history
	ctx := context.Background()
	entries, err := backend.GetProxyHistory(ctx, 10, 0)
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
	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
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
	_ = resp.Body.Close()

	// Wait for history to be recorded
	time.Sleep(100 * time.Millisecond)

	// Get metadata
	ctx := context.Background()
	metas, err := backend.GetProxyHistoryMeta(ctx, 10, 0)
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

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()

	// Add rule
	isRegex := false
	rule, err := backend.AddRule(ctx, ProxyRuleInput{
		Label:   "test-rule",
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   "old-value",
		Replace: "new-value",
	})
	require.NoError(t, err)
	assert.Equal(t, "test-rule", rule.Label)
	assert.Equal(t, RuleTypeRequestHeader, rule.Type)
	assert.Equal(t, "old-value", rule.Match)

	// List rules
	rules, err := backend.ListRules(ctx, false)
	require.NoError(t, err)
	assert.Len(t, rules, 1)

	// Update rule
	updated, err := backend.UpdateRule(ctx, "test-rule", ProxyRuleInput{
		Label:   "test-rule",
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   "updated-value",
		Replace: "new-replacement",
	})
	require.NoError(t, err)
	assert.Equal(t, "updated-value", updated.Match)

	// Delete rule
	err = backend.DeleteRule(ctx, "test-rule")
	require.NoError(t, err)

	// Verify deleted
	rules, err = backend.ListRules(ctx, false)
	require.NoError(t, err)
	assert.Empty(t, rules)
}

func TestNativeProxyBackend_Rules_Persistence(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	ruleStorage := store.NewMemStorage()

	ctx := context.Background()
	isRegex := false
	isRegexTrue := true

	// Create backend and add rules
	backend1, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), ruleStorage)
	require.NoError(t, err)

	_, err = backend1.AddRule(ctx, ProxyRuleInput{
		Label:   "http-rule",
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   "old",
		Replace: "new",
	})
	require.NoError(t, err)

	_, err = backend1.AddRule(ctx, ProxyRuleInput{
		Label:   "ws-rule",
		Type:    "ws:both",
		IsRegex: &isRegexTrue,
		Match:   `\d+`,
		Replace: "NUM",
	})
	require.NoError(t, err)

	_ = backend1.Close()

	// Create new backend with same ruleStorage — rules should be loaded
	backend2, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), ruleStorage)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend2.Close() })

	httpRules, err := backend2.ListRules(ctx, false)
	require.NoError(t, err)
	require.Len(t, httpRules, 1)
	assert.Equal(t, "http-rule", httpRules[0].Label)
	assert.Equal(t, "old", httpRules[0].Match)

	wsRules, err := backend2.ListRules(ctx, true)
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

	tempDir := t.TempDir()
	ruleStorage := store.NewMemStorage()
	ctx := context.Background()
	isRegex := false

	backend1, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), ruleStorage)
	require.NoError(t, err)

	_, err = backend1.AddRule(ctx, ProxyRuleInput{
		Label: "to-delete", Type: RuleTypeRequestHeader,
		IsRegex: &isRegex, Match: "a", Replace: "b",
	})
	require.NoError(t, err)
	_, err = backend1.AddRule(ctx, ProxyRuleInput{
		Label: "to-keep", Type: RuleTypeRequestBody,
		IsRegex: &isRegex, Match: "c", Replace: "d",
	})
	require.NoError(t, err)

	err = backend1.DeleteRule(ctx, "to-delete")
	require.NoError(t, err)
	_ = backend1.Close()

	// New backend should only see the surviving rule
	backend2, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), ruleStorage)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend2.Close() })

	rules, err := backend2.ListRules(ctx, false)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.Equal(t, "to-keep", rules[0].Label)
}

func TestNativeProxyBackend_Rules_LabelUniqueness(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add first rule
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "unique-label",
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   "a",
		Replace: "b",
	})
	require.NoError(t, err)

	// Try to add duplicate label
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "unique-label",
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   "c",
		Replace: "d",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrLabelExists)
}

func TestNativeProxyBackend_Rules_InvalidType(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Type:    "invalid_type",
		IsRegex: &isRegex,
		Match:   "a",
		Replace: "b",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid rule type")
}

func TestNativeProxyBackend_Rules_Regex(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := true

	// Valid regex
	rule, err := backend.AddRule(ctx, ProxyRuleInput{
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   `\d+`,
		Replace: "NUMBER",
	})
	require.NoError(t, err)
	assert.True(t, rule.IsRegex)

	// Invalid regex
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   `[invalid`,
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
	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()

	// Send request directly (not through proxy)
	rawReq := []byte("GET /test HTTP/1.1\r\nHost: " + serverURL.Host + "\r\n\r\n")
	result, err := backend.SendRequest(ctx, "test", SendRequestInput{
		RawRequest: rawReq,
		Target: Target{
			Hostname:  serverURL.Hostname(),
			Port:      mustParsePort(t, serverURL.Port()),
			UsesHTTPS: false,
		},
		Timeout: 10 * time.Second,
	})
	require.NoError(t, err)

	assert.Contains(t, string(result.Headers), "200")
	assert.Contains(t, string(result.Headers), "X-Test: response")
	assert.Equal(t, "Hello from server", string(result.Body))

	// Verify Headers does NOT contain the body (regression test)
	assert.NotContains(t, string(result.Headers), "Hello from server",
		"Headers field should not contain response body")
	// Headers should end with header terminator
	assert.True(t, bytes.HasSuffix(result.Headers, []byte("\r\n\r\n")),
		"Headers should end with CRLF CRLF")
}

func TestNativeProxyBackend_Close(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
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

func TestNativeProxyBackend_ImplementsHttpBackend(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	// Compile-time check is in the source file, but we verify here too
	var _ HttpBackend = backend
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
	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
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
	_ = resp.Body.Close()

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

func TestApplyRequestRules_header_literal(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add header rule
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "header-rule",
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   "old-value",
		Replace: "new-value",
	})
	require.NoError(t, err)

	// Create request with header containing "old-value"
	req := &proxy.RawHTTP1Request{
		Method:  "GET",
		Path:    "/test",
		Version: "HTTP/1.1",
		Headers: []proxy.Header{
			{Name: "Host", Value: "example.com"},
			{Name: "X-Test", Value: "old-value"},
		},
	}

	// Apply rules
	modified := backend.ApplyRequestRules(req)

	assert.Equal(t, "new-value", modified.GetHeader("X-Test"))
}

func TestApplyRequestRules_header_regex(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := true

	// Add regex header rule
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "regex-header-rule",
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   `\d+`,
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
}

func TestApplyRequestRules_body_literal(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add body rule
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "body-rule",
		Type:    RuleTypeRequestBody,
		IsRegex: &isRegex,
		Match:   "secret",
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
}

func TestApplyRequestRules_no_matching_rules(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add rule that won't match
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "no-match-rule",
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   "nonexistent",
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
}

func TestApplyResponseRules_header_literal(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add response header rule
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "resp-header-rule",
		Type:    RuleTypeResponseHeader,
		IsRegex: &isRegex,
		Match:   "Apache/2.4",
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
}

func TestApplyResponseRules_body_literal(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add response body rule
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "resp-body-rule",
		Type:    RuleTypeResponseBody,
		IsRegex: &isRegex,
		Match:   "internal-error-code-123",
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
}

func TestApplyResponseRules_compressed_body(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add response body rule
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "compressed-body-rule",
		Type:    RuleTypeResponseBody,
		IsRegex: &isRegex,
		Match:   "secret",
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
}

func TestApplyResponseRules_unsupported_encoding_skips_rules(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add response body rule that would corrupt brotli if applied
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "body-rule",
		Type:    RuleTypeResponseBody,
		IsRegex: &isRegex,
		Match:   "test",
		Replace: "MODIFIED",
	})
	require.NoError(t, err)

	// Simulate brotli-compressed body (unsupported encoding)
	fakeCompressed := []byte{0x1b, 0x03, 0x00, 0xf8, 0xff} // invalid brotli
	originalBody := make([]byte, len(fakeCompressed))
	copy(originalBody, fakeCompressed)

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

	// Body should be unchanged since br is unsupported
	assert.Equal(t, originalBody, modified.Body)
	// Content-Encoding should still be present
	assert.Equal(t, "br", modified.GetHeader("Content-Encoding"))
}

func TestApplyResponseRules_multiple_encoding_skips_rules(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add response body rule
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "body-rule",
		Type:    RuleTypeResponseBody,
		IsRegex: &isRegex,
		Match:   "test",
		Replace: "MODIFIED",
	})
	require.NoError(t, err)

	// Multiple encodings should be skipped
	fakeBody := []byte("some test data")
	originalBody := make([]byte, len(fakeBody))
	copy(originalBody, fakeBody)

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
}

func TestApplyWSRules_to_server(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add WebSocket rule for to-server direction
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "ws-to-server-rule",
		Type:    "ws:to-server",
		IsRegex: &isRegex,
		Match:   "client-secret",
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
}

func TestApplyWSRules_to_client(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add WebSocket rule for to-client direction
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "ws-to-client-rule",
		Type:    "ws:to-client",
		IsRegex: &isRegex,
		Match:   "server-internal",
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
}

func TestApplyWSRules_both_directions(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add WebSocket rule for both directions
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "ws-both-rule",
		Type:    "ws:both",
		IsRegex: &isRegex,
		Match:   "timestamp",
		Replace: "TS",
	})
	require.NoError(t, err)

	payload := []byte(`{"timestamp":"123456"}`)

	// Should apply to both directions
	toServer := backend.ApplyWSRules(payload, "ws:to-server")
	assert.Contains(t, string(toServer), "TS")

	toClient := backend.ApplyWSRules(payload, "ws:to-client")
	assert.Contains(t, string(toClient), "TS")
}

func TestApplyWSRules_regex(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := true

	// Add regex WebSocket rule
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "ws-regex-rule",
		Type:    "ws:both",
		IsRegex: &isRegex,
		Match:   `"id":\s*\d+`,
		Replace: `"id": 0`,
	})
	require.NoError(t, err)

	payload := []byte(`{"id": 12345, "data": "test"}`)

	modified := backend.ApplyWSRules(payload, "ws:to-server")
	assert.Contains(t, string(modified), `"id": 0`)
}

func TestApplyMatchReplaceRule_literal(t *testing.T) {
	t.Parallel()

	rule := nativeStoredRule{
		ID:      "test",
		Type:    RuleTypeRequestBody,
		IsRegex: false,
		Match:   "old",
		Replace: "new",
	}

	input := []byte("This old text has old values")
	result := applyMatchReplaceRule(input, rule, false)

	assert.Equal(t, "This new text has new values", string(result))
}

func TestApplyMatchReplaceRule_regex(t *testing.T) {
	t.Parallel()

	compiled, err := regexp.Compile(`\b\d{4}\b`)
	require.NoError(t, err)

	rule := nativeStoredRule{
		ID:       "test",
		Type:     RuleTypeRequestBody,
		IsRegex:  true,
		Match:    `\b\d{4}\b`,
		Replace:  "YEAR",
		compiled: compiled,
	}

	input := []byte("Year 2024 and 1999 are mentioned")
	result := applyMatchReplaceRule(input, rule, false)

	assert.Equal(t, "Year YEAR and YEAR are mentioned", string(result))
}

func TestApplyMatchReplaceRule_no_match(t *testing.T) {
	t.Parallel()

	rule := nativeStoredRule{
		ID:      "test",
		Type:    RuleTypeRequestBody,
		IsRegex: false,
		Match:   "nonexistent",
		Replace: "replacement",
	}

	input := []byte("This text has no matches")
	result := applyMatchReplaceRule(input, rule, false)

	assert.Equal(t, string(input), string(result))
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
			result := parseHeadersFromText([]byte(tt.input))
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestApplyRequestRules_multiple_rules(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add multiple rules - they should apply in order
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "rule1",
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   "AAA",
		Replace: "BBB",
	})
	require.NoError(t, err)

	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "rule2",
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   "BBB",
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
}

func TestApplyRequestRules_empty_body(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add body rule
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "body-rule",
		Type:    RuleTypeRequestBody,
		IsRegex: &isRegex,
		Match:   "test",
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
}

func TestApplyRequestRules_compressed_body(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add body rule
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "body-rule",
		Type:    RuleTypeRequestBody,
		IsRegex: &isRegex,
		Match:   "secret",
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
}

func TestApplyRequestBodyOnlyRules_compression(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add body rule
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "body-rule",
		Type:    RuleTypeRequestBody,
		IsRegex: &isRegex,
		Match:   "token",
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
}

func TestApplyRequestBodyOnlyRules_unsupported_encoding(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add body rule that would corrupt brotli if applied
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "body-rule",
		Type:    RuleTypeRequestBody,
		IsRegex: &isRegex,
		Match:   "test",
		Replace: "MODIFIED",
	})
	require.NoError(t, err)

	// Fake brotli-compressed body (unsupported encoding)
	fakeCompressed := []byte{0x1b, 0x03, 0x00, 0xf8, 0xff}
	originalBody := make([]byte, len(fakeCompressed))
	copy(originalBody, fakeCompressed)

	headers := []proxy.Header{
		{Name: "Content-Encoding", Value: "br"},
	}

	modified, modErr := backend.ApplyRequestBodyOnlyRules(fakeCompressed, headers)
	require.NoError(t, modErr)

	// Body should be unchanged since br is unsupported
	assert.Equal(t, originalBody, modified)
}

func TestApplyRequestBodyOnlyRules_no_encoding(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	backend, err := NewNativeProxyBackend(0, tempDir, 10*1024*1024, store.NewMemStorage(), store.NewMemStorage())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx := context.Background()
	isRegex := false

	// Add body rule
	_, err = backend.AddRule(ctx, ProxyRuleInput{
		Label:   "body-rule",
		Type:    RuleTypeRequestBody,
		IsRegex: &isRegex,
		Match:   "original",
		Replace: "modified",
	})
	require.NoError(t, err)

	body := []byte(`{"data":"original-value"}`)
	headers := []proxy.Header{} // no Content-Encoding

	modified, modErr := backend.ApplyRequestBodyOnlyRules(body, headers)
	require.NoError(t, modErr)

	assert.JSONEq(t, `{"data":"modified-value"}`, string(modified))
}

package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoProxyBackend_Creation(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()

	backend, err := NewGoProxyBackend(0, configDir) // port 0 = random available port
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	assert.NotEmpty(t, backend.addr)
	assert.FileExists(t, filepath.Join(configDir, caCertFile))
	assert.FileExists(t, filepath.Join(configDir, caKeyFile))
}

func TestGoProxyBackend_CAReuse(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()

	// Create first backend - generates CA
	backend1, err := NewGoProxyBackend(0, configDir)
	require.NoError(t, err)
	_ = backend1.Close()

	// Get CA cert modification time
	certInfo, err := os.Stat(filepath.Join(configDir, caCertFile))
	require.NoError(t, err)
	origModTime := certInfo.ModTime()

	time.Sleep(10 * time.Millisecond) // ensure time difference

	// Create second backend - should reuse CA
	backend2, err := NewGoProxyBackend(0, configDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend2.Close() })

	// Verify CA wasn't regenerated
	certInfo2, err := os.Stat(filepath.Join(configDir, caCertFile))
	require.NoError(t, err)
	assert.Equal(t, origModTime, certInfo2.ModTime())
}

func TestGoProxyBackend_ProxyHistory(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()

	backend, err := NewGoProxyBackend(0, configDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	t.Cleanup(ts.Close)

	// Note: We test the proxy integration separately; here we just test storage

	// Get empty proxy history
	entries, err := backend.GetProxyHistory(t.Context(), 10, 0)
	require.NoError(t, err)
	assert.Empty(t, entries)

	// Directly store a history entry to test the storage
	err = backend.storeHistoryEntry("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nhello")
	require.NoError(t, err)

	entries, err = backend.GetProxyHistory(t.Context(), 10, 0)
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Contains(t, entries[0].Request, "GET /")
	assert.Contains(t, entries[0].Response, "200 OK")
}

func TestGoProxyBackend_Rules_CRUD(t *testing.T) {
	t.Parallel()

	t.Run("full_lifecycle", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		// List empty rules
		rules, err := backend.ListRules(t.Context(), false)
		require.NoError(t, err)
		assert.Empty(t, rules)

		// Add rule
		isRegex := false
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "test-rule", Type: RuleTypeRequestHeader, IsRegex: &isRegex, Match: "oldvalue", Replace: "newvalue",
		})
		require.NoError(t, err)
		assert.Equal(t, "test-rule", rule.Label)
		assert.Equal(t, RuleTypeRequestHeader, rule.Type)

		// List rules
		rules, err = backend.ListRules(t.Context(), false)
		require.NoError(t, err)
		assert.Len(t, rules, 1)

		// Update rule - preserves label
		updated, err := backend.UpdateRule(t.Context(), rule.RuleID, ProxyRuleInput{
			Type: RuleTypeRequestHeader, Match: "updated", Replace: "replaced",
		})
		require.NoError(t, err)
		assert.Equal(t, "updated", updated.Match)
		assert.Equal(t, "test-rule", updated.Label)

		// Delete rule
		err = backend.DeleteRule(t.Context(), rule.RuleID)
		require.NoError(t, err)
		rules, _ = backend.ListRules(t.Context(), false)
		assert.Empty(t, rules)
	})

	t.Run("update_same_label", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		var isRegex bool
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "keep-label", Type: RuleTypeRequestHeader, IsRegex: &isRegex, Match: "a", Replace: "b",
		})
		require.NoError(t, err)

		updated, err := backend.UpdateRule(t.Context(), rule.RuleID, ProxyRuleInput{
			Label: "keep-label", Type: RuleTypeRequestHeader, Match: "new-match", Replace: "new-replace",
		})
		require.NoError(t, err)
		assert.Equal(t, "keep-label", updated.Label)
		assert.Equal(t, "new-match", updated.Match)
	})

	t.Run("update_preserves_isregex", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		isRegex := true
		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "regex-rule", Type: RuleTypeRequestHeader, IsRegex: &isRegex, Match: `\d+`, Replace: "NUM",
		})
		require.NoError(t, err)
		assert.True(t, rule.IsRegex)

		// Update without specifying IsRegex - should preserve
		updated, err := backend.UpdateRule(t.Context(), rule.RuleID, ProxyRuleInput{
			Type: RuleTypeRequestHeader, Match: `\w+`, Replace: "WORD",
		})
		require.NoError(t, err)
		assert.True(t, updated.IsRegex)
	})

	t.Run("list_filters_by_type", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		var isRegex bool
		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "http-rule", Type: RuleTypeRequestHeader, IsRegex: &isRegex, Match: "old", Replace: "new",
		})
		require.NoError(t, err)
		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "ws-rule", Type: "ws:to-server", IsRegex: &isRegex, Match: "foo", Replace: "bar",
		})
		require.NoError(t, err)

		httpRules, err := backend.ListRules(t.Context(), false)
		require.NoError(t, err)
		assert.Len(t, httpRules, 1)
		assert.Equal(t, "http-rule", httpRules[0].Label)

		wsRules, err := backend.ListRules(t.Context(), true)
		require.NoError(t, err)
		assert.Len(t, wsRules, 1)
		assert.Equal(t, "ws-rule", wsRules[0].Label)
	})
}

func TestGoProxyBackend_RuleErrors(t *testing.T) {
	t.Parallel()

	t.Run("add_duplicate_label", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })
		var isRegex bool

		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "unique-label", Type: RuleTypeRequestHeader, IsRegex: &isRegex, Match: "a", Replace: "b",
		})
		require.NoError(t, err)

		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "unique-label", Type: RuleTypeRequestHeader, IsRegex: &isRegex, Match: "c", Replace: "d",
		})
		assert.ErrorIs(t, err, ErrLabelExists)
	})

	t.Run("add_invalid_type", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })
		var isRegex bool

		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "bad-rule", Type: "invalid_type", IsRegex: &isRegex, Match: "a", Replace: "b",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid rule type")
	})

	t.Run("add_invalid_regex", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })
		isRegex := true

		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "bad-regex", Type: RuleTypeRequestHeader, IsRegex: &isRegex, Match: "[invalid(regex", Replace: "x",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid regex pattern")
	})

	t.Run("update_not_found", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.UpdateRule(t.Context(), "nonexistent", ProxyRuleInput{
			Type: RuleTypeRequestHeader, Match: "a", Replace: "b",
		})
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("update_http_to_websocket", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })
		var isRegex bool

		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "http-rule", Type: RuleTypeRequestHeader, IsRegex: &isRegex, Match: "a", Replace: "b",
		})
		require.NoError(t, err)

		_, err = backend.UpdateRule(t.Context(), rule.RuleID, ProxyRuleInput{
			Type: "ws:to-server", Match: "x", Replace: "y",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot update HTTP rule with WebSocket type")
	})

	t.Run("update_websocket_to_http", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })
		var isRegex bool

		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "ws-rule", Type: "ws:both", IsRegex: &isRegex, Match: "a", Replace: "b",
		})
		require.NoError(t, err)

		_, err = backend.UpdateRule(t.Context(), rule.RuleID, ProxyRuleInput{
			Type: RuleTypeRequestBody, Match: "x", Replace: "y",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot update WebSocket rule with HTTP type")
	})

	t.Run("update_invalid_regex", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })
		var isRegex bool

		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "test-rule", Type: RuleTypeRequestHeader, IsRegex: &isRegex, Match: "a", Replace: "b",
		})
		require.NoError(t, err)

		isRegex = true
		_, err = backend.UpdateRule(t.Context(), rule.RuleID, ProxyRuleInput{
			Type: RuleTypeRequestHeader, IsRegex: &isRegex, Match: "[broken(regex", Replace: "c",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid regex pattern")
	})

	t.Run("update_label_conflict", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })
		var isRegex bool

		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "first", Type: RuleTypeRequestHeader, IsRegex: &isRegex, Match: "a", Replace: "b",
		})
		require.NoError(t, err)

		rule2, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "second", Type: RuleTypeRequestHeader, IsRegex: &isRegex, Match: "c", Replace: "d",
		})
		require.NoError(t, err)

		_, err = backend.UpdateRule(t.Context(), rule2.RuleID, ProxyRuleInput{
			Label: "first", Type: RuleTypeRequestHeader, Match: "c", Replace: "d",
		})
		assert.ErrorIs(t, err, ErrLabelExists)
	})

	t.Run("update_invalid_type", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })
		var isRegex bool

		rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "test", Type: RuleTypeRequestHeader, IsRegex: &isRegex, Match: "a", Replace: "b",
		})
		require.NoError(t, err)

		_, err = backend.UpdateRule(t.Context(), rule.RuleID, ProxyRuleInput{
			Type: "invalid_type", Match: "x", Replace: "y",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid rule type")
	})

	t.Run("delete_not_found", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		err = backend.DeleteRule(t.Context(), "nonexistent")
		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestGoProxyBackend_SendRequest(t *testing.T) {
	t.Parallel()

	t.Run("http", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Test", "header")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("response body"))
		}))
		t.Cleanup(ts.Close)

		rawReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", ts.Listener.Addr().String())
		result, err := backend.SendRequest(t.Context(), "test-req", SendRequestInput{
			RawRequest: []byte(rawReq),
			Target:     Target{Hostname: "127.0.0.1", Port: ts.Listener.Addr().(*net.TCPAddr).Port, UsesHTTPS: false},
			Timeout:    10 * time.Second,
		})
		require.NoError(t, err)
		assert.Contains(t, string(result.Headers), "200 OK")
		assert.Contains(t, string(result.Headers), "X-Test: header")
		assert.Equal(t, []byte("response body"), result.Body)
	})

	t.Run("https", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("secure response"))
		}))
		t.Cleanup(ts.Close)

		tsURL, err := url.Parse(ts.URL)
		require.NoError(t, err)
		port, _ := strconv.Atoi(tsURL.Port())
		rawReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", tsURL.Host)

		result, err := backend.SendRequest(t.Context(), "test-https", SendRequestInput{
			RawRequest: []byte(rawReq),
			Target:     Target{Hostname: tsURL.Hostname(), Port: port, UsesHTTPS: true},
			Timeout:    10 * time.Second,
		})
		require.NoError(t, err)
		assert.Contains(t, string(result.Headers), "200 OK")
		assert.Equal(t, []byte("secure response"), result.Body)
	})

	t.Run("timeout", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(500 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(ts.Close)

		tsURL, err := url.Parse(ts.URL)
		require.NoError(t, err)
		port, _ := strconv.Atoi(tsURL.Port())
		rawReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", tsURL.Host)

		_, err = backend.SendRequest(t.Context(), "timeout-test", SendRequestInput{
			RawRequest: []byte(rawReq),
			Target:     Target{Hostname: tsURL.Hostname(), Port: port, UsesHTTPS: false},
			Timeout:    50 * time.Millisecond,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context deadline exceeded")
	})

	t.Run("follow_redirects", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		var redirectCount int
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/final" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("final destination"))
				return
			}
			redirectCount++
			w.Header().Set("Location", "/final")
			w.WriteHeader(http.StatusFound)
		}))
		t.Cleanup(ts.Close)

		tsURL, err := url.Parse(ts.URL)
		require.NoError(t, err)
		port, _ := strconv.Atoi(tsURL.Port())
		rawReq := fmt.Sprintf("GET /start HTTP/1.1\r\nHost: %s\r\n\r\n", tsURL.Host)

		result, err := backend.SendRequest(t.Context(), "redirect-follow", SendRequestInput{
			RawRequest:      []byte(rawReq),
			Target:          Target{Hostname: tsURL.Hostname(), Port: port, UsesHTTPS: false},
			Timeout:         10 * time.Second,
			FollowRedirects: true,
		})
		require.NoError(t, err)
		assert.Contains(t, string(result.Headers), "200 OK")
		assert.Equal(t, []byte("final destination"), result.Body)
		assert.Equal(t, 1, redirectCount)
	})

	t.Run("stop_at_redirect", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "/final")
			w.WriteHeader(http.StatusFound)
		}))
		t.Cleanup(ts.Close)

		tsURL, err := url.Parse(ts.URL)
		require.NoError(t, err)
		port, _ := strconv.Atoi(tsURL.Port())
		rawReq := fmt.Sprintf("GET /start HTTP/1.1\r\nHost: %s\r\n\r\n", tsURL.Host)

		result, err := backend.SendRequest(t.Context(), "redirect-stop", SendRequestInput{
			RawRequest:      []byte(rawReq),
			Target:          Target{Hostname: tsURL.Hostname(), Port: port, UsesHTTPS: false},
			Timeout:         10 * time.Second,
			FollowRedirects: false,
		})
		require.NoError(t, err)
		assert.Contains(t, string(result.Headers), "302")
		assert.Contains(t, string(result.Headers), "Location: /final")
	})

	t.Run("invalid_request", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		_, err = backend.SendRequest(t.Context(), "invalid", SendRequestInput{
			RawRequest: []byte("not a valid http request"),
			Target:     Target{Hostname: "127.0.0.1", Port: 80, UsesHTTPS: false},
			Timeout:    5 * time.Second,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse request")
	})

	t.Run("connection_refused", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		rawReq := "GET / HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"
		_, err = backend.SendRequest(t.Context(), "refused", SendRequestInput{
			RawRequest: []byte(rawReq),
			Target:     Target{Hostname: "127.0.0.1", Port: 1, UsesHTTPS: false},
			Timeout:    2 * time.Second,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "send request")
	})
}

func TestApplyMatchReplace(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		rule     storedRule
		expected string
	}{
		{
			name:  "literal_replace",
			input: "hello world hello",
			rule: storedRule{
				IsRegex: false,
				Match:   "hello",
				Replace: "hi",
			},
			expected: "hi world hi",
		},
		{
			name:  "regex_replace",
			input: "user123 user456",
			rule: storedRule{
				IsRegex: true,
				Match:   `user(\d+)`,
				Replace: "id:$1",
			},
			expected: "id:123 id:456",
		},
		{
			name:  "empty_input",
			input: "",
			rule: storedRule{
				Match:   "foo",
				Replace: "bar",
			},
			expected: "",
		},
		{
			name:  "no_match",
			input: "hello world",
			rule: storedRule{
				Match:   "foo",
				Replace: "bar",
			},
			expected: "hello world",
		},
		{
			name:  "empty_replacement",
			input: "remove this word",
			rule: storedRule{
				Match:   "this ",
				Replace: "",
			},
			expected: "remove word",
		},
		{
			name:  "regex_no_compiled_cache",
			input: "test123test456",
			rule: storedRule{
				IsRegex: true,
				Match:   `\d+`,
				Replace: "NUM",
			},
			expected: "testNUMtestNUM",
		},
		{
			name:  "invalid_regex_returns_input",
			input: "unchanged",
			rule: storedRule{
				IsRegex:  true,
				Match:    "[broken",
				Replace:  "x",
				compiled: nil,
			},
			expected: "unchanged",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, string(applyMatchReplace([]byte(tc.input), tc.rule)))
		})
	}
}

func TestGoProxyBackend_ProxyIntegration(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()

	backend, err := NewGoProxyBackend(0, configDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	// Create a simple HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "test response")
	}))
	t.Cleanup(ts.Close)

	// Make request through the proxy
	proxyURL, err := url.Parse("http://" + backend.addr)
	require.NoError(t, err)
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	client := &http.Client{Transport: transport}

	resp, err := client.Get(ts.URL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "test response", string(body))

	// Verify request was captured in history
	time.Sleep(50 * time.Millisecond) // allow async storage
	entries, err := backend.GetProxyHistory(t.Context(), 10, 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(entries), 1)
}

func TestCompressDecompress(t *testing.T) {
	t.Parallel()

	original := []byte("test content for compression testing")

	tests := []struct {
		name     string
		encoding string
	}{
		{"gzip", "gzip"},
		{"deflate", "deflate"},
		{"no_encoding", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			compressed, err := compressBody(original, tc.encoding)
			require.NoError(t, err)

			if tc.encoding != "" {
				assert.NotEqual(t, original, compressed)
			}

			// Create a mock response to test decompression
			resp := &http.Response{
				Header: make(http.Header),
				Body:   io.NopCloser(bytes.NewReader(compressed)),
			}
			if tc.encoding != "" {
				resp.Header.Set("Content-Encoding", tc.encoding)
			}

			decompressed, encoding, skipRules, err := readAndDecompressBody(resp)
			require.NoError(t, err)
			assert.False(t, skipRules)
			assert.Equal(t, tc.encoding, encoding)
			assert.Equal(t, original, decompressed)
		})
	}
}

func TestWSFrameRoundTrip(t *testing.T) {
	t.Parallel()

	// Generate payloads for extended length tests
	payload300 := make([]byte, 300) // 16-bit length (>125 bytes)
	for i := range payload300 {
		payload300[i] = byte(i % 256)
	}
	payload70k := make([]byte, 70000) // 64-bit length (>65535 bytes)
	for i := range payload70k {
		payload70k[i] = byte(i % 256)
	}

	tests := []struct {
		name         string
		frame        *wsFrame
		checkLenByte byte // expected length indicator in second byte (126 or 127)
		checkPayload bool // whether to verify full payload (skip for large payloads)
	}{
		{
			name:         "text_frame",
			frame:        &wsFrame{fin: true, opcode: 1, payload: []byte("hello world")},
			checkPayload: true,
		},
		{
			name:         "binary_frame",
			frame:        &wsFrame{fin: true, opcode: 2, payload: []byte{0x00, 0x01, 0x02, 0xff}},
			checkPayload: true,
		},
		{
			name:         "frame_with_rsv",
			frame:        &wsFrame{fin: true, rsv: 0x04, opcode: 1, payload: []byte("compressed")},
			checkPayload: true,
		},
		{
			name:         "masked_frame",
			frame:        &wsFrame{fin: true, opcode: 1, masked: true, mask: [4]byte{0x12, 0x34, 0x56, 0x78}, payload: []byte("masked data")},
			checkPayload: true,
		},
		{
			name:         "ping_control",
			frame:        &wsFrame{fin: true, opcode: 9, payload: []byte{0x03, 0xE8}},
			checkPayload: true,
		},
		{
			name:         "pong_control",
			frame:        &wsFrame{fin: true, opcode: 10, payload: []byte{0x03, 0xE8}},
			checkPayload: true,
		},
		{
			name:         "close_control",
			frame:        &wsFrame{fin: true, opcode: 8, payload: []byte{0x03, 0xE8}},
			checkPayload: true,
		},
		{
			name:         "continuation_frame",
			frame:        &wsFrame{fin: false, opcode: 0, payload: []byte("continued data")},
			checkPayload: true,
		},
		{
			name:         "16bit_length",
			frame:        &wsFrame{fin: true, opcode: 2, payload: payload300},
			checkLenByte: 126,
			checkPayload: true,
		},
		{
			name:         "64bit_length",
			frame:        &wsFrame{fin: true, opcode: 2, payload: payload70k},
			checkLenByte: 127,
			checkPayload: false, // just check length, not full content
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := encodeWSFrame(tc.frame)

			if tc.checkLenByte != 0 {
				assert.Equal(t, tc.checkLenByte, encoded[1]&0x7F)
			}

			decoded, err := readWSFrame(bytes.NewReader(encoded))
			require.NoError(t, err)

			assert.Equal(t, tc.frame.fin, decoded.fin)
			assert.Equal(t, tc.frame.rsv, decoded.rsv)
			assert.Equal(t, tc.frame.opcode, decoded.opcode)
			if tc.checkPayload {
				assert.Equal(t, tc.frame.payload, decoded.payload)
			} else {
				assert.Len(t, decoded.payload, len(tc.frame.payload))
			}
		})
	}
}

// TestWSFrameMaskingRFC6455 verifies RFC 6455 §5.1 masking requirements:
// - Client→Server frames MUST be masked (mask bit set, 4-byte mask key present)
// - Server→Client frames MUST NOT be masked (mask bit clear, no mask key)
func TestWSFrameMaskingRFC6455(t *testing.T) {
	t.Parallel()

	payload := []byte("test payload")

	t.Run("client_to_server_must_be_masked", func(t *testing.T) {
		frame := &wsFrame{
			fin:     true,
			opcode:  1,
			masked:  true,
			mask:    [4]byte{0xAB, 0xCD, 0xEF, 0x12},
			payload: payload,
		}

		encoded := encodeWSFrame(frame)

		// Verify mask bit is set in second byte (bit 7)
		assert.NotEqual(t, byte(0), encoded[1]&0x80, "mask bit should be set for client→server")

		// Verify mask key is present (bytes 2-5 for small payloads)
		assert.Equal(t, byte(0xAB), encoded[2])
		assert.Equal(t, byte(0xCD), encoded[3])
		assert.Equal(t, byte(0xEF), encoded[4])
		assert.Equal(t, byte(0x12), encoded[5])

		// Verify payload is XOR'd with mask
		for i, b := range payload {
			expected := b ^ frame.mask[i%4]
			assert.Equal(t, expected, encoded[6+i], "payload byte %d should be masked", i)
		}
	})

	t.Run("server_to_client_must_not_be_masked", func(t *testing.T) {
		frame := &wsFrame{
			fin:     true,
			opcode:  1,
			masked:  false,
			payload: payload,
		}

		encoded := encodeWSFrame(frame)

		// Verify mask bit is NOT set in second byte
		assert.Equal(t, byte(0), encoded[1]&0x80, "mask bit should NOT be set for server→client")

		// Verify payload starts immediately after length (byte 2 for small payloads)
		assert.Equal(t, payload, encoded[2:2+len(payload)])
	})
}

func TestDecompressionFallback(t *testing.T) {
	t.Parallel()

	t.Run("gzip_header_with_non_gzip_body", func(t *testing.T) {
		// Body claims to be gzip but isn't - should return original body and skipRules=true
		fakeGzipBody := []byte("this is not gzip data")
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader(fakeGzipBody)),
		}
		resp.Header.Set("Content-Encoding", "gzip")

		body, encoding, skipRules, err := readAndDecompressBody(resp)
		require.NoError(t, err)
		assert.True(t, skipRules)
		assert.Equal(t, "gzip", encoding)
		assert.Equal(t, fakeGzipBody, body)
	})

	t.Run("deflate_header_with_corrupted_body", func(t *testing.T) {
		corruptedDeflate := []byte{0x78, 0x9c, 0xFF, 0xFF} // invalid deflate
		resp := &http.Response{
			Header: make(http.Header),
			Body:   io.NopCloser(bytes.NewReader(corruptedDeflate)),
		}
		resp.Header.Set("Content-Encoding", "deflate")

		body, encoding, skipRules, err := readAndDecompressBody(resp)
		require.NoError(t, err)
		assert.True(t, skipRules)
		assert.Equal(t, "deflate", encoding)
		assert.Equal(t, corruptedDeflate, body)
	})
}

func TestHostHeaderRule(t *testing.T) {
	configDir := t.TempDir()
	backend, err := NewGoProxyBackend(0, configDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	var isRegex bool

	t.Run("match_and_replace_host", func(t *testing.T) {
		// Add rule to replace Host header
		_, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label:   "replace-host",
			Type:    RuleTypeRequestHeader,
			IsRegex: &isRegex,
			Match:   "Host: original.example.com",
			Replace: "Host: modified.example.com",
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.DeleteRule(context.Background(), "replace-host") })

		// Create a request with Host header
		req, err := http.NewRequest("GET", "http://original.example.com/test", nil)
		require.NoError(t, err)
		req.Host = "original.example.com"

		// Apply rules
		modifiedReq, err := backend.applyRequestRules(req)
		require.NoError(t, err)
		assert.Equal(t, "modified.example.com", modifiedReq.Host)
	})

	t.Run("regex_host_replacement", func(t *testing.T) {
		isRegexTrue := true
		_, err := backend.AddRule(t.Context(), ProxyRuleInput{
			Label:   "regex-host",
			Type:    RuleTypeRequestHeader,
			IsRegex: &isRegexTrue,
			Match:   `Host: ([a-z]+)\.example\.com`,
			Replace: "Host: $1.modified.com",
		})
		require.NoError(t, err)
		defer func() { _ = backend.DeleteRule(t.Context(), "regex-host") }()

		req, err := http.NewRequest("GET", "http://api.example.com/test", nil)
		require.NoError(t, err)
		req.Host = "api.example.com"

		modifiedReq, err := backend.applyRequestRules(req)
		require.NoError(t, err)
		assert.Equal(t, "api.modified.com", modifiedReq.Host)
	})
}

func TestGoProxyBackend_Close_Idempotent(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	backend, err := NewGoProxyBackend(0, configDir)
	require.NoError(t, err)

	// First close should succeed
	err = backend.Close()
	require.NoError(t, err)

	// Second close should be no-op (not error)
	err = backend.Close()
	require.NoError(t, err)
}

func TestGoProxyBackend_AddRule_WebSocketTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ruleType string
	}{
		{"to_server", "ws:to-server"},
		{"to_client", "ws:to-client"},
		{"both", "ws:both"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configDir := t.TempDir()
			backend, err := NewGoProxyBackend(0, configDir)
			require.NoError(t, err)
			t.Cleanup(func() { _ = backend.Close() })

			var isRegex bool
			rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
				Label:   "ws-" + tc.name,
				Type:    tc.ruleType,
				IsRegex: &isRegex,
				Match:   "match",
				Replace: "replace",
			})
			require.NoError(t, err)
			assert.Equal(t, tc.ruleType, rule.Type)

			// Verify it shows up as websocket rule
			wsRules, err := backend.ListRules(t.Context(), true)
			require.NoError(t, err)
			assert.Len(t, wsRules, 1)
		})
	}
}

func TestGoProxyBackend_GetProxyHistory_WithOffset(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	backend, err := NewGoProxyBackend(0, configDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	// Store multiple entries
	for i := 0; i < 5; i++ {
		err := backend.storeHistoryEntry(
			fmt.Sprintf("GET /%d HTTP/1.1\r\nHost: example.com\r\n\r\n", i),
			fmt.Sprintf("HTTP/1.1 200 OK\r\n\r\nresponse %d", i),
		)
		require.NoError(t, err)
	}

	// Get with offset
	entries, err := backend.GetProxyHistory(t.Context(), 2, 2)
	require.NoError(t, err)
	assert.Len(t, entries, 2)
	assert.Contains(t, entries[0].Request, "/2")
	assert.Contains(t, entries[1].Request, "/3")
}

func TestIsWebSocketUpgrade(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		upgrade    string
		connection string
		expected   bool
	}{
		{"valid_websocket", "websocket", "Upgrade", true},
		{"case_insensitive_upgrade", "WEBSOCKET", "upgrade", true},
		{"connection_with_other_values", "websocket", "keep-alive, Upgrade", true},
		{"no_upgrade_header", "", "Upgrade", false},
		{"no_connection_header", "websocket", "", false},
		{"wrong_upgrade", "h2c", "Upgrade", false},
		{"wrong_connection", "websocket", "close", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://example.com/ws", nil)
			require.NoError(t, err)
			if tc.upgrade != "" {
				req.Header.Set("Upgrade", tc.upgrade)
			}
			if tc.connection != "" {
				req.Header.Set("Connection", tc.connection)
			}
			assert.Equal(t, tc.expected, isWebSocketUpgrade(req))
		})
	}
}

func TestApplyWSRules(t *testing.T) {
	t.Parallel()

	t.Run("no_rules", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		payload := []byte("unchanged payload")
		result := backend.applyWSRules(payload, "ws:to-server")
		assert.Equal(t, payload, result)
	})

	t.Run("directional_rules", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		var isRegex bool
		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "to-server", Type: "ws:to-server", IsRegex: &isRegex, Match: "client", Replace: "SERVER",
		})
		require.NoError(t, err)
		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "to-client", Type: "ws:to-client", IsRegex: &isRegex, Match: "server", Replace: "CLIENT",
		})
		require.NoError(t, err)
		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "both", Type: "ws:both", IsRegex: &isRegex, Match: "data", Replace: "DATA",
		})
		require.NoError(t, err)

		// to-server applies to-server and both rules, not to-client
		result := backend.applyWSRules([]byte("client data server"), "ws:to-server")
		assert.Equal(t, "SERVER DATA server", string(result))

		// to-client applies to-client and both rules, not to-server
		result = backend.applyWSRules([]byte("client data server"), "ws:to-client")
		assert.Equal(t, "client DATA CLIENT", string(result))
	})

	t.Run("both_direction_rule", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		var isRegex bool
		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "both-dir", Type: "ws:both", IsRegex: &isRegex, Match: "secret", Replace: "REDACTED",
		})
		require.NoError(t, err)

		result1 := backend.applyWSRules([]byte("secret data"), "ws:to-server")
		assert.Equal(t, "REDACTED data", string(result1))

		result2 := backend.applyWSRules([]byte("secret data"), "ws:to-client")
		assert.Equal(t, "REDACTED data", string(result2))
	})
}

func TestApplyRequestRules(t *testing.T) {
	t.Parallel()

	t.Run("body_modification", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		var isRegex bool
		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "body-rule", Type: RuleTypeRequestBody, IsRegex: &isRegex, Match: "oldvalue", Replace: "newvalue-longer",
		})
		require.NoError(t, err)

		body := []byte("body contains oldvalue here")
		req, err := http.NewRequest("POST", "http://example.com/test", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))

		modifiedReq, err := backend.applyRequestRules(req)
		require.NoError(t, err)

		modifiedBody, err := io.ReadAll(modifiedReq.Body)
		require.NoError(t, err)
		assert.Contains(t, string(modifiedBody), "newvalue-longer")
		assert.NotContains(t, string(modifiedBody), "oldvalue")
		assert.Equal(t, int64(len(modifiedBody)), modifiedReq.ContentLength)
	})

	t.Run("header_only", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		var isRegex bool
		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "auth-rule", Type: RuleTypeRequestHeader, IsRegex: &isRegex,
			Match: "Authorization: Bearer old-token", Replace: "Authorization: Bearer new-token",
		})
		require.NoError(t, err)

		req, err := http.NewRequest("GET", "http://example.com/api", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer old-token")

		modifiedReq, err := backend.applyRequestRules(req)
		require.NoError(t, err)
		assert.Equal(t, "Bearer new-token", modifiedReq.Header.Get("Authorization"))
	})
}

func TestApplyResponseRules(t *testing.T) {
	t.Parallel()

	t.Run("gzip_compressed_body", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		var isRegex bool
		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "resp-body-rule", Type: RuleTypeResponseBody, IsRegex: &isRegex, Match: "secret", Replace: "REDACTED",
		})
		require.NoError(t, err)

		originalBody := []byte("response contains secret data")
		compressed, err := compressBody(originalBody, "gzip")
		require.NoError(t, err)

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(compressed)),
		}
		resp.Header.Set("Content-Encoding", "gzip")
		resp.Header.Set("Content-Length", strconv.Itoa(len(compressed)))

		modifiedResp, err := backend.applyResponseRules(resp)
		require.NoError(t, err)
		assert.Equal(t, "gzip", modifiedResp.Header.Get("Content-Encoding"))

		modifiedBody, _, _, err := readAndDecompressBody(modifiedResp)
		require.NoError(t, err)
		assert.Contains(t, string(modifiedBody), "REDACTED")
		assert.NotContains(t, string(modifiedBody), "secret")
	})

	t.Run("uncompressed_body", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		var isRegex bool
		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "resp-body-rule", Type: RuleTypeResponseBody, IsRegex: &isRegex, Match: "secret", Replace: "REDACTED",
		})
		require.NoError(t, err)

		originalBody := []byte("response contains secret data")
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(originalBody)),
		}
		resp.Header.Set("Content-Length", strconv.Itoa(len(originalBody)))

		modifiedResp, err := backend.applyResponseRules(resp)
		require.NoError(t, err)

		modifiedBody, err := io.ReadAll(modifiedResp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(modifiedBody), "REDACTED")
	})

	t.Run("header_only", func(t *testing.T) {
		backend, err := NewGoProxyBackend(0, t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		var isRegex bool
		_, err = backend.AddRule(t.Context(), ProxyRuleInput{
			Label: "server-rule", Type: RuleTypeResponseHeader, IsRegex: &isRegex,
			Match: "Server: nginx/1.0", Replace: "Server: hidden",
		})
		require.NoError(t, err)

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader([]byte("body"))),
		}
		resp.Header.Set("Server", "nginx/1.0")

		modifiedResp, err := backend.applyResponseRules(resp)
		require.NoError(t, err)
		assert.Equal(t, "hidden", modifiedResp.Header.Get("Server"))
	})
}

func TestApplyHeaderRule(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	backend, err := NewGoProxyBackend(0, configDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	tests := []struct {
		name          string
		rule          storedRule
		inputHeaders  map[string]string
		checkHeader   string
		expectedValue string
		shouldBeEmpty bool
	}{
		{
			name: "replace_header_value",
			rule: storedRule{
				ID:      "test",
				Type:    RuleTypeResponseHeader,
				IsRegex: false,
				Match:   "Server: Apache",
				Replace: "Server: nginx",
			},
			inputHeaders:  map[string]string{"Server": "Apache", "Content-Type": "text/html"},
			checkHeader:   "Server",
			expectedValue: "nginx",
		},
		{
			name: "delete_header",
			rule: storedRule{
				ID:      "test",
				Type:    RuleTypeResponseHeader,
				IsRegex: false,
				Match:   "X-Debug: true\r\n",
				Replace: "",
			},
			inputHeaders:  map[string]string{"X-Debug": "true", "Content-Type": "text/html"},
			checkHeader:   "X-Debug",
			shouldBeEmpty: true,
		},
		{
			name: "add_new_header_via_replace",
			rule: storedRule{
				ID:      "test",
				Type:    RuleTypeResponseHeader,
				IsRegex: true,
				Match:   `(Existing: value)`,
				Replace: "$1\r\nX-Added: new",
			},
			inputHeaders:  map[string]string{"Existing": "value"},
			checkHeader:   "X-Added",
			expectedValue: "new",
		},
		{
			name: "regex_capture_group",
			rule: storedRule{
				ID:      "test",
				Type:    RuleTypeResponseHeader,
				IsRegex: true,
				Match:   `X-Version: v(\d+)\.(\d+)\.(\d+)`,
				Replace: "X-Version: $1.$2.0",
			},
			inputHeaders:  map[string]string{"X-Version": "v1.2.3"},
			checkHeader:   "X-Version",
			expectedValue: "1.2.0",
		},
		{
			name: "empty_header_map",
			rule: storedRule{
				ID:      "test",
				Type:    RuleTypeResponseHeader,
				IsRegex: false,
				Match:   "old",
				Replace: "new",
			},
			inputHeaders:  map[string]string{},
			checkHeader:   "Anything",
			shouldBeEmpty: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			header := make(http.Header)
			for k, v := range tc.inputHeaders {
				header.Set(k, v)
			}

			result := backend.applyHeaderRule(header, tc.rule)

			if tc.shouldBeEmpty {
				assert.Empty(t, result.Get(tc.checkHeader))
			} else {
				assert.Equal(t, tc.expectedValue, result.Get(tc.checkHeader))
			}
		})
	}
}

func TestReadWSFrame_Errors(t *testing.T) {
	t.Parallel()

	t.Run("truncated_header", func(t *testing.T) {
		// Only 1 byte when 2 are needed
		_, err := readWSFrame(bytes.NewReader([]byte{0x81}))
		assert.Error(t, err)
	})

	t.Run("truncated_16bit_length", func(t *testing.T) {
		// Header says 126 (16-bit length) but only 1 extra byte
		_, err := readWSFrame(bytes.NewReader([]byte{0x81, 126, 0x01}))
		assert.Error(t, err)
	})

	t.Run("truncated_64bit_length", func(t *testing.T) {
		// Header says 127 (64-bit length) but only 4 extra bytes
		_, err := readWSFrame(bytes.NewReader([]byte{0x81, 127, 0, 0, 0, 0}))
		assert.Error(t, err)
	})

	t.Run("truncated_mask", func(t *testing.T) {
		// Masked frame but only 2 bytes of mask
		_, err := readWSFrame(bytes.NewReader([]byte{0x81, 0x82, 0x01, 0x02}))
		assert.Error(t, err)
	})

	t.Run("truncated_payload", func(t *testing.T) {
		// Says 5 byte payload but only provides 2
		_, err := readWSFrame(bytes.NewReader([]byte{0x81, 0x05, 'h', 'i'}))
		assert.Error(t, err)
	})
}

func TestCALoadingErrors(t *testing.T) {
	t.Run("orphaned_cert_file", func(t *testing.T) {
		configDir := t.TempDir()

		// Create only cert file (missing key)
		certPath := filepath.Join(configDir, caCertFile)
		err := os.WriteFile(certPath, []byte("fake cert"), 0644)
		require.NoError(t, err)

		_, err = NewGoProxyBackend(0, configDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key is missing")
	})

	t.Run("orphaned_key_file", func(t *testing.T) {
		configDir := t.TempDir()

		// Create only key file (missing cert)
		keyPath := filepath.Join(configDir, caKeyFile)
		err := os.WriteFile(keyPath, []byte("fake key"), 0600)
		require.NoError(t, err)

		_, err = NewGoProxyBackend(0, configDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "certificate is missing")
	})

	t.Run("invalid_cert_pem", func(t *testing.T) {
		configDir := t.TempDir()

		// Create both files with invalid content
		certPath := filepath.Join(configDir, caCertFile)
		keyPath := filepath.Join(configDir, caKeyFile)
		err := os.WriteFile(certPath, []byte("not a pem"), 0644)
		require.NoError(t, err)
		err = os.WriteFile(keyPath, []byte("not a pem"), 0600)
		require.NoError(t, err)

		_, err = NewGoProxyBackend(0, configDir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse CA certificate PEM")
	})
}

func TestHasWebSocketRules(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	backend, err := NewGoProxyBackend(0, configDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	// Initially no rules
	assert.False(t, backend.hasWebSocketRules())

	// Add HTTP rule
	var isRegex bool
	_, err = backend.AddRule(t.Context(), ProxyRuleInput{
		Label:   "http",
		Type:    RuleTypeRequestHeader,
		IsRegex: &isRegex,
		Match:   "a",
		Replace: "b",
	})
	require.NoError(t, err)
	assert.False(t, backend.hasWebSocketRules())

	// Add WebSocket rule
	_, err = backend.AddRule(t.Context(), ProxyRuleInput{
		Label:   "ws",
		Type:    "ws:both",
		IsRegex: &isRegex,
		Match:   "x",
		Replace: "y",
	})
	require.NoError(t, err)
	assert.True(t, backend.hasWebSocketRules())
}

func TestApplyRequestHeaderRule(t *testing.T) {
	t.Parallel()

	backend, err := NewGoProxyBackend(0, t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	t.Run("empty_host", func(t *testing.T) {
		rule := storedRule{
			ID: "test", Type: RuleTypeRequestHeader, IsRegex: false, Match: "X-Old: value", Replace: "X-New: value",
		}
		header := make(http.Header)
		header.Set("X-Old", "value")

		result, host := backend.applyRequestHeaderRule(header, "", rule)
		assert.Empty(t, host)
		assert.Equal(t, "value", result.Get("X-New"))
	})

	t.Run("header_without_space_after_colon", func(t *testing.T) {
		rule := storedRule{
			ID: "test", Type: RuleTypeRequestHeader, IsRegex: false, Match: "X-Test: old", Replace: "X-Test:new",
		}
		header := make(http.Header)
		header.Set("X-Test", "old")

		result, _ := backend.applyRequestHeaderRule(header, "example.com", rule)
		assert.Equal(t, "new", result.Get("X-Test"))
	})

	t.Run("no_change_needed", func(t *testing.T) {
		rule := storedRule{
			ID: "test", Type: RuleTypeRequestHeader, IsRegex: false, Match: "nonexistent", Replace: "replacement",
		}
		header := make(http.Header)
		header.Set("X-Keep", "value")

		result, host := backend.applyRequestHeaderRule(header, "example.com", rule)
		assert.Equal(t, "example.com", host)
		assert.Equal(t, "value", result.Get("X-Keep"))
	})
}

func TestDialWebSocket_NonUpgradeResponse(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	backend, err := NewGoProxyBackend(0, configDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	// Server that returns 200 instead of 101
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not a websocket"))
	}))
	t.Cleanup(ts.Close)

	tsURL, err := url.Parse(ts.URL)
	require.NoError(t, err)

	req, err := http.NewRequest("GET", "/ws", nil)
	require.NoError(t, err)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Host = tsURL.Host

	_, _, err = backend.dialWebSocket(t.Context(), tsURL.Host, false, req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status: 200")
}

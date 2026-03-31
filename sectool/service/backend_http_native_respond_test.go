package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

func TestNativeProxyBackend_AddResponder(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	entry, err := backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Origin:     "https://example.com",
		Path:       "/set-cookies",
		StatusCode: 200,
		Headers:    map[string]string{"Set-Cookie": "session=abc123"},
		Body:       "<html>ok</html>",
		Label:      "set-cookies",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, entry.ResponderID)
	assert.Equal(t, "https://example.com", entry.Origin)
	assert.Equal(t, "/set-cookies", entry.Path)
	assert.Equal(t, 200, entry.StatusCode)
	assert.Equal(t, "set-cookies", entry.Label)
	assert.Equal(t, "<html>ok</html>", entry.Body)
	assert.Equal(t, map[string]string{"Set-Cookie": "session=abc123"}, entry.Headers)
}

func TestNativeProxyBackend_AddResponder_DefaultStatus(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	entry, err := backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Origin: "https://example.com",
		Path:   "/page",
	})
	require.NoError(t, err)
	assert.Equal(t, 200, entry.StatusCode)
}

func TestNativeProxyBackend_DeleteResponder(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	entry, err := backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Origin: "https://example.com",
		Path:   "/page",
		Label:  "my-page",
	})
	require.NoError(t, err)

	// Delete by ID
	err = backend.DeleteResponder(t.Context(), entry.ResponderID)
	require.NoError(t, err)

	// Not found
	err = backend.DeleteResponder(t.Context(), entry.ResponderID)
	require.ErrorIs(t, err, ErrNotFound)

	// Add again and delete by label
	_, err = backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Origin: "https://example.com",
		Path:   "/page2",
		Label:  "my-page2",
	})
	require.NoError(t, err)

	err = backend.DeleteResponder(t.Context(), "my-page2")
	require.NoError(t, err)
}

func TestNativeProxyBackend_ListResponders(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	// Empty list
	list, err := backend.ListResponders(t.Context())
	require.NoError(t, err)
	assert.Empty(t, list)

	// Add two
	_, err = backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Origin: "https://example.com",
		Path:   "/a",
	})
	require.NoError(t, err)

	_, err = backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Origin: "http://other.com:8080",
		Path:   "/b",
	})
	require.NoError(t, err)

	list, err = backend.ListResponders(t.Context())
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestNativeProxyBackend_InterceptRequest(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	_, err = backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Origin:     "https://example.com",
		Path:       "/set-state",
		Method:     "GET",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html"},
		Body:       "<html>state set</html>",
	})
	require.NoError(t, err)

	t.Run("match", func(t *testing.T) {
		resp := backend.InterceptRequest("example.com", 443, "/set-state", "GET")
		require.NotNil(t, resp)
		assert.Equal(t, 200, resp.StatusCode)
		assert.Equal(t, []byte("<html>state set</html>"), resp.Body)
	})

	t.Run("no_match_host", func(t *testing.T) {
		resp := backend.InterceptRequest("other.com", 443, "/set-state", "GET")
		assert.Nil(t, resp)
	})

	t.Run("no_match_port", func(t *testing.T) {
		resp := backend.InterceptRequest("example.com", 8443, "/set-state", "GET")
		assert.Nil(t, resp)
	})

	t.Run("no_match_path", func(t *testing.T) {
		resp := backend.InterceptRequest("example.com", 443, "/other", "GET")
		assert.Nil(t, resp)
	})

	t.Run("no_match_method", func(t *testing.T) {
		resp := backend.InterceptRequest("example.com", 443, "/set-state", "POST")
		assert.Nil(t, resp)
	})

	t.Run("method_case_insensitive", func(t *testing.T) {
		resp := backend.InterceptRequest("example.com", 443, "/set-state", "get")
		require.NotNil(t, resp)
	})

	t.Run("query_ignored", func(t *testing.T) {
		// The handler strips query before calling InterceptRequest,
		// so passing path without query should match
		resp := backend.InterceptRequest("example.com", 443, "/set-state", "GET")
		require.NotNil(t, resp)
	})
}

func TestNativeProxyBackend_InterceptRequest_AllMethods(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	// Empty method matches all
	_, err = backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Origin:     "https://example.com",
		Path:       "/any-method",
		StatusCode: 204,
	})
	require.NoError(t, err)

	for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
		resp := backend.InterceptRequest("example.com", 443, "/any-method", method)
		require.NotNil(t, resp, "should match method %s", method)
		assert.Equal(t, 204, resp.StatusCode)
	}
}

func TestNativeProxyBackend_Responder_Persistence(t *testing.T) {
	t.Parallel()

	respStorage := store.NewMemStorage()

	backend1, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), respStorage, proxy.TimeoutConfig{})
	require.NoError(t, err)

	_, err = backend1.AddResponder(t.Context(), protocol.ResponderEntry{
		Origin:     "https://example.com",
		Path:       "/persisted",
		StatusCode: 201,
		Label:      "persisted",
	})
	require.NoError(t, err)
	_ = backend1.Close()

	// Create new backend with same storage
	backend2, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), respStorage, proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend2.Close() })

	list, err := backend2.ListResponders(t.Context())
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "/persisted", list[0].Path)
	assert.Equal(t, "persisted", list[0].Label)

	// Intercept should also work
	resp := backend2.InterceptRequest("example.com", 443, "/persisted", "GET")
	require.NotNil(t, resp)
	assert.Equal(t, 201, resp.StatusCode)
}

func TestNativeProxyBackend_Responder_LabelUniqueness(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	_, err = backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Origin: "https://example.com",
		Path:   "/a",
		Label:  "my-label",
	})
	require.NoError(t, err)

	// Duplicate label across responders
	_, err = backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Origin: "https://example.com",
		Path:   "/b",
		Label:  "my-label",
	})
	require.ErrorIs(t, err, ErrLabelExists)

	// Labels are independent from rules - same label allowed
	_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
		Label: "rule-label",
		Type:  RuleTypeRequestHeader,
		Match: "test",
	})
	require.NoError(t, err)

	_, err = backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Origin: "https://example.com",
		Path:   "/c",
		Label:  "rule-label",
	})
	require.NoError(t, err)
}

func TestParseOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		origin  string
		host    string
		port    int
		scheme  string
		wantErr bool
	}{
		{name: "https_default_port", origin: "https://example.com", host: "example.com", port: 443, scheme: "https"},
		{name: "http_default_port", origin: "http://example.com", host: "example.com", port: 80, scheme: "http"},
		{name: "https_custom_port", origin: "https://example.com:8443", host: "example.com", port: 8443, scheme: "https"},
		{name: "http_custom_port", origin: "http://example.com:8080", host: "example.com", port: 8080, scheme: "http"},
		{name: "uppercase_host", origin: "https://EXAMPLE.COM", host: "example.com", port: 443, scheme: "https"},
		{name: "with_path_ignored", origin: "https://example.com/path", host: "example.com", port: 443, scheme: "https"},
		{name: "invalid_scheme", origin: "ftp://example.com", wantErr: true},
		{name: "no_scheme", origin: "example.com", wantErr: true},
		{name: "empty", origin: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, scheme, err := parseOrigin(tt.origin)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.host, host)
			assert.Equal(t, tt.port, port)
			assert.Equal(t, tt.scheme, scheme)
		})
	}
}

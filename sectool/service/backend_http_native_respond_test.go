package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

func TestNativeProxyBackend_AddResponder(t *testing.T) {
	t.Parallel()

	backend := newTestNativeBackend(t)

	t.Run("stores_response_and_generates_id", func(t *testing.T) {
		entry, err := backend.AddResponder(t.Context(), protocol.ResponderEntry{
			Host:       "example.com",
			Path:       "/set-cookies",
			StatusCode: 200,
			Headers:    map[string]string{"Set-Cookie": "session=abc123"},
			Body:       "<html>ok</html>",
			Label:      "set-cookies",
		})
		require.NoError(t, err)
		assert.NotEmpty(t, entry.ResponderID)
		assert.Equal(t, "example.com", entry.Host)
		assert.Equal(t, "/set-cookies", entry.Path)
		assert.Equal(t, "set-cookies", entry.Label)
		assert.Equal(t, 200, entry.StatusCode)
		assert.Equal(t, "<html>ok</html>", entry.Body)
		assert.Equal(t, map[string]string{"Set-Cookie": "session=abc123"}, entry.Headers)
	})

	t.Run("strips_scheme_and_port", func(t *testing.T) {
		entry, err := backend.AddResponder(t.Context(), protocol.ResponderEntry{
			Host: "https://EXAMPLE.com:8443",
			Path: "/scheme-port",
		})
		require.NoError(t, err)
		assert.Equal(t, "example.com", entry.Host)
	})

	t.Run("default_status", func(t *testing.T) {
		entry, err := backend.AddResponder(t.Context(), protocol.ResponderEntry{
			Host: "example.com",
			Path: "/page",
		})
		require.NoError(t, err)
		assert.Equal(t, 200, entry.StatusCode)
	})
}

func TestNativeProxyBackend_DeleteResponder(t *testing.T) {
	t.Parallel()

	backend := newTestNativeBackend(t)

	entry, err := backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Host:  "example.com",
		Path:  "/page",
		Label: "my-page",
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
		Host:  "example.com",
		Path:  "/page2",
		Label: "my-page2",
	})
	require.NoError(t, err)

	err = backend.DeleteResponder(t.Context(), "my-page2")
	require.NoError(t, err)
}

func TestNativeProxyBackend_ListResponders(t *testing.T) {
	t.Parallel()

	backend := newTestNativeBackend(t)

	// Empty list
	list, err := backend.ListResponders(t.Context())
	require.NoError(t, err)
	assert.Empty(t, list)

	// Add two
	_, err = backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Host: "example.com",
		Path: "/a",
	})
	require.NoError(t, err)

	_, err = backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Host: "other.com",
		Path: "/b",
	})
	require.NoError(t, err)

	list, err = backend.ListResponders(t.Context())
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestNativeProxyBackend_InterceptRequest(t *testing.T) {
	t.Parallel()

	backend := newTestNativeBackend(t)

	_, err := backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Host:       "example.com",
		Path:       "/set-state",
		Method:     "GET",
		StatusCode: 200,
		Headers:    map[string]string{"Content-Type": "text/html"},
		Body:       "<html>state set</html>",
	})
	require.NoError(t, err)

	t.Run("match", func(t *testing.T) {
		resp := backend.InterceptRequest("example.com", "/set-state", "GET")
		require.NotNil(t, resp)
		assert.Equal(t, 200, resp.StatusCode)
		assert.Equal(t, []byte("<html>state set</html>"), resp.Body)
	})

	t.Run("no_match_host", func(t *testing.T) {
		resp := backend.InterceptRequest("other.com", "/set-state", "GET")
		assert.Nil(t, resp)
	})

	t.Run("no_match_path", func(t *testing.T) {
		resp := backend.InterceptRequest("example.com", "/other", "GET")
		assert.Nil(t, resp)
	})

	t.Run("no_match_method", func(t *testing.T) {
		resp := backend.InterceptRequest("example.com", "/set-state", "POST")
		assert.Nil(t, resp)
	})

	t.Run("method_case_insensitive", func(t *testing.T) {
		resp := backend.InterceptRequest("example.com", "/set-state", "get")
		require.NotNil(t, resp)
	})

	t.Run("empty_method_matches_all", func(t *testing.T) {
		_, err := backend.AddResponder(t.Context(), protocol.ResponderEntry{
			Host:       "example.com",
			Path:       "/any-method",
			StatusCode: 204,
		})
		require.NoError(t, err)

		for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
			resp := backend.InterceptRequest("example.com", "/any-method", method)
			require.NotNilf(t, resp, "method %s", method)
			assert.Equal(t, 204, resp.StatusCode)
		}
	})
}

func TestNativeProxyBackend_Responder_Persistence(t *testing.T) {
	t.Parallel()

	respStorage := store.NewMemStorage()
	provider := sharedMemProvider("resp", respStorage)

	backend1, err := NewNativeProxyBackend(t.Context(), 0, t.TempDir(), 10*1024*1024, provider, proxy.TimeoutConfig{}, false)
	require.NoError(t, err)

	_, err = backend1.AddResponder(t.Context(), protocol.ResponderEntry{
		Host:       "example.com",
		Path:       "/persisted",
		StatusCode: 201,
		Label:      "persisted",
	})
	require.NoError(t, err)
	_ = backend1.Close(t.Context())

	// New backend over the same responder storage should load persisted responders.
	backend2, err := NewNativeProxyBackend(t.Context(), 0, t.TempDir(), 10*1024*1024, provider, proxy.TimeoutConfig{}, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend2.Close(context.Background()) })

	list, err := backend2.ListResponders(t.Context())
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "/persisted", list[0].Path)
	assert.Equal(t, "persisted", list[0].Label)

	// Intercept should also work
	resp := backend2.InterceptRequest("example.com", "/persisted", "GET")
	require.NotNil(t, resp)
	assert.Equal(t, 201, resp.StatusCode)
}

func TestNativeProxyBackend_Responder_LabelUniqueness(t *testing.T) {
	t.Parallel()

	backend := newTestNativeBackend(t)

	_, err := backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Host:  "example.com",
		Path:  "/a",
		Label: "my-label",
	})
	require.NoError(t, err)

	// Duplicate label across responders
	_, err = backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Host:  "example.com",
		Path:  "/b",
		Label: "my-label",
	})
	require.ErrorIs(t, err, ErrLabelExists)

	// Labels are independent from rules - same label allowed
	_, err = backend.AddRule(t.Context(), protocol.RuleEntry{
		Label: "rule-label",
		Type:  wire.RuleTypeRequestHeader,
		Find:  "test",
	})
	require.NoError(t, err)

	_, err = backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Host:  "example.com",
		Path:  "/c",
		Label: "rule-label",
	})
	require.NoError(t, err)
}

func TestNativeProxyBackend_Responder_PortAgnostic(t *testing.T) {
	t.Parallel()

	backend := newTestNativeBackend(t)

	// registered via a scheme+port URL; scheme and port are discarded
	_, err := backend.AddResponder(t.Context(), protocol.ResponderEntry{
		Host: "https://example.com:8443",
		Path: "/state",
	})
	require.NoError(t, err)

	// matches the bare host regardless of the request's scheme or port
	require.NotNil(t, backend.InterceptRequest("example.com", "/state", "GET"))
}

func TestParseResponderHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "bare_host", input: "example.com", want: "example.com"},
		{name: "uppercase_lowercased", input: "EXAMPLE.COM", want: "example.com"},
		{name: "host_port_stripped", input: "example.com:8080", want: "example.com"},
		{name: "https_url", input: "https://example.com", want: "example.com"},
		{name: "url_scheme_and_port_stripped", input: "http://example.com:8080", want: "example.com"},
		{name: "surrounding_space", input: "  example.com  ", want: "example.com"},
		{name: "path_rejected", input: "example.com/path", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, err := parseResponderHost(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, host)
		})
	}
}

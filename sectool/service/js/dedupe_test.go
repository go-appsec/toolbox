package js

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

func TestDedupeEndpoints(t *testing.T) {
	t.Parallel()

	t.Run("literal_yields_to_call_site", func(t *testing.T) {
		in := []protocol.ExtractedEndpoint{
			{URL: "/api/x", Library: libLiteral},
			{URL: "/api/x", Library: libFetch},
		}
		out := dedupeEndpoints(in)
		assert.Len(t, out, 1)
		assert.Equal(t, libFetch, out[0].Library)
	})

	t.Run("call_site_then_literal", func(t *testing.T) {
		in := []protocol.ExtractedEndpoint{
			{URL: "/api/x", Library: libFetch},
			{URL: "/api/x", Library: libLiteral},
		}
		out := dedupeEndpoints(in)
		assert.Len(t, out, 1)
		assert.Equal(t, libFetch, out[0].Library)
	})

	t.Run("method_distinguishes", func(t *testing.T) {
		in := []protocol.ExtractedEndpoint{
			{URL: "/api/x", Method: "GET", Library: libAxios},
			{URL: "/api/x", Method: "POST", Library: libAxios},
		}
		out := dedupeEndpoints(in)
		assert.Len(t, out, 2)
	})

	t.Run("two_call_sites_first_wins", func(t *testing.T) {
		in := []protocol.ExtractedEndpoint{
			{URL: "/api/x", Library: libFetch},
			{URL: "/api/x", Library: libAxios},
		}
		out := dedupeEndpoints(in)
		assert.Len(t, out, 1)
		// Neither side is "literal", so the first occurrence is retained.
		assert.Equal(t, libFetch, out[0].Library)
	})

	t.Run("sorted_by_url_then_method", func(t *testing.T) {
		in := []protocol.ExtractedEndpoint{
			{URL: "/b", Method: "POST"},
			{URL: "/a", Method: "POST"},
			{URL: "/a", Method: "GET"},
		}
		out := dedupeEndpoints(in)
		assert.Equal(t, []protocol.ExtractedEndpoint{
			{URL: "/a", Method: "GET"},
			{URL: "/a", Method: "POST"},
			{URL: "/b", Method: "POST"},
		}, out)
	})

	t.Run("empty_input", func(t *testing.T) {
		out := dedupeEndpoints(nil)
		assert.Empty(t, out)
	})
}

func TestDedupeRoutes(t *testing.T) {
	t.Parallel()

	t.Run("same_path_and_framework_collapsed", func(t *testing.T) {
		in := []protocol.ExtractedRoute{
			{Path: "/x", Framework: frameworkReactRouter},
			{Path: "/x", Framework: frameworkReactRouter},
		}
		out := dedupeRoutes(in)
		assert.Len(t, out, 1)
	})

	t.Run("same_path_different_framework_kept", func(t *testing.T) {
		in := []protocol.ExtractedRoute{
			{Path: "/x", Framework: frameworkReactRouter},
			{Path: "/x", Framework: frameworkVueRouter},
		}
		out := dedupeRoutes(in)
		assert.Len(t, out, 2)
	})

	t.Run("sorted_by_path", func(t *testing.T) {
		in := []protocol.ExtractedRoute{
			{Path: "/c"},
			{Path: "/a"},
			{Path: "/b"},
		}
		out := dedupeRoutes(in)
		assert.Equal(t, []protocol.ExtractedRoute{
			{Path: "/a"},
			{Path: "/b"},
			{Path: "/c"},
		}, out)
	})

	t.Run("empty_input", func(t *testing.T) {
		out := dedupeRoutes(nil)
		assert.Empty(t, out)
	})
}

func TestDedupeStrings(t *testing.T) {
	t.Parallel()

	t.Run("collapses_duplicates_and_sorts", func(t *testing.T) {
		out := dedupeStrings([]string{"b.js", "a.js", "b.js"})
		assert.Equal(t, []string{"a.js", "b.js"}, out)
	})

	t.Run("already_unique_returns_input", func(t *testing.T) {
		in := []string{"a", "b"}
		out := dedupeStrings(in)
		// Fast path returns the input slice unchanged.
		assert.Equal(t, in, out)
	})

	t.Run("empty_input", func(t *testing.T) {
		assert.Empty(t, dedupeStrings(nil))
	})
}

func TestDedupeSecrets(t *testing.T) {
	t.Parallel()

	t.Run("collapses_same_kind_and_value", func(t *testing.T) {
		in := []protocol.ExtractedSecret{
			{Kind: "aws_access_key", Value: "AKIAIOSFODNN7EXAMPLE"},
			{Kind: "aws_access_key", Value: "AKIAIOSFODNN7EXAMPLE"},
		}
		out := dedupeSecrets(in)
		assert.Len(t, out, 1)
	})

	t.Run("same_kind_different_value_kept", func(t *testing.T) {
		in := []protocol.ExtractedSecret{
			{Kind: "aws_access_key", Value: "AKIAIOSFODNN7AAAAAAA"},
			{Kind: "aws_access_key", Value: "AKIAIOSFODNN7BBBBBBB"},
		}
		out := dedupeSecrets(in)
		assert.Len(t, out, 2)
	})

	t.Run("sorted_by_kind_then_value", func(t *testing.T) {
		in := []protocol.ExtractedSecret{
			{Kind: "github_pat", Value: "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
			{Kind: "aws_access_key", Value: "AKIAIOSFODNN7EXAMPLE"},
		}
		out := dedupeSecrets(in)
		assert.Equal(t, "aws_access_key", out[0].Kind)
		assert.Equal(t, "github_pat", out[1].Kind)
	})

	t.Run("empty_input", func(t *testing.T) {
		assert.Empty(t, dedupeSecrets(nil))
	})
}

func TestClassifyURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, in, host, path string
	}{
		{"absolute_path", "/api/users", "", "/api/users"},
		{"absolute_path_with_query", "/api/users?id=1", "", "/api/users?id=1"},
		{"https_with_path", "https://example.com/api/x", "example.com", "/api/x"},
		{"https_with_query_and_frag", "https://example.com/api/x?q=1#frag", "example.com", "/api/x?q=1"},
		{"https_no_path", "https://example.com", "example.com", "/"},
		{"protocol_relative", "//cdn.example.com/bundle.js", "cdn.example.com", "/bundle.js"},
		{"http_with_port", "http://example.com:8080/x", "example.com:8080", "/x"},
		{"non_http_scheme_dropped", "wss://example.com/ws", "", ""},
		{"bare_relative_dropped", "relative/path", "", ""},
		{"dot_relative_dropped", "./local", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotHost, gotPath := ClassifyURL(tc.in)
			assert.Equal(t, tc.host, gotHost)
			assert.Equal(t, tc.path, gotPath)
		})
	}
}

func TestStripQuery(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, in, want string
	}{
		{"no_query", "/api/users", "/api/users"},
		{"single_param", "/api/users?id=1", "/api/users"},
		{"multi_param", "/api/users?id=1&q=2", "/api/users"},
		{"empty", "", ""},
		{"only_query", "?only=query", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, StripQuery(tc.in))
		})
	}
}

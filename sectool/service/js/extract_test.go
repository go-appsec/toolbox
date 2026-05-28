package js

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLooksLikeURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"https_with_query", "https://example.com/path?q=1", true},
		{"http_root", "http://example.com/", true},
		{"wss_path", "wss://ws.example/socket", true},
		{"protocol_relative", "//cdn.example.com/x.js", true},
		{"absolute_path", "/api/users", true},
		{"absolute_path_query", "/api/users?id=1", true},
		{"dot_relative", "./local", true},
		{"dot_dot_relative", "../up/over", true},
		{"bare_relative", "api/users", true},
		{"asset_relative", "assets/main.js", true},
		{"template_interpolation", "/api/users/${id}", true},
		{"plain_text_rejected", "hello world", false},
		{"i18n_key_rejected", "translation.key", false},
		{"bare_ident_rejected", "foo", false},
		{"angle_brackets_rejected", "https://example.com/<script>", false},
		{"empty_rejected", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, looksLikeURL(tc.in))
		})
	}
}

func TestLooksLikeWebSocketURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"ws_scheme", "ws://x/y", true},
		{"wss_scheme", "wss://x/y", true},
		{"ws_template_host", "ws://${host}/sock", true},
		{"wss_template_path", "wss://example.com/${path}", true},
		{"bare_text_rejected", "notaurl", false},
		{"absolute_path_rejected", "/socket", false},
		{"https_rejected", "https://example.com/", false},
		{"protocol_relative_rejected", "//cdn/foo", false},
		{"empty_rejected", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, looksLikeWebSocketURL(tc.in))
		})
	}
}

func TestExtractFromSource(t *testing.T) {
	t.Parallel()

	t.Run("captures_source_map_url", func(t *testing.T) {
		src := []byte(`var x=1;
//# sourceMappingURL=app.js.map`)
		pr := parseSource(src)
		got, _ := extractFromSource(src, pr.ast)
		assert.Equal(t, []string{"app.js.map"}, got.SourceMaps)
	})

	t.Run("returns_token_literals_for_secrets", func(t *testing.T) {
		src := []byte(`var k = "secret-value-x";`)
		_, literals := extractFromSource(src, nil)
		assert.Contains(t, literals, "secret-value-x")
	})

	t.Run("ast_nil_still_scans_literals", func(t *testing.T) {
		// With a nil AST the AST visitor is skipped, but URL-shaped literals
		// in the token stream still flow into Endpoints as libLiteral entries.
		src := []byte(`var x = '/api/from-tokens';`)
		got, _ := extractFromSource(src, nil)
		assert.Len(t, got.Endpoints, 1)
		assert.Equal(t, "/api/from-tokens", got.Endpoints[0].URL)
		assert.Equal(t, libLiteral, got.Endpoints[0].Library)
	})

	t.Run("token_literal_does_not_duplicate_sink_url", func(t *testing.T) {
		src := []byte(`fetch('/api/x'); var also = '/api/x';`)
		pr := parseSource(src)
		got, _ := extractFromSource(src, pr.ast)
		// Only the fetch call site should appear; the bare literal must not
		// add a second /api/x entry.
		var matches int
		for _, e := range got.Endpoints {
			if e.URL == "/api/x" {
				matches++
			}
		}
		assert.Equal(t, 1, matches)
	})
}

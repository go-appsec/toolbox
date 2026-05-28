package js

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSource(t *testing.T) {
	t.Parallel()

	t.Run("valid_returns_ast_no_err", func(t *testing.T) {
		pr := parseSource([]byte(`var x = 1;`))
		require.NoError(t, pr.err)
		assert.NotNil(t, pr.ast)
	})

	t.Run("invalid_returns_err", func(t *testing.T) {
		pr := parseSource([]byte(`function (`))
		assert.Error(t, pr.err)
	})

	t.Run("empty_input", func(t *testing.T) {
		pr := parseSource(nil)
		require.NoError(t, pr.err)
		assert.NotNil(t, pr.ast)
	})
}

func TestScanStringLiterals(t *testing.T) {
	t.Parallel()

	t.Run("double_and_single_quotes", func(t *testing.T) {
		got := scanStringLiterals([]byte(`var a = "hello"; var b = 'world';`))
		assert.Contains(t, got, "hello")
		assert.Contains(t, got, "world")
	})

	t.Run("decodes_escapes", func(t *testing.T) {
		got := scanStringLiterals([]byte(`var u = "\/api\/users";`))
		assert.Contains(t, got, "/api/users")
	})

	t.Run("plain_template", func(t *testing.T) {
		got := scanStringLiterals([]byte("var s = `plain`;"))
		assert.Contains(t, got, "plain")
	})

	t.Run("interpolated_template_parts_skipped", func(t *testing.T) {
		// Only StringToken / TemplateToken (whole-template) are captured; the
		// Start/Middle/End fragments of an interpolated template are emitted as
		// different token types and intentionally ignored — the AST visitor
		// reconstructs them with ${...} placeholders.
		got := scanStringLiterals([]byte("var s = `pre${x}post`;"))
		assert.NotContains(t, got, "pre")
		assert.NotContains(t, got, "post")
	})

	t.Run("ignores_numeric_and_identifiers", func(t *testing.T) {
		got := scanStringLiterals([]byte(`var n = 123; var foo = bar;`))
		assert.Empty(t, got)
	})

	t.Run("stops_at_lex_error", func(t *testing.T) {
		// A bare quote leaves the lexer in an error state; the function should
		// return whatever was scanned successfully before that point.
		got := scanStringLiterals([]byte(`var a = "ok"; var b = "unterminated`))
		assert.Contains(t, got, "ok")
	})

	t.Run("empty_input", func(t *testing.T) {
		assert.Empty(t, scanStringLiterals(nil))
	})
}

func TestUnquote(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"double_quoted", `"hello"`, "hello", true},
		{"single_quoted", `'hello'`, "hello", true},
		{"backtick_plain", "`hello`", "hello", true},
		{"escaped_path", `"\/api\/users"`, "/api/users", true},
		{"unicode_path", `"/api"`, "/api", true},
		{"too_short", `"`, "", false},
		{"mismatched", `"hello'`, "", false},
		{"template_start", "`prefix${", "prefix", true},
		{"template_middle", "}mid${", "mid", true},
		{"template_end", "}suffix`", "suffix", true},
		{"empty_double_quoted", `""`, "", false},
		{"unrecognized_delim", `xhellox`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := unquote([]byte(tc.in))
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestDecodeJSEscapes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"no_escapes_fast_path", "/api/users", "/api/users"},
		{"slash_escape", `\/api\/users`, "/api/users"},
		{"quote_escape", `it\'s \"x\"`, `it's "x"`},
		{"newline_tab", `a\nb\tc`, "a\nb\tc"},
		{"hex_escape", `\x2fapi`, "/api"},
		{"unicode_escape", "\\u002fapi", "/api"},
		{"unicode_brace_escape", `\u{1F600}`, "\U0001F600"},
		{"unknown_escape_dropped", `\zfoo`, "zfoo"},
		{"trailing_backslash", `foo\`, `foo\`},
		{"backslash_self", `a\\b`, `a\b`},
		{"malformed_hex_kept", `\xZZ`, `\xZZ`},
		{"malformed_unicode_kept", `\uZZZZ`, `\uZZZZ`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, decodeJSEscapes(tc.in))
		})
	}
}

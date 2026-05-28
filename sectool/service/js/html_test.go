package js

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseHTMLScripts(t *testing.T) {
	t.Parallel()

	t.Run("inline_and_external_mixed", func(t *testing.T) {
		src := []byte(`<html><head>
<script src="https://cdn.example/app.js"></script>
<script>fetch('/a');</script>
<script src="/b.js"></script>
<script>fetch('/c');</script>
</head></html>`)
		got := ParseHTMLScripts(src)
		assert.Equal(t, []string{"https://cdn.example/app.js", "/b.js"}, got.External)
		assert.Len(t, got.Inline, 2)
		assert.Contains(t, string(got.Inline[0]), "fetch('/a')")
		assert.Contains(t, string(got.Inline[1]), "fetch('/c')")
	})

	t.Run("ld_json_inline_skipped", func(t *testing.T) {
		src := []byte(`<html><head>
<script type="application/ld+json">{"ignored":"yes"}</script>
<script>fetch('/keep');</script>
</head></html>`)
		got := ParseHTMLScripts(src)
		assert.Empty(t, got.External)
		assert.Len(t, got.Inline, 1)
		assert.Contains(t, string(got.Inline[0]), "/keep")
	})

	t.Run("type_module_kept", func(t *testing.T) {
		src := []byte(`<script type="module">fetch('/m');</script>`)
		got := ParseHTMLScripts(src)
		assert.Len(t, got.Inline, 1)
		assert.Contains(t, string(got.Inline[0]), "/m")
	})

	t.Run("type_javascript_kept", func(t *testing.T) {
		src := []byte(`<script type="text/javascript">fetch('/j');</script>` +
			`<script type="application/javascript">fetch('/k');</script>`)
		got := ParseHTMLScripts(src)
		assert.Len(t, got.Inline, 2)
	})

	t.Run("src_attr_suppresses_inline", func(t *testing.T) {
		// Browsers ignore inline content when src= is present.
		src := []byte(`<script src="/x.js">fetch('/ignored');</script>`)
		got := ParseHTMLScripts(src)
		assert.Equal(t, []string{"/x.js"}, got.External)
		assert.Empty(t, got.Inline)
	})

	t.Run("whitespace_only_inline_skipped", func(t *testing.T) {
		src := []byte(`<script>
		</script>`)
		got := ParseHTMLScripts(src)
		assert.Empty(t, got.Inline)
	})

	t.Run("no_scripts", func(t *testing.T) {
		got := ParseHTMLScripts([]byte(`<html><body><p>hi</p></body></html>`))
		assert.Empty(t, got.Inline)
		assert.Empty(t, got.External)
	})

	t.Run("malformed_html_tolerated", func(t *testing.T) {
		// Unclosed tag; tokenizer should still surface the inline content.
		src := []byte(`<html><head><script>fetch('/mal')`)
		got := ParseHTMLScripts(src)
		assert.Len(t, got.Inline, 1)
		assert.Contains(t, string(got.Inline[0]), "/mal")
	})

	t.Run("preserves_document_order", func(t *testing.T) {
		src := []byte(`<script>1</script>x<script>2</script>x<script>3</script>`)
		got := ParseHTMLScripts(src)
		assert.Len(t, got.Inline, 3)
		assert.Equal(t, "1", string(got.Inline[0]))
		assert.Equal(t, "2", string(got.Inline[1]))
		assert.Equal(t, "3", string(got.Inline[2]))
	})
}

package js

import (
	"bytes"
	"slices"
	"strings"

	"golang.org/x/net/html"
)

// HTMLScripts holds the inline blocks and external src URLs extracted from HTML.
type HTMLScripts struct {
	Inline   [][]byte
	External []string
}

// ParseHTMLScripts walks the HTML document and returns inline <script> bodies
// and external <script src=...> URLs. Inline blocks are returned in document
// order so the caller can parse them independently.
func ParseHTMLScripts(src []byte) HTMLScripts {
	var out HTMLScripts
	z := html.NewTokenizer(bytes.NewReader(src))

	var inScript, skipInline bool
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return out
		case html.StartTagToken:
			name, hasAttr := z.TagName()
			if string(name) != "script" {
				continue
			}

			inScript = true
			skipInline = false
			var srcURL string
			for hasAttr {
				var k, val []byte
				k, val, hasAttr = z.TagAttr()
				switch string(k) {
				case "src":
					srcURL = string(val)
				case "type":
					// Skip non-JS script blocks (e.g., application/ld+json).
					t := strings.ToLower(string(val))
					if t != "" && t != "text/javascript" && t != "application/javascript" && t != "module" {
						skipInline = true
					}
				}
			}
			if srcURL != "" {
				out.External = append(out.External, srcURL)
				skipInline = true
			}
		case html.TextToken:
			if !inScript || skipInline {
				continue
			}
			text := z.Text()
			if len(bytes.TrimSpace(text)) > 0 {
				out.Inline = append(out.Inline, slices.Clone(text))
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			if string(name) == "script" {
				inScript = false
				skipInline = false
			}
		}
	}
}

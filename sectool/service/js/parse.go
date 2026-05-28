// Package js extracts API surface (endpoints, routes, WebSocket URLs, URL literals)
// from JavaScript and HTML responses using the tdewolff/parse JS parser.
package js

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

// parseResult holds the parsed AST and any parse error. AST may be nil on hard failure.
type parseResult struct {
	ast *js.AST
	err error
}

// parseSource parses a single JS source block. On error the AST may still be nil.
func parseSource(src []byte) parseResult {
	input := parse.NewInputBytes(src)
	ast, err := js.Parse(input, js.Options{})
	return parseResult{ast: ast, err: err}
}

// scanStringLiterals returns every string and template literal value in src.
// Used as a tolerant fallback when AST parsing fails.
func scanStringLiterals(src []byte) []string {
	l := js.NewLexer(parse.NewInputBytes(src))
	var out []string
	for {
		tt, data := l.Next()
		switch tt {
		case js.ErrorToken:
			return out
		case js.StringToken, js.TemplateToken:
			// TemplateToken covers every template-literal fragment; unquote
			// handles each delimiter shape (`...`, `...${, }...${, }...`).
			if s, ok := unquote(data); ok {
				out = append(out, s)
			}
		}
	}
}

// unquote strips delimiters from a string or template-literal token's raw data.
// Returns false if no recognizable delimiters are present.
func unquote(data []byte) (string, bool) {
	if len(data) < 2 {
		return "", false
	}
	var start, end int
	switch data[0] {
	case '\'', '"':
		if data[len(data)-1] != data[0] {
			return "", false
		}
		start, end = 1, len(data)-1
	case '`':
		start = 1
		if len(data) >= 3 && data[len(data)-2] == '$' && data[len(data)-1] == '{' {
			end = len(data) - 2
		} else if data[len(data)-1] == '`' {
			end = len(data) - 1
		} else {
			return "", false
		}
	case '}':
		start = 1
		if len(data) >= 3 && data[len(data)-2] == '$' && data[len(data)-1] == '{' {
			end = len(data) - 2
		} else if data[len(data)-1] == '`' {
			end = len(data) - 1
		} else {
			return "", false
		}
	default:
		return "", false
	}
	if end <= start {
		return "", false
	}
	return decodeJSEscapes(string(data[start:end])), true
}

// decodeJSEscapes resolves JS string-escape sequences (\n, \t, \xHH, \uHHHH, \u{H..}, etc.).
// Unknown single-char escapes drop the backslash. Malformed escapes are left as-is.
func decodeJSEscapes(s string) string {
	if strings.IndexByte(s, '\\') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			i++
			continue
		}
		next := s[i+1]
		switch next {
		case '/', '\\', '"', '\'', '`':
			b.WriteByte(next)
			i += 2
		case 'n':
			b.WriteByte('\n')
			i += 2
		case 'r':
			b.WriteByte('\r')
			i += 2
		case 't':
			b.WriteByte('\t')
			i += 2
		case 'b':
			b.WriteByte('\b')
			i += 2
		case 'f':
			b.WriteByte('\f')
			i += 2
		case 'v':
			b.WriteByte('\v')
			i += 2
		case '0':
			b.WriteByte(0)
			i += 2
		case 'x':
			if i+4 <= len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
					b.WriteByte(byte(v))
					i += 4
					continue
				}
			}
			b.WriteByte(c)
			i++
		case 'u':
			if i+2 < len(s) && s[i+2] == '{' {
				if end := strings.IndexByte(s[i+3:], '}'); end > 0 && end <= 6 {
					if v, err := strconv.ParseUint(s[i+3:i+3+end], 16, 32); err == nil && v <= utf8.MaxRune {
						b.WriteRune(rune(v))
						i += 4 + end
						continue
					}
				}
			} else if i+6 <= len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+6], 16, 16); err == nil {
					b.WriteRune(rune(v))
					i += 6
					continue
				}
			}
			b.WriteByte(c)
			i++
		default:
			b.WriteByte(next)
			i += 2
		}
	}
	return b.String()
}

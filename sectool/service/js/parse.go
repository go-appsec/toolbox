package js

import (
	"strconv"
	"strings"
	"unicode/utf16"
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

// maxScanResumes bounds how many times scanStringLiterals restarts after a lexer
// error, guarding against O(n²) work on pathological (e.g. binary) input.
const maxScanResumes = 1024

// scanStringLiterals returns the decoded value of every string and template literal
// in src. Used both for secret detection and as the source for URL extraction; only
// lexer-identified strings are returned, so regex literals, division, and comments are
// excluded by construction. Template interpolation fragments are included so
// `${x}/api/y` contributes its literal pieces. The lexer halts at the first malformed
// or truncated token, so on error the scan skips the offending byte and resumes.
func scanStringLiterals(src []byte) []string {
	var out []string
	for resumes := 0; len(src) > 0; resumes++ {
		l := js.NewLexer(parse.NewInputBytes(src))
		var consumed int
		var tmpl []string // stack of in-progress interpolated-template buffers
		for {
			tt, data := l.Next()
			if tt == js.ErrorToken {
				break
			}
			switch tt {
			case js.StringToken, js.TemplateToken:
				// unquote handles each delimiter shape (`...`, `...${, }...${, }...`)
				if s, ok := unquote(data); ok {
					out = append(out, s)
				}
			case js.TemplateStartToken:
				s, _ := unquote(data)
				tmpl = append(tmpl, s+"${...}")
			case js.TemplateMiddleToken:
				if n := len(tmpl); n > 0 {
					s, _ := unquote(data)
					tmpl[n-1] += s + "${...}"
				}
			case js.TemplateEndToken:
				// Reconstruct the full interpolated template with ${...} markers,
				// matching the AST's staticString output so the two dedupe.
				if n := len(tmpl); n > 0 {
					s, _ := unquote(data)
					out = append(out, tmpl[n-1]+s)
					tmpl = tmpl[:n-1]
				}
			}
			consumed += len(data)
		}
		if consumed >= len(src) || resumes >= maxScanResumes {
			break // clean EOF, or give up after too many malformed tokens
		}
		src = src[consumed+1:] // skip the byte that stalled the lexer, then resume
	}
	return out
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
					r := rune(v)
					// astral chars are JS-encoded as a surrogate pair (😀)
					if utf16.IsSurrogate(r) && i+12 <= len(s) && s[i+6] == '\\' && s[i+7] == 'u' {
						if v2, err := strconv.ParseUint(s[i+8:i+12], 16, 16); err == nil {
							if combined := utf16.DecodeRune(r, rune(v2)); combined != utf8.RuneError {
								b.WriteRune(combined)
								i += 12
								continue
							}
						}
					}
					b.WriteRune(r)
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

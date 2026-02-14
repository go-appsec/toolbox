package service

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const maxMatchesPerSection = 10

// compileSearchPattern compiles an RE2 regex; on failure auto-escapes to literal.
// When caseInsensitive is true, prepends (?i) to make the match case-insensitive.
// Returns compiled regexp and note string (empty if pattern was valid regex).
func compileSearchPattern(pattern string, caseInsensitive bool) (*regexp.Regexp, string) {
	p := pattern
	if caseInsensitive && !strings.HasPrefix(p, "(?i)") {
		p = "(?i)" + p
	}
	re, err := regexp.Compile(p)
	if err != nil {
		escaped := regexp.QuoteMeta(pattern)
		if caseInsensitive {
			escaped = "(?i)" + escaped
		}
		return regexp.MustCompile(escaped), fmt.Sprintf("invalid regex %q, treated as literal", pattern)
	}
	return re, ""
}

// extractMatchContext returns grep-like output with ~80 chars context around each match.
// Returns "" if no matches or binary data. Iterates matches lazily to avoid
// allocating index slices for patterns that match many times in large bodies.
func extractMatchContext(re *regexp.Regexp, data []byte, maxMatches int) string {
	if !utf8.Valid(data) {
		return ""
	}

	limit := maxMatches
	if limit <= 0 {
		limit = maxMatchesPerSection
	}

	var b strings.Builder
	var shown, pos int
	// Iterate matches incrementally; stop after limit without scanning the rest
	for pos < len(data) && shown < limit {
		loc := re.FindIndex(data[pos:])
		if loc == nil {
			break
		}
		// Translate to absolute offsets
		loc[0] += pos
		loc[1] += pos

		if shown > 0 {
			b.WriteString("\n----\n")
		}

		start := loc[0] - 80
		if start < 0 {
			start = 0
		}
		end := loc[1] + 80
		if end > len(data) {
			end = len(data)
		}
		// Snap to UTF-8 rune boundaries to avoid splitting multi-byte characters
		for start > 0 && !utf8.RuneStart(data[start]) {
			start--
		}
		for end < len(data) && !utf8.RuneStart(data[end]) {
			end++
		}

		if start > 0 {
			b.WriteString("...")
		}
		b.Write(data[start:end])
		if end < len(data) {
			b.WriteString("...")
		}
		shown++

		// Advance past this match to find the next
		pos = loc[1]
		if loc[0] == loc[1] {
			pos++ // avoid infinite loop on zero-width match
		}
	}

	if shown == 0 {
		return ""
	}

	// Peek one more match to indicate truncation without counting all remaining
	if shown == limit && pos < len(data) && re.FindIndex(data[pos:]) != nil {
		b.WriteString("\n[truncated: more matches]")
	}

	return b.String()
}

// matchesFlowSearch returns true if request/response data matches the given
// header and/or body search regexes. Decompresses bodies before matching.
// Returns true when both regexes are nil (no search).
func matchesFlowSearch(request, response []byte, headerRe, bodyRe *regexp.Regexp) bool {
	if headerRe == nil && bodyRe == nil {
		return true
	}
	if headerRe != nil {
		if reqHeaders, _ := splitHeadersBody(request); headerRe.Match(reqHeaders) {
			return true
		} else if respHeaders, _ := splitHeadersBody(response); headerRe.Match(respHeaders) {
			return true
		}
	}
	if bodyRe != nil {
		reqHeaders, reqBody := splitHeadersBody(request)
		displayReqBody, _ := decompressForDisplay(reqBody, string(reqHeaders))
		if utf8.Valid(displayReqBody) && bodyRe.Match(displayReqBody) {
			return true
		}
		respHeaders, respBody := splitHeadersBody(response)
		displayRespBody, _ := decompressForDisplay(respBody, string(respHeaders))
		if utf8.Valid(displayRespBody) && bodyRe.Match(displayRespBody) {
			return true
		}
	}
	return false
}

// parseScopeSet parses a comma-separated scope string into a set.
// Valid values: request_headers, request_body, response_headers, response_body, all.
// Empty string or "all" returns all four scopes.
func parseScopeSet(scope string) (map[string]bool, error) {
	all := map[string]bool{
		"request_headers":  true,
		"request_body":     true,
		"response_headers": true,
		"response_body":    true,
	}
	if scope == "" || scope == "all" {
		return all, nil
	}

	result := make(map[string]bool)
	for _, s := range strings.Split(scope, ",") {
		s = strings.TrimSpace(s)
		if s == "all" {
			return all, nil
		} else if !all[s] {
			return nil, fmt.Errorf("invalid scope %q: valid values are request_headers, request_body, response_headers, response_body, all", s)
		}
		result[s] = true
	}

	if len(result) == 0 {
		return all, nil
	}
	return result, nil
}

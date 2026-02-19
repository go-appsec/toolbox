package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// validateRequest checks a parsed request for protocol issues that the parser
// tolerates but that may indicate malformed input, injection, or smuggling.
// Used when force=false to warn about conditions that force=true bypasses.
// Returns nil if request passes all checks, or an error listing all issues.
func validateRequest(req *RawHTTP1Request) error {
	if req == nil {
		return errors.New("nil request")
	}

	var issues []string

	// Method must be non-empty and contain only valid token characters
	if req.Method == "" {
		issues = append(issues, "empty method")
	} else if !isValidToken(req.Method) {
		issues = append(issues, fmt.Sprintf("invalid method characters: %q", req.Method))
	}

	// Path must be non-empty; CR/LF in path is a request splitting risk
	if req.Path == "" {
		issues = append(issues, "empty path")
	} else if strings.ContainsAny(req.Path, "\r\n") {
		issues = append(issues, "CR/LF in request path")
	}

	// Version should be HTTP/1.0 or HTTP/1.1
	if req.Version != "HTTP/1.0" && req.Version != "HTTP/1.1" {
		issues = append(issues, fmt.Sprintf("invalid HTTP version: %q (expected HTTP/1.0 or HTTP/1.1)", req.Version))
	}

	// Bare LF line endings (parser tolerates but HTTP requires CRLF)
	if req.Wire != nil && req.Wire.UsedBareLF {
		issues = append(issues, "bare LF line endings (HTTP requires CRLF)")
	}

	// Per-header checks
	for _, h := range req.Headers {
		// Header name: NUL (most specific), then token validation
		if h.Name == "" {
			issues = append(issues, "empty header name")
		} else if strings.ContainsRune(h.Name, '\x00') {
			issues = append(issues, fmt.Sprintf("NUL byte in header name: %q", h.Name))
		} else if !isValidToken(h.Name) {
			issues = append(issues, fmt.Sprintf("invalid header name: %q", h.Name))
		}

		// Header value: NUL bytes, then CR/LF injection
		if strings.ContainsRune(h.Value, '\x00') {
			issues = append(issues, fmt.Sprintf("NUL byte in header value for %q", h.Name))
		} else if strings.ContainsAny(h.Value, "\r\n") {
			issues = append(issues, fmt.Sprintf("CR/LF in header value for %q", h.Name))
		}

		// Wire-level checks using RawLine (only available for parsed-from-wire headers)
		if len(h.RawLine) > 0 {
			// Obs-fold (continuation lines) deprecated per RFC 7230 §3.2.4
			if bytes.ContainsAny(h.RawLine, "\r\n") {
				issues = append(issues, fmt.Sprintf("obs-fold (line continuation) in header %q", h.Name))
			}
			// Header line without colon separator (parser treats entire line as name)
			if !bytes.ContainsRune(h.RawLine, ':') {
				issues = append(issues, fmt.Sprintf("header without colon separator: %q", h.Name))
			}
		}
	}

	// Host header: required for HTTP/1.1, at most one
	hostCount := countHeaders(req.Headers, "Host")
	if req.Version == "HTTP/1.1" && hostCount == 0 {
		issues = append(issues, "missing Host header")
	}
	if hostCount > 1 {
		issues = append(issues, fmt.Sprintf("duplicate Host header (%d)", hostCount))
	}

	// Smuggling indicators: TE+CL conflict, duplicate CL/TE
	clCount := countHeaders(req.Headers, "Content-Length")
	teCount := countHeaders(req.Headers, "Transfer-Encoding")
	if teCount > 0 && clCount > 0 {
		issues = append(issues, "both Transfer-Encoding and Content-Length present")
	}
	if clCount > 1 {
		issues = append(issues, fmt.Sprintf("duplicate Content-Length (%d)", clCount))
	}
	if teCount > 1 {
		issues = append(issues, fmt.Sprintf("duplicate Transfer-Encoding (%d)", teCount))
	}

	// Content-Length accuracy
	if clCount == 1 {
		clStr := req.GetHeader("Content-Length")
		if cl, err := strconv.Atoi(clStr); err != nil {
			issues = append(issues, fmt.Sprintf("non-numeric Content-Length: %q", clStr))
		} else if cl != len(req.Body) {
			issues = append(issues, fmt.Sprintf("Content-Length (%d) does not match body length (%d)", cl, len(req.Body)))
		}
	}

	if len(issues) == 0 {
		return nil
	}
	return errors.New(strings.Join(issues, "; "))
}

// countHeaders returns the number of headers with the given name (case-insensitive).
func countHeaders(headers Headers, name string) int {
	var count int
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			count++
		}
	}
	return count
}

// isValidToken checks if s contains only valid HTTP token characters.
// RFC 7230: token = 1*tchar
// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//
//	"^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
func isValidToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isTokenChar(s[i]) {
			return false
		}
	}
	return true
}

// isTokenChar checks if c is a valid HTTP token character.
func isTokenChar(c byte) bool {
	// ALPHA
	if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
		return true
	}
	// DIGIT
	if c >= '0' && c <= '9' {
		return true
	}
	// Special characters allowed in tokens
	switch c {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// CheckLineEndings detects line ending issues in HTTP headers.
// Returns a description of the issue, or empty string if OK.
func CheckLineEndings(raw []byte) string {
	var hasCRLF, hasBareLF, hasBareCR bool

	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '\n':
			if i > 0 && raw[i-1] == '\r' {
				hasCRLF = true
			} else {
				hasBareLF = true
			}
		case '\r':
			if i+1 >= len(raw) || raw[i+1] != '\n' {
				hasBareCR = true
			}
		}
	}

	if hasBareCR {
		return "bare CR without LF detected"
	} else if hasBareLF && hasCRLF {
		return "mixed line endings (some CRLF, some bare LF)"
	} else if hasBareLF {
		return "using LF instead of CRLF line endings"
	}
	return ""
}

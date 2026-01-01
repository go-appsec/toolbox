package service

import (
	"bufio"
	"bytes"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// extractRequestMeta extracts method, host, path from raw HTTP request.
// Returns empty strings on parse failure.
func extractRequestMeta(raw string) (method, host, path string) {
	lines := strings.SplitN(raw, "\r\n", 2)
	if len(lines) == 0 {
		return "", "", ""
	}

	// Request line: "GET /path HTTP/1.1"
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) >= 2 {
		method, path = parts[0], parts[1]
	}

	// Host header (case-insensitive search)
	for _, line := range strings.Split(raw, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(line[5:])
			break
		}
	}

	return method, host, path
}

// splitHeadersBody splits raw HTTP at the \r\n\r\n boundary.
func splitHeadersBody(raw []byte) (headers, body []byte) {
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		return raw, nil
	}
	return raw[:idx+4], raw[idx+4:] // Include blank line in headers
}

// inferSchemeAndPort determines scheme and port from host string.
// Returns scheme, port, and host without port suffix.
func inferSchemeAndPort(host string) (scheme string, port int, hostOnly string) {
	scheme = schemeHTTPS
	port = 443
	hostOnly = host

	if idx := strings.LastIndex(host, ":"); idx > 0 {
		portStr := host[idx+1:]
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
			hostOnly = host[:idx]
			if port == 80 {
				scheme = schemeHTTP
			}
		}
	}
	return scheme, port, hostOnly
}

func readResponseBytes(resp []byte) (*http.Response, error) {
	// Converts "HTTP/2 " to "HTTP/2.0 " since Go's parser requires major.minor format.
	if bytes.HasPrefix(resp, []byte("HTTP/2 ")) {
		resp = append([]byte("HTTP/2.0 "), resp[7:]...)
	}
	return http.ReadResponse(bufio.NewReader(bytes.NewReader(resp)), nil)
}

// previewBody returns a UTF-8 safe preview of the body.
// Returns "<BINARY:N Bytes>" for non-UTF-8 content, truncates at maxLen.
func previewBody(body []byte, maxLen int) string {
	if len(body) == 0 {
		return ""
	}
	if !utf8.Valid(body) {
		return "<BINARY:" + strconv.Itoa(len(body)) + " Bytes>"
	}
	if len(body) <= maxLen {
		return string(body)
	}
	return string(body[:maxLen]) + "..."
}

// transformRequestForValidation converts HTTP/2 request lines to HTTP/1.1 for Go's parser.
// "POST /path HTTP/2\r\n" -> "POST /path HTTP/1.1\r\n"
// The original request should still be sent to Burp (which handles HTTP/2 natively).
func transformRequestForValidation(raw []byte) []byte {
	firstLineEnd := bytes.Index(raw, []byte("\r\n"))
	if firstLineEnd < 0 {
		return raw
	}
	firstLine := raw[:firstLineEnd]
	if bytes.HasSuffix(firstLine, []byte(" HTTP/2")) {
		transformed := make([]byte, 0, len(raw))
		transformed = append(transformed, firstLine[:len(firstLine)-7]...)
		transformed = append(transformed, []byte(" HTTP/1.1")...)
		transformed = append(transformed, raw[firstLineEnd:]...)
		return transformed
	}
	return raw
}

// parseResponseStatus extracts status code and status line from response headers.
// Returns zero values if parsing fails.
func parseResponseStatus(headers []byte) (code int, statusLine string) {
	resp, err := readResponseBytes(headers)
	if err != nil {
		return 0, ""
	}
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Proto + " " + resp.Status
}

// readResponseStatusCode extracts the HTTP status code from raw response bytes.
// Returns 0 if the status code cannot be extracted or is invalid.
// Handles both \r\n and \n line endings, and validates status code range.
func readResponseStatusCode(resp []byte) int {
	// Find end of status line (handle both \r\n and \n)
	lineEnd := bytes.IndexByte(resp, '\n')
	if lineEnd < 0 {
		lineEnd = len(resp)
	}
	if lineEnd > 100 {
		return 0 // status line shouldn't be this long
	}

	line := strings.TrimSuffix(string(resp[:lineEnd]), "\r")

	// Status line: "HTTP/x.y SSS reason" or "HTTP/2 SSS"
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return 0
	}

	code, err := strconv.Atoi(parts[1])
	if err != nil || code < 100 || code >= 600 {
		return 0
	}
	return code
}

// extractHeaderLines extracts header lines from raw HTTP request.
// Skips the request line and returns each header as "Name: Value".
func extractHeaderLines(raw string) []string {
	lines := strings.Split(raw, "\r\n")
	if len(lines) <= 1 {
		return nil
	}

	var result []string
	for _, line := range lines[1:] { // skip request line
		if line == "" {
			break // end of headers
		}
		if strings.Contains(line, ":") {
			result = append(result, line)
		}
	}
	return result
}

// parseHeadersToMap parses raw HTTP into a header map, skipping the first line.
// Header names are normalized to canonical form (e.g., "content-type" -> "Content-Type").
func parseHeadersToMap(raw string) map[string][]string {
	result := make(map[string][]string)
	lines := strings.Split(raw, "\r\n")

	// Skip first line (request/status line)
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			break // end of headers
		}
		if idx := strings.Index(line, ":"); idx > 0 {
			name := http.CanonicalHeaderKey(strings.TrimSpace(line[:idx]))
			value := strings.TrimSpace(line[idx+1:])
			result[name] = append(result[name], value)
		}
	}
	return result
}

// PathQueryOpts contains options for modifying the path and query string.
type PathQueryOpts struct {
	Path        string   // replace entire path (without query)
	Query       string   // replace entire query string
	SetQuery    []string // add or replace query params ("key=value")
	RemoveQuery []string // remove query params by key
}

// HasModifications returns true if any path/query modification is specified.
func (o *PathQueryOpts) HasModifications() bool {
	return o.Path != "" || o.Query != "" || len(o.SetQuery) > 0 || len(o.RemoveQuery) > 0
}

// parseRequestLine parses the HTTP request line into method, path, query, and version.
// Example: "GET /api/users?id=123 HTTP/1.1" -> "GET", "/api/users", "id=123", "HTTP/1.1"
func parseRequestLine(line string) (method, path, query, version string) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return "", "", "", ""
	}
	method = parts[0]
	fullPath := parts[1]
	if len(parts) >= 3 {
		version = parts[2]
	}

	// Split path and query
	if idx := strings.Index(fullPath, "?"); idx >= 0 {
		path = fullPath[:idx]
		query = fullPath[idx+1:]
	} else {
		path = fullPath
	}
	return method, path, query, version
}

// buildRequestLine reconstructs the request line from components.
func buildRequestLine(method, path, query, version string) string {
	if query != "" {
		return method + " " + path + "?" + query + " " + version
	}
	return method + " " + path + " " + version
}

// applyQueryModifications applies set and remove operations to query values.
func applyQueryModifications(values url.Values, opts *PathQueryOpts) url.Values {
	// Remove params first
	for _, key := range opts.RemoveQuery {
		values.Del(key)
	}

	// Set params (add or replace existing)
	for _, kv := range opts.SetQuery {
		if key, val, ok := strings.Cut(kv, "="); ok {
			values.Set(key, val)
		}
	}

	return values
}

// modifyRequestLine applies path and query modifications to raw HTTP request bytes.
// Returns the modified request.
func modifyRequestLine(raw []byte, opts *PathQueryOpts) []byte {
	if opts == nil || !opts.HasModifications() {
		return raw
	}

	// Find end of first line
	lineEnd := bytes.Index(raw, []byte("\r\n"))
	if lineEnd < 0 {
		return raw
	}

	firstLine := string(raw[:lineEnd])
	method, path, query, version := parseRequestLine(firstLine)
	if method == "" {
		return raw
	}

	// Apply path replacement
	if opts.Path != "" {
		path = opts.Path
	}

	// Apply query modifications
	if opts.Query != "" {
		// Complete replacement
		query = opts.Query
	} else if len(opts.SetQuery) > 0 || len(opts.RemoveQuery) > 0 {
		// Parse existing query and apply modifications
		values, _ := url.ParseQuery(query)
		values = applyQueryModifications(values, opts)
		query = values.Encode()
	}

	// Build new request line
	newLine := buildRequestLine(method, path, query, version)

	// Replace first line
	result := make([]byte, 0, len(newLine)+len(raw)-lineEnd)
	result = append(result, []byte(newLine)...)
	result = append(result, raw[lineEnd:]...)
	return result
}

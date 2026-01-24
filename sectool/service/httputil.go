package service

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/go-harden/llm-security-toolbox/sectool/config"
)

const (
	// fetchBatchSize is the number of entries to fetch per MCP call
	fetchBatchSize = 500
	// responsePreviewSize is the maximum bytes to show in response preview
	responsePreviewSize = 500
	// fullBodyMaxSize is the maximum bytes to return in full body responses
	fullBodyMaxSize = 20480
)

var (
	numericSegmentRe = regexp.MustCompile(`^\d+$`)
	uuidSegmentRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexIDSegmentRe   = regexp.MustCompile(`^[0-9a-fA-F]{24,}$`)
)

// normalizePath replaces dynamic path segments (numeric IDs, UUIDs, hex IDs 24+ chars)
// with * for grouping. Query strings are preserved.
func normalizePath(path string) string {
	if path == "" {
		return path
	}

	queryIdx := strings.Index(path, "?")
	var query string
	pathOnly := path
	if queryIdx != -1 {
		query = path[queryIdx:]
		pathOnly = path[:queryIdx]
	}

	segments := strings.Split(pathOnly, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		if numericSegmentRe.MatchString(seg) || uuidSegmentRe.MatchString(seg) || hexIDSegmentRe.MatchString(seg) {
			segments[i] = "*"
		}
	}

	return strings.Join(segments, "/") + query
}

// maxPathLength is the maximum path length for display.
const maxPathLength = 80

// aggregateByTuple groups entries by (host, path, method, status).
// The extract function maps each entry to its aggregate key components.
func aggregateByTuple[T any](entries []T, extract func(T) (host, path, method string, status int)) []SummaryEntry {
	type aggregateKey struct {
		Host   string
		Path   string
		Method string
		Status int
	}
	counts := make(map[aggregateKey]int)
	for _, e := range entries {
		host, path, method, status := extract(e)
		key := aggregateKey{
			Host:   host,
			Path:   normalizePath(path),
			Method: method,
			Status: status,
		}
		counts[key]++
	}

	result := make([]SummaryEntry, 0, len(counts))
	for key, count := range counts {
		result = append(result, SummaryEntry{
			Host:   key.Host,
			Path:   truncateString(key.Path, maxPathLength),
			Method: key.Method,
			Status: key.Status,
			Count:  count,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	return result
}

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
			result[name] = append(result[name], strings.TrimSpace(line[idx+1:]))
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

// parseURLWithDefaultHTTPS parses a URL string, defaulting to HTTPS if no scheme.
func parseURLWithDefaultHTTPS(urlStr string) (*url.URL, error) {
	if !strings.Contains(urlStr, "://") {
		urlStr = schemeHTTPS + "://" + urlStr
	}
	return url.Parse(urlStr)
}

// targetFromURL extracts Target (hostname, port, usesHTTPS) from a parsed URL.
func targetFromURL(u *url.URL) Target {
	t := Target{
		Hostname:  u.Hostname(),
		UsesHTTPS: u.Scheme != schemeHTTP,
	}

	if u.Port() != "" {
		t.Port, _ = strconv.Atoi(u.Port())
	} else if t.UsesHTTPS {
		t.Port = 443
	} else {
		t.Port = 80
	}

	return t
}

// buildRawRequest constructs a raw HTTP/1.1 request from components.
// Returns bytes with proper CRLF line endings.
func buildRawRequest(method string, parsedURL *url.URL, headers map[string]string, body []byte) []byte {
	var bodyReader io.Reader
	if len(body) > 0 {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, parsedURL.String(), bodyReader)
	if err != nil {
		return nil
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("User-Agent", config.UserAgent())

	// Apply user headers (may override Host or User-Agent)
	for name, value := range headers {
		if strings.EqualFold(name, "Host") {
			req.Host = value
		} else {
			req.Header.Set(name, value)
		}
	}

	var buf bytes.Buffer
	_ = req.Write(&buf)
	return buf.Bytes()
}

// globToRegex converts a simple glob pattern to regex.
// Supports: * (any chars), ? (single char)
func globToRegex(glob string) string {
	escaped := regexp.QuoteMeta(glob)
	escaped = strings.ReplaceAll(escaped, `\*`, ".*")
	escaped = strings.ReplaceAll(escaped, `\?`, ".")
	return escaped
}

// pathWithoutQuery returns the path portion before any query string.
func pathWithoutQuery(path string) string {
	if idx := strings.Index(path, "?"); idx != -1 {
		return path[:idx]
	}
	return path
}

// matchesGlob checks if s matches a simple glob pattern.
func matchesGlob(s, pattern string) bool {
	if pattern == "" {
		return true
	}
	re, err := regexp.Compile("^" + globToRegex(pattern) + "$")
	if err != nil {
		return false
	}
	return re.MatchString(s)
}

// parseCommaSeparated parses a comma-separated list into a slice.
func parseCommaSeparated(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// StatusCodeFilter matches status codes by exact value or range (e.g., 2XX).
type StatusCodeFilter struct {
	codes  []int // Exact codes
	ranges []int // Range prefixes (2 for 2xx, 4 for 4xx, etc.)
}

// Matches returns true if the code matches the filter.
func (f *StatusCodeFilter) Matches(code int) bool {
	if f == nil {
		return true
	}
	if slices.Contains(f.codes, code) {
		return true
	}
	for _, r := range f.ranges {
		if code >= r*100 && code < (r+1)*100 {
			return true
		}
	}
	return false
}

// Empty returns true if the filter has no conditions.
func (f *StatusCodeFilter) Empty() bool {
	return f == nil || (len(f.codes) == 0 && len(f.ranges) == 0)
}

// parseStatusFilter parses comma-separated status codes/ranges.
// Supports exact codes (200, 404) and ranges (2XX, 2xx, 4XX, 4xx).
func parseStatusFilter(s string) *StatusCodeFilter {
	parts := parseCommaSeparated(s)
	if parts == nil {
		return nil
	}
	filter := &StatusCodeFilter{}
	for _, p := range parts {
		upper := strings.ToUpper(p)
		// Check for range pattern like "2XX" or "4XX"
		if len(upper) == 3 && upper[1] == 'X' && upper[2] == 'X' {
			if digit, err := strconv.Atoi(string(upper[0])); err == nil && digit >= 1 && digit <= 5 {
				filter.ranges = append(filter.ranges, digit)
				continue
			}
		}
		// Try exact code
		if code, err := strconv.Atoi(p); err == nil {
			filter.codes = append(filter.codes, code)
		}
	}
	return filter
}

// updateContentLength updates or adds Content-Length header.
func updateContentLength(headers []byte, length int) []byte {
	re := regexp.MustCompile(`(?im)^Content-Length:\s*\d+\r?\n`)
	newHeader := fmt.Sprintf("Content-Length: %d\r\n", length)

	if re.Match(headers) {
		return re.ReplaceAll(headers, []byte(newHeader))
	}

	// Insert before blank line if not present and length > 0
	if length > 0 {
		return bytes.Replace(headers, []byte("\r\n\r\n"), []byte("\r\n"+newHeader+"\r\n"), 1)
	}
	return headers
}

// setHeader adds or replaces a header.
func setHeader(headers []byte, name, value string) []byte {
	re := regexp.MustCompile(`(?im)^` + regexp.QuoteMeta(name) + `:\s*.+\r?\n`)
	newHeader := []byte(name + ": " + value + "\r\n")

	if re.Match(headers) {
		return re.ReplaceAll(headers, newHeader)
	}

	// Insert before the blank line
	return bytes.Replace(headers, []byte("\r\n\r\n"),
		append([]byte("\r\n"), append(newHeader, []byte("\r\n")...)...), 1)
}

func setHeaderIfMissing(headers []byte, name, value string) []byte {
	re := regexp.MustCompile(`(?im)^` + regexp.QuoteMeta(name) + `:`)
	if re.Match(headers) {
		return headers
	}
	return setHeader(headers, name, value)
}

// removeHeader removes a header.
func removeHeader(headers []byte, name string) []byte {
	re := regexp.MustCompile(`(?im)^` + regexp.QuoteMeta(name) + `:\s*.+\r?\n`)
	return re.ReplaceAll(headers, nil)
}

// applyHeaderModifications applies header modifications.
func applyHeaderModifications(headers []byte, req *ReplaySendRequest) []byte {
	for _, name := range req.RemoveHeaders {
		headers = removeHeader(headers, name)
	}
	for _, h := range req.AddHeaders {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			headers = setHeader(headers, strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	// Handle --target (update Host header)
	if req.Target != "" {
		if u, err := url.Parse(req.Target); err == nil && u.Host != "" {
			headers = setHeader(headers, "Host", u.Host)
		}
	}

	return headers
}

// checkLineEndings detects line ending issues in HTTP headers.
func checkLineEndings(headers []byte) string {
	hasCRLF := bytes.Contains(headers, []byte("\r\n"))
	var hasBareLF bool
	for i := 0; i < len(headers); i++ {
		if headers[i] == '\n' {
			if i == 0 || headers[i-1] != '\r' {
				hasBareLF = true
				break
			}
		}
	}

	if hasBareLF && hasCRLF {
		return "mixed line endings (some CRLF, some bare LF)"
	} else if hasBareLF {
		return "using LF instead of CRLF line endings"
	}
	return ""
}

// validationIssue represents a single validation problem.
type validationIssue struct {
	Check    string
	Severity string
	Detail   string
}

const (
	severityError   = "error"
	severityWarning = "warning"
)

// validateRequest checks request for common issues.
func validateRequest(raw []byte) []validationIssue {
	var issues []validationIssue

	headers, body := splitHeadersBody(raw)

	// Check line endings FIRST - HTTP requires CRLF
	if issue := checkLineEndings(headers); issue != "" {
		issues = append(issues, validationIssue{
			Check:    "crlf",
			Severity: severityError,
			Detail:   issue + "; HTTP requires CRLF (\\r\\n) line endings, use --force to send anyway",
		})
		return issues
	}

	// Transform for validation only (HTTP/2 -> HTTP/1.1 for Go's parser)
	validationRaw := transformRequestForValidation(raw)

	// Use Go's parser to check structure
	_, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(validationRaw)))
	if err != nil {
		issues = append(issues, validationIssue{
			Check:    "parse",
			Severity: severityError,
			Detail:   err.Error(),
		})
	}

	// Check Content-Length matches body
	clMatch := regexp.MustCompile(`(?im)^Content-Length:\s*(\d+)`).FindSubmatch(headers)
	if clMatch != nil {
		cl, _ := strconv.Atoi(string(clMatch[1]))
		if cl != len(body) {
			issues = append(issues, validationIssue{
				Check:    "content_length",
				Severity: severityError,
				Detail:   fmt.Sprintf("header says %d, body is %d bytes", cl, len(body)),
			})
		}
	}

	// Check Host header (warning only)
	if !regexp.MustCompile(`(?im)^Host:`).Match(headers) {
		issues = append(issues, validationIssue{
			Check:    "host",
			Severity: severityWarning,
			Detail:   "missing Host header",
		})
	}

	return issues
}

// formatIssues formats validation issues as Markdown.
func formatIssues(issues []validationIssue) string {
	var sb strings.Builder
	sb.WriteString("| Issue | Severity | Detail |\n")
	sb.WriteString("|-------|----------|--------|\n")
	for _, i := range issues {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", i.Check, i.Severity, i.Detail))
	}
	return sb.String()
}

// parseTarget determines host, port, and HTTPS from request or target override.
func parseTarget(raw []byte, targetOverride string) (host string, port int, usesHTTPS bool) {
	if targetOverride != "" {
		u, err := url.Parse(targetOverride)
		if err == nil {
			host = u.Hostname()
			port = 443
			if u.Port() != "" {
				port, _ = strconv.Atoi(u.Port())
			} else if u.Scheme == schemeHTTP {
				port = 80
			}
			usesHTTPS = u.Scheme == schemeHTTPS
			return
		}
	}

	// Extract from Host header
	_, host, _ = extractRequestMeta(string(raw))

	// Parse port from host
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		if p, err := strconv.Atoi(host[idx+1:]); err == nil {
			port = p
			host = host[:idx]
			usesHTTPS = port != 80
			return
		}
	}

	// Default to HTTPS
	port = 443
	usesHTTPS = true
	return
}

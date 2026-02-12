package service

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/util"
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
func aggregateByTuple[T any](entries []T, extract func(T) (host, path, method string, status int)) []protocol.SummaryEntry {
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

	result := make([]protocol.SummaryEntry, 0, len(counts))
	for key, count := range counts {
		result = append(result, protocol.SummaryEntry{
			Host:   key.Host,
			Path:   util.TruncateString(key.Path, maxPathLength),
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
// Handles both origin-form ("GET /path") and proxy-form ("GET http://host/path") requests.
// Returns empty strings on parse failure.
func extractRequestMeta(raw string) (method, host, path string) {
	// Request line: "GET /path HTTP/1.1" or "GET http://host/path HTTP/1.1"
	firstLine, _, _ := strings.Cut(raw, "\r\n")
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) >= 2 {
		method = parts[0]
		requestURI := parts[1]

		// Check for proxy-form (absolute URI): "http://host/path" or "https://host/path"
		if strings.HasPrefix(requestURI, "http://") || strings.HasPrefix(requestURI, "https://") {
			if u, err := url.Parse(requestURI); err == nil {
				host = u.Host
				path = u.Path
				if u.RawQuery != "" {
					path = path + "?" + u.RawQuery
				}
				if path == "" {
					path = "/"
				}
				return method, host, path
			}
		}

		// Origin-form: "/path"
		path = requestURI
	}

	// Host header (case-insensitive search) for origin-form requests
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

// extractHeader extracts a header value from raw HTTP headers (case-insensitive).
// Returns empty string if not found.
func extractHeader(headers string, name string) string {
	for _, line := range strings.Split(headers, "\r\n") {
		if idx := strings.Index(line, ":"); idx > 0 {
			if strings.EqualFold(strings.TrimSpace(line[:idx]), name) {
				return strings.TrimSpace(line[idx+1:])
			}
		}
	}
	return ""
}

// decompressForDisplay decompresses body based on Content-Encoding header.
// Returns (decompressed body, wasDecompressed).
// If decompression fails or encoding unsupported, returns original body unchanged.
func decompressForDisplay(body []byte, headers string) ([]byte, bool) {
	encoding := extractHeader(headers, "Content-Encoding")
	if encoding == "" {
		return body, false
	}

	normalized, ok := proxy.NormalizeEncoding(encoding)
	if !ok {
		return body, false
	}

	decompressed, wasCompressed := proxy.Decompress(body, normalized)
	if decompressed == nil {
		// Decompression failed, return original
		return body, false
	}
	return decompressed, wasCompressed
}

// compressBody compresses body based on Content-Encoding value.
// Returns (compressed body, compression failed).
// If encoding is empty or unsupported, returns (original body, false).
// If compression fails, returns (original body, true) - caller should remove Content-Encoding.
func compressBody(body []byte, encoding string) ([]byte, bool) {
	if encoding == "" {
		return body, false
	}

	normalized, ok := proxy.NormalizeEncoding(encoding)
	if !ok {
		return body, false // unsupported encoding, not a failure
	}

	compressed, err := proxy.Compress(body, normalized)
	if err != nil {
		return body, true // compression failed
	}
	return compressed, false
}

// previewBody returns a UTF-8 safe preview of the body.
// Returns "<BINARY:N Bytes>" for non-UTF-8 content, truncates at maxLen runes.
func previewBody(body []byte, maxLen int) string {
	if len(body) == 0 {
		return ""
	}
	if !utf8.Valid(body) {
		return "<BINARY:" + strconv.Itoa(len(body)) + " Bytes>"
	}
	s := string(body)
	if utf8.RuneCountInString(s) <= maxLen {
		return s
	}
	// Truncate at rune boundary
	runes := []rune(s)
	return string(runes[:maxLen]) + "..."
}

// transformRequestForValidation converts HTTP/2 request lines to HTTP/1.1 for Go's parser.
// "POST /path HTTP/2\r\n" -> "POST /path HTTP/1.1\r\n"
// The original request is sent unmodified to the backend (both handle HTTP/2 natively).
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

// parseHeaderArg extracts headers from an MCP argument that may be either:
//   - an object {"Name": "Value"} (documented for request_send)
//   - an array ["Name: Value"] (documented for replay_send add_headers)
//
// Returns headers as "Name: Value" strings regardless of input format.
func parseHeaderArg(raw interface{}) []string {
	switch v := raw.(type) {
	case map[string]interface{}:
		result := make([]string, 0, len(v))
		for k, val := range v {
			if vs, ok := val.(string); ok {
				result = append(result, k+": "+vs)
			}
		}
		return result
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	default:
		return nil
	}
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

// PathQueryOpts contains options for modifying the request line.
type PathQueryOpts struct {
	Method      string   // replace HTTP method
	Path        string   // replace entire path (without query)
	Query       string   // replace entire query string
	SetQuery    []string // add or replace query params ("key=value")
	RemoveQuery []string // remove query params by key
}

// HasModifications returns true if any request line modification is specified.
func (o *PathQueryOpts) HasModifications() bool {
	return o.Method != "" || o.Path != "" || o.Query != "" || len(o.SetQuery) > 0 || len(o.RemoveQuery) > 0
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

	method, path, query, version, err := proxy.ParseRequestLine(raw[:lineEnd])
	if err != nil {
		return raw
	}

	// Apply method replacement
	if opts.Method != "" {
		method = opts.Method
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

// matchesCookieDomain returns true if domain equals filter or is a subdomain of filter.
// e.g. filter "example.com" matches "example.com", "api.example.com", "a.b.example.com".
func matchesCookieDomain(domain, filter string) bool {
	if strings.EqualFold(domain, filter) {
		return true
	}
	return len(domain) > len(filter) && strings.HasSuffix(strings.ToLower(domain), "."+strings.ToLower(filter))
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

// containsContentLengthHeader checks if any header string sets Content-Length.
// Headers are in "Name: Value" format.
func containsContentLengthHeader(headers []string) bool {
	for _, h := range headers {
		if idx := strings.Index(h, ":"); idx > 0 {
			name := strings.TrimSpace(h[:idx])
			if strings.EqualFold(name, "Content-Length") {
				return true
			}
		}
	}
	return false
}

// setHeader adds or replaces a header.
func setHeader(headers []byte, name, value string) []byte {
	re := regexp.MustCompile(`(?im)^` + regexp.QuoteMeta(name) + `:[ \t]*.*\r?\n`)
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
	re := regexp.MustCompile(`(?im)^` + regexp.QuoteMeta(name) + `:[ \t]*.*\r?\n`)
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

// validationIssue represents a single validation problem.
type validationIssue struct {
	Check  string
	Detail string
}

// validateRequest checks request for common issues.
func validateRequest(raw []byte) []validationIssue {
	var issues []validationIssue

	headers, body := splitHeadersBody(raw)

	// Check line endings FIRST - HTTP requires CRLF
	if issue := proxy.CheckLineEndings(headers); issue != "" {
		issues = append(issues, validationIssue{
			Check:  "crlf",
			Detail: issue + "; HTTP requires CRLF (\\r\\n) line endings, use --force to send anyway",
		})
		return issues
	}

	// Use Go's parser to check structure
	// Transform for validation only (HTTP/2 -> HTTP/1.1 for Go's parser)
	validationRaw := transformRequestForValidation(raw)
	if _, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(validationRaw))); err != nil {
		issues = append(issues, validationIssue{
			Check:  "parse",
			Detail: err.Error(),
		})
	}

	// Check Content-Length vs actual body length
	if clIssue := validateContentLength(headers, body); clIssue != "" {
		issues = append(issues, validationIssue{
			Check:  "content-length",
			Detail: clIssue,
		})
	}

	return issues
}

// validateContentLength checks if Content-Length header matches actual body length.
func validateContentLength(headers, body []byte) string {
	// Extract Content-Length header
	clMatch := regexp.MustCompile(`(?im)^Content-Length:\s*(\d+)`).FindSubmatch(headers)
	if clMatch == nil {
		return "" // No Content-Length header, no validation needed
	}

	cl, err := strconv.Atoi(string(clMatch[1]))
	if err != nil {
		return "invalid Content-Length value"
	}

	bodyLen := len(body)
	if cl != bodyLen {
		return fmt.Sprintf("Content-Length (%d) does not match body length (%d)", cl, bodyLen)
	}

	return ""
}

// formatIssues formats validation issues as Markdown.
func formatIssues(issues []validationIssue) string {
	var sb strings.Builder
	sb.WriteString("| Issue | Detail |\n")
	sb.WriteString("|-------|--------|\n")
	for _, i := range issues {
		sb.WriteString(fmt.Sprintf("| %s | %s |\n", i.Check, i.Detail))
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

	// Check for proxy-form URL in request line first (e.g., "GET http://host/path")
	rawStr := string(raw)
	firstLine, _, _ := strings.Cut(rawStr, "\r\n")
	parts := strings.SplitN(firstLine, " ", 3)
	if len(parts) >= 2 {
		requestURI := parts[1]
		if strings.HasPrefix(requestURI, "http://") || strings.HasPrefix(requestURI, "https://") {
			if u, err := url.Parse(requestURI); err == nil {
				host = u.Hostname()
				usesHTTPS = u.Scheme == schemeHTTPS
				if u.Port() != "" {
					port, _ = strconv.Atoi(u.Port())
				} else if usesHTTPS {
					port = 443
				} else {
					port = 80
				}
				return
			}
		}
	}

	// Extract from Host header (for origin-form requests)
	_, host, _ = extractRequestMeta(rawStr)

	// Parse port from host
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		if p, err := strconv.Atoi(host[idx+1:]); err == nil {
			port = p
			host = host[:idx]
			// Port 443 implies HTTPS, port 80 implies HTTP, others default to HTTP
			usesHTTPS = port == 443
			return
		}
	}

	// Default to HTTPS when no port is specified (common for web traffic)
	port = 443
	usesHTTPS = true
	return
}

// extractMethod extracts the HTTP method from a raw request.
func extractMethod(raw []byte) string {
	lines := bytes.SplitN(raw, []byte("\r\n"), 2)
	if len(lines) == 0 {
		return "GET"
	}
	parts := bytes.SplitN(lines[0], []byte(" "), 2)
	if len(parts) == 0 {
		return "GET"
	}
	return string(parts[0])
}

// extractRequestPath extracts the path from a raw request's request line,
// stripping any query parameters.
func extractRequestPath(raw []byte) string {
	lines := bytes.SplitN(raw, []byte("\r\n"), 2)
	if len(lines) == 0 {
		return "/"
	}
	parts := bytes.SplitN(lines[0], []byte(" "), 3)
	if len(parts) < 2 {
		return "/"
	}
	p := string(parts[1])
	if idx := strings.Index(p, "?"); idx >= 0 {
		p = p[:idx]
	}
	return p
}

// buildRedirectRequest builds a new request for following a redirect.
// Preserves headers (including cookies and Authorization),
// handles method/body per status code.
func buildRedirectRequest(originalReq []byte, location string, currentTarget Target, currentPath string, status int) ([]byte, Target, string, error) {
	var preserveMethod, preserveBody bool
	switch status {
	case 307, 308:
		preserveMethod = true
		preserveBody = true
	}

	newTarget, newPath, err := resolveRedirectLocation(location, currentTarget, currentPath)
	if err != nil {
		return nil, Target{}, "", err
	}

	method := extractMethod(originalReq)
	if !preserveMethod {
		method = "GET"
	}

	var body []byte
	if preserveBody {
		_, body = splitHeadersBody(originalReq)
	}

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, newPath))
	copyHeadersForRedirect(originalReq, &buf, newTarget, preserveBody)

	if len(body) > 0 {
		buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}

	buf.WriteString("\r\n")
	buf.Write(body)

	return buf.Bytes(), newTarget, newPath, nil
}

// resolveRedirectLocation resolves a Location header value to a target and path.
func resolveRedirectLocation(location string, currentTarget Target, currentPath string) (Target, string, error) {
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		u, err := url.Parse(location)
		if err != nil {
			return Target{}, "", err
		}
		return targetFromURL(u), u.RequestURI(), nil
	}

	if strings.HasPrefix(location, "//") {
		scheme := schemeHTTPS
		if !currentTarget.UsesHTTPS {
			scheme = schemeHTTP
		}
		u, err := url.Parse(scheme + ":" + location)
		if err != nil {
			return Target{}, "", err
		}
		return targetFromURL(u), u.RequestURI(), nil
	}

	if strings.HasPrefix(location, "/") {
		return currentTarget, location, nil
	}

	baseDir := path.Dir(currentPath)
	if baseDir == "." {
		baseDir = "/"
	}
	resolved := path.Join(baseDir, location)
	if !strings.HasPrefix(resolved, "/") {
		resolved = "/" + resolved
	}
	return currentTarget, resolved, nil
}

// copyHeadersForRedirect copies headers from original request to buffer,
// applying redirect-appropriate modifications.
func copyHeadersForRedirect(originalReq []byte, buf *bytes.Buffer, newTarget Target, preserveBody bool) {
	headers, _ := splitHeadersBody(originalReq)

	newHost := newTarget.Hostname
	if (newTarget.UsesHTTPS && newTarget.Port != 443) || (!newTarget.UsesHTTPS && newTarget.Port != 80) {
		newHost = fmt.Sprintf("%s:%d", newTarget.Hostname, newTarget.Port)
	}

	skipHeaders := map[string]bool{
		"host":           true,
		"content-length": true,
	}
	if !preserveBody {
		skipHeaders["content-type"] = true
		skipHeaders["content-encoding"] = true
		skipHeaders["transfer-encoding"] = true
	}

	_, _ = fmt.Fprintf(buf, "Host: %s\r\n", newHost)

	for _, line := range bytes.Split(headers, []byte("\r\n")) {
		if len(line) == 0 {
			continue
		}

		// Skip request line
		if bytes.HasPrefix(line, []byte("GET ")) || bytes.HasPrefix(line, []byte("POST ")) ||
			bytes.HasPrefix(line, []byte("PUT ")) || bytes.HasPrefix(line, []byte("DELETE ")) ||
			bytes.HasPrefix(line, []byte("PATCH ")) || bytes.HasPrefix(line, []byte("HEAD ")) ||
			bytes.HasPrefix(line, []byte("OPTIONS ")) || bytes.HasPrefix(line, []byte("TRACE ")) ||
			bytes.HasPrefix(line, []byte("CONNECT ")) {
			continue
		}

		if colonIdx := bytes.IndexByte(line, ':'); colonIdx < 0 {
			continue
		} else if name := strings.ToLower(string(bytes.TrimSpace(line[:colonIdx]))); skipHeaders[name] {
			continue
		}

		buf.Write(line)
		buf.WriteString("\r\n")
	}
}

// RequestSender sends a single request and returns the result.
type RequestSender func(ctx context.Context, req SendRequestInput, start time.Time) (*SendRequestResult, error)

// FollowRedirects sends a request and follows redirects up to maxRedirects times.
// Uses sender to perform individual requests, allowing different backend implementations.
// Used by BurpBackend which doesn't use the wire-fidelity sender.
func FollowRedirects(ctx context.Context, req SendRequestInput, start time.Time, maxRedirects int, sender RequestSender) (*SendRequestResult, error) {
	currentReq := req
	currentPath := extractRequestPath(currentReq.RawRequest)

	for i := 0; i < maxRedirects; i++ {
		result, err := sender(ctx, currentReq, start)
		if err != nil {
			return nil, err
		}

		resp, err := readResponseBytes(result.Headers)
		if err != nil {
			result.Duration = time.Since(start)
			return result, nil
		}
		_ = resp.Body.Close()

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			result.Duration = time.Since(start)
			return result, nil
		}

		location := resp.Header.Get("Location")
		if location == "" {
			result.Duration = time.Since(start)
			return result, nil
		}

		newReq, newTarget, newPath, err :=
			buildRedirectRequest(currentReq.RawRequest, location, currentReq.Target, currentPath, resp.StatusCode)
		if err != nil {
			result.Duration = time.Since(start)
			return result, nil
		}

		currentReq.RawRequest = newReq
		currentReq.Target = newTarget
		currentPath = newPath
	}

	return nil, errors.New("too many redirects")
}

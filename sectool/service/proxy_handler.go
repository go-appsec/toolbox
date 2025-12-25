package service

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/go-analyze/bulk"

	"github.com/jentfoo/llm-security-toolbox/sectool/service/ids"
	"github.com/jentfoo/llm-security-toolbox/sectool/service/store"
)

const (
	// fetchBatchSize is the number of entries to fetch per MCP call
	fetchBatchSize = 500
	// maxPathLength is the maximum path length for display (truncated beyond this)
	maxPathLength = 100
	// responsePreviewSize is the maximum bytes to show in response preview
	responsePreviewSize = 500
)

// globToJavaRegex converts a simple glob to Java regex.
// Supports: * (any chars), ? (single char)
func globToJavaRegex(glob string) string {
	var result strings.Builder
	for _, c := range glob {
		switch c {
		case '*':
			result.WriteString(".*")
		case '?':
			result.WriteString(".")
		case '.', '[', ']', '(', ')', '{', '}', '+', '^', '$', '|', '\\':
			result.WriteString("\\")
			result.WriteRune(c)
		default:
			result.WriteRune(c)
		}
	}
	return result.String()
}

// buildJavaRegex builds a regex for Burp's regex filter from request filters.
func buildJavaRegex(req *ProxyListRequest) string {
	var parts []string

	if req.Host != "" {
		parts = append(parts, `Host:\s*`+globToJavaRegex(req.Host))
	}
	if req.Path != "" {
		// Match path in request line
		parts = append(parts, `\s+`+globToJavaRegex(req.Path)+`\s+HTTP/`)
	}
	if req.Contains != "" {
		parts = append(parts, regexp.QuoteMeta(req.Contains))
	}
	if req.ContainsBody != "" {
		parts = append(parts, regexp.QuoteMeta(req.ContainsBody))
	}

	if len(parts) == 0 {
		return ""
	} else if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, "|") + ")"
}

// truncatePath truncates path to maxLen characters.
func truncatePath(path string, maxLen int) string {
	if len(path) <= maxLen || maxLen < 1 {
		return path
	}
	return path[:maxLen-3] + "..."
}

// matchesGlob checks if s matches a simple glob pattern.
func matchesGlob(s, pattern string) bool {
	if pattern == "" {
		return true
	}
	// Convert glob to regex and match
	re, err := regexp.Compile("^" + globToJavaRegex(pattern) + "$")
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

// parseStatusCodes parses comma-separated status codes into integers.
func parseStatusCodes(s string) []int {
	parts := parseCommaSeparated(s)
	if parts == nil {
		return nil
	}
	result := make([]int, 0, len(parts))
	for _, p := range parts {
		if code, err := strconv.Atoi(p); err == nil {
			result = append(result, code)
		}
	}
	return result
}

// aggregateByTuple groups entries by (host, path, method, status).
func aggregateByTuple(entries []flowEntry) []AggregateEntry {
	type aggregateKey struct {
		Host   string
		Path   string
		Method string
		Status int
	}
	counts := make(map[aggregateKey]int)
	for _, e := range entries {
		key := aggregateKey{
			Host:   e.host,
			Path:   e.path,
			Method: e.method,
			Status: e.status,
		}
		counts[key]++
	}

	// Convert to slice and sort by count descending
	result := make([]AggregateEntry, 0, len(counts))
	for key, count := range counts {
		result = append(result, AggregateEntry{
			Host:   key.Host,
			Path:   truncatePath(key.Path, maxPathLength),
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

// flowEntry holds parsed metadata for a proxy history entry.
type flowEntry struct {
	offset   uint32
	method   string
	host     string
	path     string
	status   int
	respLen  int
	request  string
	response string
}

// handleProxyList handles POST /proxy/list
func (s *Server) handleProxyList(w http.ResponseWriter, r *http.Request) {
	var req ProxyListRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	}

	ctx := r.Context()

	// Build regex filter if applicable (moved outside loop for efficiency)
	var regex string
	if req.HasFilters() &&
		// If any of the filters below are set the filtering must be client side
		req.Method == "" && req.Status == "" &&
		req.ExcludeHost == "" && req.ExcludePath == "" &&
		req.Since == "" {
		regex = buildJavaRegex(&req)
	}

	// Fetch all entries from HttpBackend
	var allEntries []flowEntry
	var offset uint32
	for {
		var proxyEntries []ProxyEntry
		var fetchErr error

		if regex != "" {
			proxyEntries, fetchErr = s.httpBackend.GetProxyHistoryRegex(ctx, regex, fetchBatchSize, offset)
		} else {
			proxyEntries, fetchErr = s.httpBackend.GetProxyHistory(ctx, fetchBatchSize, offset)
		}
		if fetchErr != nil {
			s.writeError(w, http.StatusBadGateway, ErrCodeBackendError,
				"failed to fetch proxy history", fetchErr.Error())
			return
		}

		if len(proxyEntries) == 0 {
			break
		}

		// Parse entries into flowEntry format
		for i, entry := range proxyEntries {
			method, host, path := extractRequestMeta(entry.Request)
			status := extractStatus(entry.Response)
			_, respBody := splitHeadersBody([]byte(entry.Response))

			allEntries = append(allEntries, flowEntry{
				offset:   offset + uint32(i),
				method:   method,
				host:     host,
				path:     path,
				status:   status,
				respLen:  len(respBody),
				request:  entry.Request,
				response: entry.Response,
			})
		}

		offset += uint32(len(proxyEntries))

		if len(proxyEntries) < fetchBatchSize {
			break // Last page
		}
	}

	lastOffset := s.proxyLastOffset.Load()

	// Apply client-side filters
	filtered := applyClientFilters(allEntries, &req, s.flowStore, lastOffset)

	// Track max offset for updating lastOffset
	var maxOffset uint32
	for _, e := range allEntries {
		if e.offset > maxOffset {
			maxOffset = e.offset
		}
	}

	// Build response
	if req.HasFilters() {
		flows := make([]FlowSummary, 0, len(filtered))
		for _, entry := range filtered {
			// Compute hash including headers and body for stable flow identification
			headerLines := extractHeaderLines(entry.request)
			_, reqBody := splitHeadersBody([]byte(entry.request))
			hash := store.ComputeFlowHashSimple(entry.method, entry.host, entry.path, headerLines, reqBody)
			flowID := s.flowStore.Register(entry.offset, hash)

			scheme, port, _ := inferSchemeAndPort(entry.host)

			flows = append(flows, FlowSummary{
				FlowID:         flowID,
				Method:         entry.method,
				Scheme:         scheme,
				Host:           entry.host,
				Port:           port,
				Path:           truncatePath(entry.path, maxPathLength),
				Status:         entry.status,
				ResponseLength: entry.respLen,
			})
		}
		s.writeJSON(w, http.StatusOK, ProxyListResponse{Flows: flows})
	} else {
		// Return aggregates
		agg := aggregateByTuple(filtered)
		s.writeJSON(w, http.StatusOK, ProxyListResponse{Aggregates: agg})
	}

	if maxOffset > lastOffset {
		s.proxyLastOffset.Store(maxOffset)
	}
}

// applyClientFilters applies filters that can't be expressed in Burp regex.
func applyClientFilters(entries []flowEntry, req *ProxyListRequest, store *store.FlowStore, lastOffset uint32) []flowEntry {
	if !req.HasFilters() {
		return entries
	}

	methods := parseCommaSeparated(req.Method)
	statuses := parseStatusCodes(req.Status)

	var sinceOffset uint32
	var hasSince bool
	if req.Since != "" {
		if req.Since == "last" {
			sinceOffset = lastOffset
			hasSince = true
		} else if entry, ok := store.Lookup(req.Since); ok {
			sinceOffset = entry.Offset
			hasSince = true
		}
	}

	return bulk.SliceFilter(func(e flowEntry) bool {
		if hasSince && e.offset <= sinceOffset {
			return false // Since filter (exclusive - only entries after)
		} else if len(methods) > 0 && !slices.Contains(methods, e.method) {
			return false // Method filter
		} else if len(statuses) > 0 && !slices.Contains(statuses, e.status) {
			return false // Status filter
		} else if req.Host != "" && !matchesGlob(e.host, req.Host) {
			return false // Host filter (if using client-side filtering)
		} else if req.Path != "" && !matchesGlob(e.path, req.Path) {
			return false // Path filter (if using client-side filtering)
		} else if req.ExcludeHost != "" && matchesGlob(e.host, req.ExcludeHost) {
			return false // Exclude host
		} else if req.ExcludePath != "" && matchesGlob(e.path, req.ExcludePath) {
			return false // Exclude path
		}
		if req.Contains != "" {
			// Search URL and headers only (not body) - spec line 665
			reqHeaders, _ := splitHeadersBody([]byte(e.request))
			respHeaders, _ := splitHeadersBody([]byte(e.response))
			combined := string(reqHeaders) + string(respHeaders)
			if !strings.Contains(combined, req.Contains) {
				return false
			}
		}
		if req.ContainsBody != "" {
			_, reqBody := splitHeadersBody([]byte(e.request))
			_, respBody := splitHeadersBody([]byte(e.response))
			combined := string(reqBody) + string(respBody)
			if !strings.Contains(combined, req.ContainsBody) {
				return false // Contains body filter
			}
		}

		return true
	}, entries)
}

// handleProxyExport handles POST /proxy/export
func (s *Server) handleProxyExport(w http.ResponseWriter, r *http.Request) {
	var req ProxyExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	} else if req.FlowID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "flow_id is required", "")
		return
	}

	entry, ok := s.flowStore.Lookup(req.FlowID)
	if !ok {
		s.writeError(w, http.StatusNotFound, ErrCodeNotFound,
			"flow_id not found", "run 'sectool proxy list' to see available flows")
		return
	}

	ctx := r.Context()

	proxyEntries, err := s.httpBackend.GetProxyHistory(ctx, 1, entry.Offset)
	if err != nil {
		s.writeError(w, http.StatusBadGateway, ErrCodeBackendError,
			"failed to fetch flow from HttpBackend", err.Error())
		return
	} else if len(proxyEntries) == 0 {
		s.writeError(w, http.StatusNotFound, ErrCodeNotFound,
			"flow not found in proxy history", "the flow may have been cleared")
		return
	}

	// Parse request
	method, host, path := extractRequestMeta(proxyEntries[0].Request)
	headers, body := splitHeadersBody([]byte(proxyEntries[0].Request))

	// Generate bundle ID and path
	bundleID := ids.Generate(ids.DefaultLength)
	bundlePath := req.OutDir
	if bundlePath == "" {
		bundlePath = filepath.Join(s.paths.RequestsDir, bundleID)
	}

	// Determine scheme from host port
	scheme, _, _ := inferSchemeAndPort(host)
	url := scheme + "://" + host + path

	meta := &bundleMeta{
		BundleID:     bundleID,
		SourceFlowID: req.FlowID,
		CapturedAt:   "",
		URL:          url,
		Method:       method,
		BodyIsUTF8:   utf8.Valid(body),
		BodySize:     len(body),
		Notes:        proxyEntries[0].Notes,
	}

	if err := writeBundle(bundlePath, headers, body, meta); err != nil {
		s.writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to write bundle", err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, ProxyExportResponse{
		BundleID:   bundleID,
		BundlePath: bundlePath,
	})
}

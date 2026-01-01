package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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

// globToRegex converts a simple glob pattern to regex.
// Supports: * (any chars), ? (single char)
func globToRegex(glob string) string {
	escaped := regexp.QuoteMeta(glob)
	escaped = strings.ReplaceAll(escaped, `\*`, ".*")
	escaped = strings.ReplaceAll(escaped, `\?`, ".")
	return escaped
}

// truncatePath truncates path to maxLen characters.
func truncatePath(path string, maxLen int) string {
	if len(path) <= maxLen || maxLen < 1 {
		return path
	}
	return path[:maxLen-3] + "..."
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	}

	resp, err := s.processProxyList(r.Context(), &req)
	if err != nil {
		if IsTimeoutError(err) {
			s.writeError(w, http.StatusGatewayTimeout, ErrCodeTimeout, "proxy history request timed out", err.Error())
		} else {
			s.writeError(w, http.StatusBadGateway, ErrCodeBackendError, "failed to fetch proxy history", err.Error())
		}
		return
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// processProxyList fetches and filters proxy history. Shared by HTTP and MCP handlers.
func (s *Server) processProxyList(ctx context.Context, req *ProxyListRequest) (*ProxyListResponse, error) {
	if req.HasFilters() {
		log.Printf("proxy/list: fetching with filters (host=%q path=%q method=%q status=%q since=%q)",
			req.Host, req.Path, req.Method, req.Status, req.Since)
	} else {
		log.Printf("proxy/list: fetching aggregated summary")
	}

	var allEntries []flowEntry
	var offset uint32
	for {
		proxyEntries, err := s.httpBackend.GetProxyHistory(ctx, fetchBatchSize, offset)
		if err != nil {
			return nil, err
		}
		if len(proxyEntries) == 0 {
			break
		}

		for i, entry := range proxyEntries {
			method, host, path := extractRequestMeta(entry.Request)
			status := readResponseStatusCode([]byte(entry.Response))
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
			break
		}
	}

	lastOffset := s.proxyLastOffset.Load()
	filtered := applyClientFilters(allEntries, req, s.flowStore, lastOffset)

	if req.Limit > 0 && len(filtered) > req.Limit {
		filtered = filtered[:req.Limit]
	}

	var maxOffset uint32
	for _, e := range filtered {
		if e.offset > maxOffset {
			maxOffset = e.offset
		}
	}

	var resp ProxyListResponse
	if req.HasFilters() {
		flows := make([]FlowSummary, 0, len(filtered))
		for _, entry := range filtered {
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
		log.Printf("proxy/list: returning %d flows (fetched %d, filtered %d)", len(flows), len(allEntries), len(allEntries)-len(filtered))
		resp.Flows = flows
	} else {
		agg := aggregateByTuple(filtered)
		log.Printf("proxy/list: returning %d aggregates from %d entries", len(agg), len(filtered))
		resp.Aggregates = agg
	}

	if maxOffset > lastOffset {
		s.proxyLastOffset.Store(maxOffset)
	}

	return &resp, nil
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
		} else if req.Path != "" && !matchesGlob(e.path, req.Path) && !matchesGlob(pathWithoutQuery(e.path), req.Path) {
			return false
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

	log.Printf("proxy/export: exporting flow %s", req.FlowID)

	entry, ok := s.flowStore.Lookup(req.FlowID)
	if !ok {
		s.writeError(w, http.StatusNotFound, ErrCodeNotFound,
			"flow_id not found", "run 'sectool proxy list' to see available flows")
		return
	}

	ctx := r.Context()

	proxyEntries, err := s.httpBackend.GetProxyHistory(ctx, 1, entry.Offset)
	if err != nil {
		if IsTimeoutError(err) {
			s.writeError(w, http.StatusGatewayTimeout, ErrCodeTimeout,
				"request timed out fetching flow", err.Error())
		} else {
			s.writeError(w, http.StatusBadGateway, ErrCodeBackendError,
				"failed to fetch flow from HttpBackend", err.Error())
		}
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

	log.Printf("proxy/export: exported flow %s to bundle %s at %s", req.FlowID, bundleID, bundlePath)
	s.writeJSON(w, http.StatusOK, ProxyExportResponse{
		BundleID:   bundleID,
		BundlePath: bundlePath,
	})
}

// handleRuleList handles POST /proxy/rule/list
func (s *Server) handleRuleList(w http.ResponseWriter, r *http.Request) {
	var req RuleListRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	}

	log.Printf("proxy/rule/list: websocket=%t", req.WebSocket)

	rules, err := s.httpBackend.ListRules(r.Context(), req.WebSocket)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
			"failed to list rules", err.Error())
		return
	}

	if req.Limit > 0 && len(rules) > req.Limit {
		rules = rules[:req.Limit]
	}

	log.Printf("proxy/rule/list: returning %d rules", len(rules))
	s.writeJSON(w, http.StatusOK, RuleListResponse{Rules: rules})
}

// handleRuleAdd handles POST /proxy/rule/add
func (s *Server) handleRuleAdd(w http.ResponseWriter, r *http.Request) {
	var req RuleAddRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	} else if req.Type == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "type is required", "")
		return
	} else if err := validateRuleTypeAny(req.Type); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, err.Error(), "")
		return
	} else if req.Match == "" && req.Replace == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "match or replace is required", "")
		return
	}

	log.Printf("proxy/rule/add: type=%s label=%q", req.Type, req.Label)

	rule, err := s.httpBackend.AddRule(r.Context(), ProxyRuleInput(req))
	if err != nil {
		if errors.Is(err, ErrLabelExists) {
			s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest,
				"failed to add rule", err.Error())
		} else {
			s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
				"failed to add rule", err.Error())
		}
		return
	}

	log.Printf("proxy/rule/add: created rule %s", rule.RuleID)
	s.writeJSON(w, http.StatusOK, rule)
}

// handleRuleUpdate handles POST /proxy/rule/update
func (s *Server) handleRuleUpdate(w http.ResponseWriter, r *http.Request) {
	var req RuleUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	} else if req.RuleID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "rule_id is required", "")
		return
	} else if req.Type == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "type is required", "")
		return
	} else if err := validateRuleTypeAny(req.Type); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, err.Error(), "")
		return
	} else if req.Match == "" && req.Replace == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "match or replace is required", "")
		return
	}

	log.Printf("proxy/rule/update: rule=%s", req.RuleID)

	rule, err := s.httpBackend.UpdateRule(r.Context(), req.RuleID, ProxyRuleInput{
		Label:   req.Label,
		Type:    req.Type,
		IsRegex: req.IsRegex,
		Match:   req.Match,
		Replace: req.Replace,
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.writeError(w, http.StatusNotFound, ErrCodeNotFound, "rule not found", "")
		} else if errors.Is(err, ErrLabelExists) {
			s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest,
				"failed to update rule", err.Error())
		} else {
			s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
				"failed to update rule", err.Error())
		}
		return
	}

	log.Printf("proxy/rule/update: updated rule %s", rule.RuleID)
	s.writeJSON(w, http.StatusOK, rule)
}

// handleRuleDelete handles POST /proxy/rule/delete
func (s *Server) handleRuleDelete(w http.ResponseWriter, r *http.Request) {
	var req RuleDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	} else if req.RuleID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "rule_id is required", "")
		return
	}

	log.Printf("proxy/rule/delete: rule=%s", req.RuleID)

	if err := s.httpBackend.DeleteRule(r.Context(), req.RuleID); err != nil {
		if errors.Is(err, ErrNotFound) {
			s.writeError(w, http.StatusNotFound, ErrCodeNotFound, "rule not found", "")
		} else {
			s.writeError(w, http.StatusInternalServerError, ErrCodeBackendError,
				"failed to delete rule", err.Error())
		}
		return
	}

	log.Printf("proxy/rule/delete: deleted rule %s", req.RuleID)
	s.writeJSON(w, http.StatusOK, RuleDeleteResponse{})
}

var validRuleTypes = map[string]bool{
	// HTTP types
	RuleTypeRequestHeader:  true,
	RuleTypeRequestBody:    true,
	RuleTypeResponseHeader: true,
	RuleTypeResponseBody:   true,
	// WebSocket types
	"ws:to-server": true,
	"ws:to-client": true,
	"ws:both":      true,
}

func validateRuleTypeAny(t string) error {
	if !validRuleTypes[t] {
		return fmt.Errorf("invalid rule type %q", t)
	}
	return nil
}

package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/go-analyze/bulk"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/jwt"
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sectool/util"
)

func (m *mcpServer) proxyPollTool() mcp.Tool {
	return mcp.NewTool("proxy_poll",
		mcp.WithDescription(`Query proxy history: summary (default) or flows mode.

Output modes:
- "summary" (default): Returns traffic grouped by (host, path, method, status). Use first to understand available traffic.
- "flows": Returns individual flows with flow_id for use with proxy_get or replay_send. Requires at least one filter or limit.

Sources: Results include both proxy-captured traffic (source=proxy) and replay-sent traffic (source=replay) in chronological order.
Filters: host/path/exclude_host/exclude_path use glob (*, ?). method/status are comma-separated (status supports ranges like 2XX).
Search: search_header/search_body use regex; literal if invalid.
Incremental: since accepts flow_id or "last" (cursor). Flows mode only: pagination with limit/offset.`),
		mcp.WithString("output_mode", mcp.Description("Output mode: 'summary' (default) or 'flows'")),
		mcp.WithString("source", mcp.Description("Filter by source: 'proxy', 'replay', or empty for both")),
		mcp.WithString("host", mcp.Description("Filter by host glob. *.example.com = subdomains only; *example.com = domain + subdomains")),
		mcp.WithString("path", mcp.Description("Filter by path+query (glob pattern, e.g., '/api/*')")),
		mcp.WithString("method", mcp.Description("Filter by HTTP method(s), comma-separated (e.g., 'GET,POST')")),
		mcp.WithString("status", mcp.Description("Filter by status code(s) or ranges (e.g., '200,302' or '2XX,4XX')")),
		mcp.WithString("search_header", mcp.Description("Search request/response headers by regex (RE2); literal if invalid")),
		mcp.WithString("search_body", mcp.Description("Search request/response body by regex (RE2, use (?i) for case-insensitive); literal if invalid")),
		mcp.WithString("since", mcp.Description("Entries after flow_id, or 'last' (cursor)")),
		mcp.WithString("exclude_host", mcp.Description("Exclude hosts matching glob pattern")),
		mcp.WithString("exclude_path", mcp.Description("Exclude paths matching glob pattern")),
		mcp.WithNumber("limit", mcp.Description("List mode: max results to return")),
		mcp.WithNumber("offset", mcp.Description("List mode: skip first N results (applied after filtering)")),
	)
}

func (m *mcpServer) proxyGetTool() mcp.Tool {
	return mcp.NewTool("proxy_get",
		mcp.WithDescription(`Get full request and response data for a proxy history entry.

Returns headers and body for both request and response. Binary bodies are returned as "<BINARY:N Bytes>" placeholder.
Use flow_id from proxy_poll (output_mode=flows) to identify the entry.

Scope: Sections to return (comma-separated): request_headers, request_body, response_headers, response_body, all (default).
Pattern: Regex search within scoped sections; returns match context instead of full content. Sections without matches are omitted.`),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow ID from proxy_poll")),
		mcp.WithString("scope", mcp.Description("Sections to return (comma-separated): request_headers, request_body, response_headers, response_body, all (default)")),
		mcp.WithString("pattern", mcp.Description("Regex (RE2) search within scoped sections; returns match context instead of full content")),
	)
}

func (m *mcpServer) proxyRuleListTool() mcp.Tool {
	return mcp.NewTool("proxy_rule_list",
		mcp.WithDescription("List proxy match/replace rules. Use type_filter to control which rules are returned."),
		mcp.WithString("type_filter", mcp.Description("Filter by rule type: 'http', 'websocket', or 'all' (default: 'all')")),
		mcp.WithNumber("limit", mcp.Description("Maximum number of rules to return")),
	)
}

func (m *mcpServer) proxyRuleAddTool() mcp.Tool {
	return mcp.NewTool("proxy_rule_add",
		mcp.WithDescription(`Add proxy match/replace rule. Applies to proxy-intercepted traffic only. For one-off request edits, use replay_send parameters instead.

Types:
  HTTP:      request_header (default), request_body, response_header, response_body
  WebSocket: ws:to-server, ws:to-client, ws:both

Regex: is_regex=true (RE2 regex). Labels must be unique.
To modify a rule, delete it with proxy_rule_delete and recreate.`),
		mcp.WithString("type", mcp.Required(), mcp.Description("Rule type: request_header, request_body, response_header, response_body, ws:to-server, ws:to-client, ws:both")),
		mcp.WithString("match", mcp.Description("Pattern to find")),
		mcp.WithString("replace", mcp.Description("Replacement text")),
		mcp.WithString("label", mcp.Description("Optional unique label (usable as rule_id)")),
		mcp.WithBoolean("is_regex", mcp.Description("Treat match as regex pattern (RE2)")),
	)
}

func (m *mcpServer) proxyRuleDeleteTool() mcp.Tool {
	return mcp.NewTool("proxy_rule_delete",
		mcp.WithDescription("Delete a proxy match/replace rule by rule_id or label (searches HTTP+WS)."),
		mcp.WithString("rule_id", mcp.Required(), mcp.Description("Rule ID or label to delete")),
	)
}

func (m *mcpServer) cookieJarTool() mcp.Tool {
	return mcp.NewTool("cookie_jar",
		mcp.WithDescription(`Extract and deduplicate cookies from proxy and replay traffic.
Returns cookies deduplicated by (name, domain) with security attributes (Secure, HttpOnly, SameSite) and origin flow_id.
Without filters: overview only (no values). With name or domain filter: includes full values and auto-decoded JWT claims.`),
		mcp.WithString("name", mcp.Description("Filter by cookie name (exact match); enables value and JWT decode in response")),
		mcp.WithString("domain", mcp.Description("Filter by cookie domain (matches domain and subdomains); enables value and JWT decode in response")),
	)
}

func (m *mcpServer) handleCookieJar(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	nameFilter := req.GetString("name", "")
	domainFilter := req.GetString("domain", "")
	// Detail mode: include values and JWT decode when any filter is applied
	detailMode := nameFilter != "" || domainFilter != ""

	// Fetch all proxy+replay entries with full response data
	allEntries, err := m.service.fetchAllProxyEntries(ctx, true)
	if err != nil {
		return errorResultFromErr("failed to fetch proxy history: ", err), nil
	}

	// Filter out-of-scope domains
	cfg := m.service.cfg
	if len(cfg.AllowedDomains) > 0 || len(cfg.ExcludeDomains) > 0 {
		allEntries = bulk.SliceFilterInPlace(func(e flowEntry) bool {
			allowed, _ := cfg.IsDomainAllowed(e.host)
			return allowed
		}, allEntries)
	}

	// Extract cookies: deduplicate by (name, domain), keeping last seen
	type cookieKey struct{ name, domain string }
	seen := make(map[cookieKey]protocol.CookieEntry)
	var order []cookieKey
	for _, entry := range allEntries {
		if entry.response == "" {
			continue
		}

		resp, parseErr := readResponseBytes([]byte(entry.response))
		if parseErr != nil {
			continue
		}

		cookies := resp.Cookies()
		_ = resp.Body.Close()
		if len(cookies) == 0 {
			continue
		}

		var flowID string
		if entry.flowID != "" {
			flowID = entry.flowID
		} else {
			flowID = m.service.proxyIndex.Register(entry.offset)
		}

		for _, c := range cookies {
			if nameFilter != "" && c.Name != nameFilter {
				continue
			}

			domain := c.Domain
			if domain == "" {
				domain = entry.host
			}
			// Strip leading dot for consistency
			domain = strings.TrimPrefix(domain, ".")

			if domainFilter != "" && !matchesCookieDomain(domain, domainFilter) {
				continue
			}

			var sameSite string
			switch c.SameSite {
			case http.SameSiteLaxMode:
				sameSite = "Lax"
			case http.SameSiteStrictMode:
				sameSite = "Strict"
			case http.SameSiteNoneMode:
				sameSite = "None"
			}

			var expires string
			if !c.Expires.IsZero() {
				expires = c.Expires.UTC().Format(time.RFC3339)
			} else if c.MaxAge > 0 {
				expires = time.Now().Add(time.Duration(c.MaxAge) * time.Second).UTC().Format(time.RFC3339)
			} else {
				expires = "session"
			}

			// Include value and JWT decode only in detail mode
			var value string
			var decoded *jwt.Result
			if detailMode {
				value = c.Value
				if strings.HasPrefix(c.Value, "eyJ") {
					decoded, _ = jwt.DecodeJWT(c.Value)
				}
			}

			key := cookieKey{name: c.Name, domain: domain}
			if _, exists := seen[key]; !exists {
				order = append(order, key)
			}
			seen[key] = protocol.CookieEntry{
				Name:     c.Name,
				Domain:   domain,
				Path:     c.Path,
				Secure:   c.Secure,
				HttpOnly: c.HttpOnly,
				SameSite: sameSite,
				Expires:  expires,
				Value:    value,
				Decoded:  decoded,
				FlowID:   flowID,
			}
		}
	}

	// Build result in insertion order
	cookies := make([]protocol.CookieEntry, 0, len(order))
	for _, key := range order {
		cookies = append(cookies, seen[key])
	}

	log.Printf("proxy/cookie_jar: %d cookies (name=%q domain=%q)", len(cookies), nameFilter, domainFilter)
	return jsonResult(&protocol.CookieJarResponse{Cookies: cookies})
}

func (m *mcpServer) handleProxyPoll(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	outputMode := req.GetString("output_mode", "summary")

	listReq := &ProxyListRequest{
		Host:         req.GetString("host", ""),
		Path:         req.GetString("path", ""),
		Method:       req.GetString("method", ""),
		Status:       req.GetString("status", ""),
		SearchHeader: req.GetString("search_header", ""),
		SearchBody:   req.GetString("search_body", ""),
		Since:        req.GetString("since", ""),
		ExcludeHost:  req.GetString("exclude_host", ""),
		ExcludePath:  req.GetString("exclude_path", ""),
		Limit:        req.GetInt("limit", 0),
		Offset:       req.GetInt("offset", 0),
		Source:       req.GetString("source", ""),
	}

	// Flows mode requires at least one filter
	if outputMode == OutputModeFlows && !listReq.HasFilters() {
		return errorResult("flows mode requires at least one filter or limit; use output_mode=summary first to see available traffic"), nil
	}

	// Compile search patterns once
	var searchHeaderRe, searchBodyRe *regexp.Regexp
	var notes []string
	if listReq.SearchHeader != "" {
		re, note := compileSearchPattern(listReq.SearchHeader, true)
		searchHeaderRe = re
		if note != "" {
			notes = append(notes, note)
		}
	}
	if listReq.SearchBody != "" {
		re, note := compileSearchPattern(listReq.SearchBody, false)
		searchBodyRe = re
		if note != "" {
			notes = append(notes, note)
		}
	}

	needsFullText := listReq.SearchHeader != "" || listReq.SearchBody != ""
	allEntries, err := m.service.fetchAllProxyEntries(ctx, needsFullText)
	if err != nil {
		return errorResultFromErr("failed to fetch proxy history: ", err), nil
	}

	// Filter out-of-scope domains before user filters
	cfg := m.service.cfg
	if len(cfg.AllowedDomains) > 0 || len(cfg.ExcludeDomains) > 0 {
		allEntries = bulk.SliceFilterInPlace(func(e flowEntry) bool {
			allowed, _ := cfg.IsDomainAllowed(e.host)
			return allowed
		}, allEntries)
	}

	// Get lastFlowID for "since=last" support
	var lastFlowID string
	if v := m.service.lastFlowID.Load(); v != nil {
		lastFlowID = v.(string)
	}
	// Early termination: in flows mode, cap scan at offset+limit matches
	var maxResults int
	if outputMode == OutputModeFlows && listReq.Limit > 0 {
		maxResults = listReq.Offset + listReq.Limit
	}
	filtered := applyProxyFilters(allEntries, listReq, m.service.proxyIndex, m.service.replayHistoryStore, lastFlowID, searchHeaderRe, searchBodyRe, maxResults)

	switch outputMode {
	case OutputModeFlows:
		// Apply offset after filtering
		if listReq.Offset > 0 && listReq.Offset < len(filtered) {
			filtered = filtered[listReq.Offset:]
		} else if listReq.Offset >= len(filtered) {
			filtered = nil
		}

		// Apply limit after offset
		if listReq.Limit > 0 && len(filtered) > listReq.Limit {
			filtered = filtered[:listReq.Limit]
		}

		var maxOffset uint32
		for _, e := range filtered {
			if e.offset > maxOffset {
				maxOffset = e.offset
			}
		}

		flows := make([]protocol.FlowEntry, 0, len(filtered))
		for _, entry := range filtered {
			var flowID string
			if entry.flowID != "" {
				// Replay entry: use pre-assigned flowID (registered at send time)
				flowID = entry.flowID
			} else {
				// Proxy entry: generate flowID based on offset
				flowID = m.service.proxyIndex.Register(entry.offset)
			}

			scheme, port, _ := inferSchemeAndPort(entry.host)

			flows = append(flows, protocol.FlowEntry{
				FlowID:         flowID,
				Method:         entry.method,
				Scheme:         scheme,
				Host:           entry.host,
				Port:           port,
				Path:           util.TruncateString(entry.path, maxPathLength),
				Status:         entry.status,
				ResponseLength: entry.respLen,
				Source:         entry.source,
			})
		}
		log.Printf("proxy/poll: %d flows (host=%q path=%q method=%q status=%q)", len(flows), listReq.Host, listReq.Path, listReq.Method, listReq.Status)

		// Update tracking for "since=last" cursor
		if maxOffset > m.service.proxyLastOffset.Load() {
			m.service.proxyLastOffset.Store(maxOffset)
		}
		if len(flows) > 0 {
			m.service.lastFlowID.Store(flows[len(flows)-1].FlowID)
		}

		noteStr := strings.Join(notes, "; ")
		return jsonResult(&protocol.ProxyPollResponse{Flows: flows, Note: noteStr})

	default: // summary
		agg := aggregateByTuple(filtered, func(e flowEntry) (string, string, string, int) {
			return e.host, e.path, e.method, e.status
		})
		log.Printf("proxy/poll: %d aggregates from %d entries (host=%q path=%q method=%q status=%q)", len(agg), len(filtered), listReq.Host, listReq.Path, listReq.Method, listReq.Status)

		noteStr := strings.Join(notes, "; ")
		return jsonResult(&protocol.ProxyPollResponse{Aggregates: agg, Note: noteStr})
	}
}

func (m *mcpServer) handleProxyGet(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	flowID := req.GetString("flow_id", "")
	if flowID == "" {
		return errorResult("flow_id is required"), nil
	}

	// Hidden parameter for CLI: returns full base64-encoded bodies instead of previews
	fullBody := req.GetBool("full_body", false)
	scopeStr := req.GetString("scope", "")
	patternStr := req.GetString("pattern", "")

	// pattern takes precedence over full_body
	if patternStr != "" {
		fullBody = false
	}

	scopeSet, err := parseScopeSet(scopeStr)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	var patternRe *regexp.Regexp
	var noteStr string
	if patternStr != "" {
		re, note := compileSearchPattern(patternStr, false)
		patternRe = re
		noteStr = note
	}

	resolved, errResult := m.resolveFlow(ctx, flowID)
	if errResult != nil {
		return errResult, nil
	}
	rawReq := resolved.RawRequest
	rawResp := resolved.RawResponse

	// Determine source for logging
	var source string
	if _, ok := m.service.replayHistoryStore.Get(flowID); ok {
		source = SourceReplay
	} else {
		source = SourceProxy
	}

	method, host, path := extractRequestMeta(string(rawReq))
	reqHeaders, reqBody := splitHeadersBody(rawReq)
	respHeaders, respBody := splitHeadersBody(rawResp)
	respCode, respStatusLine := parseResponseStatus(respHeaders)

	// Extract version from request line
	var version string
	if idx := strings.Index(string(rawReq), "\r\n"); idx > 0 {
		if parts := strings.SplitN(string(rawReq[:idx]), " ", 3); len(parts) >= 3 {
			version = parts[2]
		}
	}

	scheme, _, _ := inferSchemeAndPort(host)
	fullURL := scheme + "://" + host + path

	log.Printf("proxy/get: flow=%s method=%s url=%s source=%s", flowID, method, fullURL, source)

	// Decompress bodies lazily: only when scope/pattern needs them
	needsReqBody := scopeSet["request_body"]
	needsRespBody := scopeSet["response_body"]
	var displayReqBody, displayRespBody []byte
	if needsReqBody {
		displayReqBody, _ = decompressForDisplay(reqBody, string(reqHeaders))
	}
	if needsRespBody {
		displayRespBody, _ = decompressForDisplay(respBody, string(respHeaders))
	}

	// Build response map: always include metadata
	result := map[string]interface{}{
		"flow_id":       flowID,
		"method":        method,
		"url":           fullURL,
		"status":        respCode,
		"status_line":   respStatusLine,
		"request_size":  len(reqBody),
		"response_size": len(respBody),
	}

	if patternRe != nil {
		// Pattern mode: grep-like context output
		if scopeSet["request_headers"] {
			if match := extractMatchContext(patternRe, reqHeaders, maxMatchesPerSection); match != "" {
				result["request_headers"] = match
			}
		}
		if needsReqBody {
			if match := extractMatchContext(patternRe, displayReqBody, maxMatchesPerSection); match != "" {
				result["request_body"] = match
			}
		}
		if scopeSet["response_headers"] {
			if match := extractMatchContext(patternRe, respHeaders, maxMatchesPerSection); match != "" {
				result["response_headers"] = match
			}
		}
		if needsRespBody {
			if match := extractMatchContext(patternRe, displayRespBody, maxMatchesPerSection); match != "" {
				result["response_body"] = match
			}
		}
	} else {
		// Standard mode: full content based on scope
		if scopeSet["request_headers"] {
			result["request_headers"] = string(reqHeaders)
			result["request_headers_parsed"] = parseHeadersToMap(string(reqHeaders))
			result["request_line"] = &protocol.RequestLine{Path: path, Version: version}
		}
		if needsReqBody {
			if fullBody {
				result["request_body"] = base64.StdEncoding.EncodeToString(displayReqBody)
			} else {
				result["request_body"] = previewBody(displayReqBody, fullBodyMaxSize, extractHeader(string(reqHeaders), "Content-Type"))
			}
		}
		if scopeSet["response_headers"] {
			result["response_headers"] = string(respHeaders)
			result["response_headers_parsed"] = parseHeadersToMap(string(respHeaders))
		}
		if needsRespBody {
			if fullBody {
				result["response_body"] = base64.StdEncoding.EncodeToString(displayRespBody)
			} else {
				result["response_body"] = previewBody(displayRespBody, fullBodyMaxSize, extractHeader(string(respHeaders), "Content-Type"))
			}
		}
	}

	if noteStr != "" {
		result["note"] = noteStr
	}

	return jsonResult(result)
}

func (m *mcpServer) handleProxyRuleList(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	typeFilter := req.GetString("type_filter", "all")
	limit := req.GetInt("limit", 0)

	var rules []protocol.RuleEntry
	switch typeFilter {
	case "http":
		httpRules, err := m.service.httpBackend.ListRules(ctx, false)
		if err != nil {
			return errorResultFromErr("failed to list HTTP rules: ", err), nil
		}
		rules = httpRules
	case "websocket":
		wsRules, err := m.service.httpBackend.ListRules(ctx, true)
		if err != nil {
			return errorResultFromErr("failed to list WebSocket rules: ", err), nil
		}
		rules = wsRules
	case "all", "":
		httpRules, err := m.service.httpBackend.ListRules(ctx, false)
		if err != nil {
			return errorResultFromErr("failed to list HTTP rules: ", err), nil
		}
		wsRules, err := m.service.httpBackend.ListRules(ctx, true)
		if err != nil {
			return errorResultFromErr("failed to list WebSocket rules: ", err), nil
		}
		rules = append(httpRules, wsRules...)
	default:
		return errorResult("invalid type_filter: must be 'http', 'websocket', or 'all'"), nil
	}

	if limit > 0 && len(rules) > limit {
		rules = rules[:limit]
	}

	log.Printf("proxy/rule_list: %d rules (filter=%s)", len(rules), typeFilter)
	return jsonResult(protocol.RuleListResponse{Rules: rules})
}

func (m *mcpServer) handleProxyRuleAdd(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	ruleType := req.GetString("type", "")
	if ruleType == "" {
		return errorResult("type is required"), nil
	}
	if err := validateRuleTypeAny(ruleType); err != nil {
		return errorResult(err.Error()), nil
	}

	match := req.GetString("match", "")
	replace := req.GetString("replace", "")
	if match == "" && replace == "" {
		return errorResult("match or replace is required"), nil
	}
	label := req.GetString("label", "")

	isRegex := req.GetBool("is_regex", false)
	if isRegex {
		if fixed := unDoubleEscapeRegex(match); fixed != match {
			match = fixed
		}
	}
	rule, err := m.service.httpBackend.AddRule(ctx, ProxyRuleInput{
		Label:   label,
		Type:    ruleType,
		IsRegex: &isRegex,
		Match:   match,
		Replace: replace,
	})
	if err != nil {
		if errors.Is(err, ErrConfigEditDisabled) {
			return errorResult("STOP: Burp config editing is disabled. Proxy rules cannot be added or removed. Ask the user to enable 'Edit config' in MCP Extension, then retry."), nil
		} else if errors.Is(err, ErrLabelExists) {
			return errorResult("label already exists: delete the existing rule first with proxy_rule_delete, or use a different label"), nil
		}
		return errorResultFromErr("failed to add rule: ", err), nil
	}

	log.Printf("proxy/rule_add: created %s type=%s label=%q", rule.RuleID, ruleType, label)
	return jsonResult(rule)
}

func (m *mcpServer) handleProxyRuleDelete(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	ruleID := req.GetString("rule_id", "")
	if ruleID == "" {
		return errorResult("rule_id is required"), nil
	}

	if err := m.service.httpBackend.DeleteRule(ctx, ruleID); err != nil {
		if errors.Is(err, ErrConfigEditDisabled) {
			return errorResult("STOP: Burp config editing is disabled. Proxy rules cannot be added or removed. Ask the user to enable 'Edit config' in MCP Extension, then retry."), nil
		} else if errors.Is(err, ErrNotFound) {
			return errorResult("rule not found"), nil
		}
		return errorResultFromErr("failed to delete rule: ", err), nil
	}

	log.Printf("proxy/rule_delete: deleted rule %s", ruleID)
	return jsonResult(RuleDeleteResponse{})
}

// flowEntry holds parsed metadata for a proxy or replay history entry.
type flowEntry struct {
	offset          uint32
	referenceOffset uint32 // for replays: the proxy offset they follow
	flowID          string // pre-assigned for replays, empty for proxy entries
	method          string
	host            string
	path            string
	status          int
	respLen         int
	request         string
	response        string
	source          string    // "proxy" or "replay"
	timestamp       time.Time // for ordering replays with same reference
}

// fetchAllProxyEntries retrieves all proxy history entries and replay entries, merged in chronological order.
// When needsFullText is false, uses metadata-only APIs (avoids deserializing full request/response bodies).
// When needsFullText is true, loads full entries for search_header/search_body filters.
func (s *Server) fetchAllProxyEntries(ctx context.Context, needsFullText bool) ([]flowEntry, error) {
	var allEntries []flowEntry
	var maxProxyOffset uint32
	var offset uint32

	if needsFullText {
		// Full-text path: need complete request/response for contains filters
		for {
			proxyEntries, err := s.httpBackend.GetProxyHistory(ctx, fetchBatchSize, offset)
			if err != nil {
				return nil, err
			}
			if len(proxyEntries) == 0 {
				break
			}

			for i, entry := range proxyEntries {
				entryOffset := offset + uint32(i)
				if entryOffset > maxProxyOffset {
					maxProxyOffset = entryOffset
				}

				method, host, path := extractRequestMeta(entry.Request)
				status := readResponseStatusCode([]byte(entry.Response))
				_, respBody := splitHeadersBody([]byte(entry.Response))

				allEntries = append(allEntries, flowEntry{
					offset:   entryOffset,
					method:   method,
					host:     host,
					path:     path,
					status:   status,
					respLen:  len(respBody),
					request:  entry.Request,
					response: entry.Response,
					source:   SourceProxy,
				})
			}

			offset += uint32(len(proxyEntries))
			if len(proxyEntries) < fetchBatchSize {
				break
			}
		}
	} else {
		// Metadata-only path: skip full request/response bodies
		for {
			metas, err := s.httpBackend.GetProxyHistoryMeta(ctx, fetchBatchSize, offset)
			if err != nil {
				return nil, err
			}
			if len(metas) == 0 {
				break
			}

			for i, m := range metas {
				entryOffset := offset + uint32(i)
				if entryOffset > maxProxyOffset {
					maxProxyOffset = entryOffset
				}

				allEntries = append(allEntries, flowEntry{
					offset:  entryOffset,
					method:  m.Method,
					host:    m.Host,
					path:    m.Path,
					status:  m.Status,
					respLen: m.RespLen,
					source:  SourceProxy,
				})
			}

			offset += uint32(len(metas))
			if len(metas) < fetchBatchSize {
				break
			}
		}
	}

	// 2. Update replay store's reference tracking (detects history clear)
	if _, cleared := s.replayHistoryStore.UpdateReferenceOffset(maxProxyOffset); cleared {
		// Proxy history was cleared - invalidate stale proxy flow IDs
		s.proxyIndex.Clear()
	}

	// 3. Fetch replay entries and convert to flowEntry
	if needsFullText {
		replayEntries := s.replayHistoryStore.List()
		for _, re := range replayEntries {
			allEntries = append(allEntries, flowEntry{
				offset:          0, // not used for sorting replays
				referenceOffset: re.ReferenceOffset,
				flowID:          re.FlowID,
				method:          re.Method,
				host:            re.Host,
				path:            re.Path,
				status:          re.RespStatus,
				respLen:         len(re.RespBody),
				request:         string(re.RawRequest),
				response:        formatReplayResponse(re.RespHeaders, re.RespBody),
				source:          SourceReplay,
				timestamp:       re.CreatedAt,
			})
		}
	} else {
		replayMetas := s.replayHistoryStore.ListMeta()
		for _, rm := range replayMetas {
			allEntries = append(allEntries, flowEntry{
				offset:          0,
				referenceOffset: rm.ReferenceOffset,
				flowID:          rm.FlowID,
				method:          rm.Method,
				host:            rm.Host,
				path:            rm.Path,
				status:          rm.RespStatus,
				respLen:         rm.RespLen,
				source:          SourceReplay,
				timestamp:       rm.CreatedAt,
			})
		}
	}

	// 4. Sort: merge proxy and replay in chronological order
	sort.SliceStable(allEntries, func(i, j int) bool {
		return compareFlowEntries(allEntries[i], allEntries[j])
	})

	return allEntries, nil
}

// formatReplayResponse combines headers and body for consistent response format.
func formatReplayResponse(headers, body []byte) string {
	return string(headers) + string(body)
}

// compareFlowEntries determines ordering for merged proxy+replay list.
// Proxy entries ordered by offset. Replay entries inserted after their reference offset.
func compareFlowEntries(a, b flowEntry) bool {
	posA := effectivePosition(a)
	posB := effectivePosition(b)

	if posA != posB {
		return posA < posB
	}

	// Same position: proxy before replay, or replays by timestamp
	if a.source != b.source {
		return a.source == SourceProxy
	}

	// Both replays at same reference: order by creation time
	if a.source == SourceReplay {
		return a.timestamp.Before(b.timestamp)
	}

	// Both proxy at same offset (shouldn't happen): maintain order
	return false
}

// effectivePosition returns sort position: proxy uses offset, replay uses referenceOffset+0.5.
// The +0.5 ensures replays sort after the proxy entry at the same offset but before the next offset.
// Multiple replays at the same reference offset then sort by timestamp in compareFlowEntries.
func effectivePosition(e flowEntry) float64 {
	if e.source == SourceProxy {
		return float64(e.offset)
	}
	return float64(e.referenceOffset) + 0.5
}

// applyProxyFilters applies client-side filters to proxy history entries.
// When maxResults > 0, stops after collecting that many matches (early termination for offset+limit).
func applyProxyFilters(entries []flowEntry, req *ProxyListRequest, proxyIndex *store.ProxyIndex, replayHistoryStore *store.ReplayHistoryStore, lastFlowID string, searchHeaderRe, searchBodyRe *regexp.Regexp, maxResults int) []flowEntry {
	if !req.HasFilters() {
		return entries
	}

	methods := parseCommaSeparated(req.Method)
	statuses := parseStatusFilter(req.Status)

	var sincePosition float64
	var sinceTimestamp time.Time
	var sinceIsReplay bool
	var hasSince bool
	if req.Since != "" {
		sinceFlowID := req.Since
		if sinceFlowID == "last" && lastFlowID != "" {
			sinceFlowID = lastFlowID
		} else if sinceFlowID == "last" {
			// No lastFlowID set, skip since filter
			sinceFlowID = ""
		}

		if sinceFlowID != "" {
			if replayEntry, ok := replayHistoryStore.Get(sinceFlowID); ok {
				// Replay entry: get reference offset from replay history store
				sincePosition = float64(replayEntry.ReferenceOffset) + 0.5
				sinceTimestamp = replayEntry.CreatedAt
				sinceIsReplay = true
				hasSince = true
			} else if offset, ok := proxyIndex.Offset(sinceFlowID); ok {
				// Proxy entry: use offset
				sincePosition = float64(offset)
				hasSince = true
			}
		}
	}

	result := entries[:0]
	for _, e := range entries {
		if maxResults > 0 && len(result) >= maxResults {
			break
		}
		if req.Source != "" && req.Source != e.source {
			continue
		}
		// Since filter: compare effective position for both proxy and replay
		if hasSince {
			ePos := effectivePosition(e)
			if ePos < sincePosition {
				continue
			}
			if ePos == sincePosition {
				// Same position: replays at same ReferenceOffset use timestamp
				if sinceIsReplay && e.source == SourceReplay {
					if !e.timestamp.After(sinceTimestamp) {
						continue
					}
				} else {
					continue
				}
			}
		}
		if len(methods) > 0 && !slices.Contains(methods, e.method) {
			continue
		} else if !statuses.Empty() && !statuses.Matches(e.status) {
			continue
		} else if req.Host != "" && !matchesGlob(e.host, req.Host) {
			continue
		} else if req.Path != "" && !matchesGlob(e.path, req.Path) && !matchesGlob(proxy.PathWithoutQuery(e.path), req.Path) {
			continue
		} else if req.ExcludeHost != "" && matchesGlob(e.host, req.ExcludeHost) {
			continue
		} else if req.ExcludePath != "" && matchesGlob(e.path, req.ExcludePath) {
			continue
		}
		if searchHeaderRe != nil || searchBodyRe != nil {
			if !matchesFlowSearch([]byte(e.request), []byte(e.response), searchHeaderRe, searchBodyRe) {
				continue
			}
		}
		result = append(result, e)
	}
	return result
}

var validRuleTypes = map[string]bool{
	// HTTP types
	RuleTypeRequestHeader:  true,
	RuleTypeRequestBody:    true,
	RuleTypeResponseHeader: true,
	RuleTypeResponseBody:   true,
	// WebSocket types
	RuleTypeWSToServer: true,
	RuleTypeWSToClient: true,
	RuleTypeWSBoth:     true,
}

func validateRuleTypeAny(t string) error {
	if !validRuleTypes[t] {
		return fmt.Errorf("invalid rule type %q", t)
	}
	return nil
}

// unDoubleEscapeRegex collapses double-escaped regex metacharacters (\\X → \X).
// LLM agents sometimes produce double-escaped patterns (e.g. \\* instead of \*)
// due to extra JSON encoding of backslashes in tool call arguments.
func unDoubleEscapeRegex(s string) string {
	if !strings.Contains(s, `\\`) {
		return s
	}
	// Regex punctuation metacharacters — always collapse \\X → \X
	const metachars = `.*+?()[]{}^$|/`
	// Regex shorthand class letters (\d, \w, \s, etc.) — only collapse when
	// the \\ pair is not preceded by another backslash, to avoid mangling
	// literal-backslash sequences like \\\\server into \\\server.
	const shorthand = `dDwWsSbBnrtfv`
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if i+2 < len(s) && s[i] == '\\' && s[i+1] == '\\' {
			c := s[i+2]
			if strings.IndexByte(metachars, c) >= 0 {
				b.WriteByte('\\')
				b.WriteByte(c)
				i += 2
				continue
			} else if strings.IndexByte(shorthand, c) >= 0 && (i == 0 || s[i-1] != '\\') {
				b.WriteByte('\\')
				b.WriteByte(c)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

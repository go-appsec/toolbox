package service

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-analyze/bulk"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/jwt"
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sectool/util"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// proxyPollTool builds the proxy_poll definition. extra carries the
// sidecar-conditional adapter/protocol_tag filters, appended only when a sidecar
// is connected so the no-sidecar schema is unchanged.
func (m *mcpServer) proxyPollTool(extra ...mcp.ToolOption) mcp.Tool {
	incremental := `Incremental: since accepts flow_id or "last" (cursor); use to window summaries to recent traffic. Only flows mode advances the cursor. Limit caps results in both modes; offset is for paging flows only.`
	sinceDesc := "Entries after flow_id, or 'last' (cursor)"
	if m.workflowMode == protocol.WorkflowModeMulti {
		incremental = `Incremental: pass a previous flow_id as since to window results to flows after it. Limit caps results in both modes; offset is for paging flows only.`
		sinceDesc = "Entries after this flow_id"
	}
	return mcp.NewTool("proxy_poll", append([]mcp.ToolOption{
		mcp.WithDescription(`Query proxy history: summary (default) or flows mode.

Output modes:
- "summary" (default): Returns traffic grouped by (host, path, method, status). Use first to understand available traffic.
- "flows": Returns individual flows with flow_id for use with flow_get or replay_send. Requires at least one filter or limit.

Results include both proxy-captured traffic (source=proxy) and replay-sent traffic (source=replay) in chronological order.
` + incremental),
		mcp.WithString("output_mode", mcp.Description("Output mode: 'summary' (default) or 'flows'")),
		mcp.WithString("source", mcp.Description("Filter by source: 'proxy', 'replay', or empty for both")),
		mcp.WithString("host", mcp.Description("Filter by host glob (*, ?). *.example.com = subdomains only; *example.com = domain + subdomains")),
		mcp.WithString("path", mcp.Description("Filter by path+query glob (*, ?), e.g. '/api/*'")),
		mcp.WithString("method", mcp.Description("Filter by HTTP method(s), comma-separated (e.g., 'GET,POST')")),
		mcp.WithString("status", mcp.Description("Filter by status code(s) or ranges, comma-separated (e.g., '200,302' or '2XX,4XX')")),
		mcp.WithString("search_header", mcp.Description("Search request/response headers by regex (RE2); literal if invalid")),
		mcp.WithString("search_body", mcp.Description("Search request/response body by regex (RE2, use (?i) for case-insensitive); literal if invalid")),
		mcp.WithString("since", mcp.Description(sinceDesc)),
		mcp.WithString("exclude_host", mcp.Description("Exclude hosts matching glob (*, ?)")),
		mcp.WithString("exclude_path", mcp.Description("Exclude paths matching glob (*, ?)")),
		// adapter/protocol_tag filters appended via extra in syncSidecarTools when a sidecar is connected
		mcp.WithString("parent_flow_id", mcp.Description("Filter to child flows of this parent flow_id (stream children, session inner flows)")),
		mcp.WithNumber("limit", mcp.Description("Max results to return")),
		mcp.WithNumber("offset", mcp.Description("Skip first N results (flows mode, applied after filtering)")),
	}, extra...)...)
}

func (m *mcpServer) flowGetTool() mcp.Tool {
	return mcp.NewTool("flow_get",
		mcp.WithDescription(`Get full request and response for a flow.

Returns headers and body for both request and response. Binary bodies are returned as "<BINARY:N Bytes>" placeholder.
Works with flow_id from any source: proxy_poll, replay_send, request_send, or crawl_poll.

Scope: Sections to return (comma-separated): request_headers, request_body, response_headers, response_body, all (default).
Pattern: Regex search within scoped sections; returns match context instead of full content. Sections without matches are omitted.`),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow identifier")),
		mcp.WithString("scope", mcp.Description("Sections to return (comma-separated): request_headers, request_body, response_headers, response_body, all (default)")),
		mcp.WithString("pattern", mcp.Description("Regex (RE2) search within scoped sections; returns match context instead of full content")),
	)
}

func (m *mcpServer) proxyRuleListTool() mcp.Tool {
	return mcp.NewTool("proxy_rule_list",
		mcp.WithDescription("List proxy find/replace rules. Use type_filter to control which rules are returned."),
		mcp.WithString("type_filter", mcp.Description("Filter by rule type: 'http', 'websocket', or 'all' (default: 'all')")),
		mcp.WithNumber("limit", mcp.Description("Maximum number of rules to return")),
	)
}

// proxyRuleAddTool builds the proxy_rule_add definition. extra carries the
// sidecar-conditional adapter scope param, appended only when a sidecar is
// connected so the no-sidecar schema is unchanged.
func (m *mcpServer) proxyRuleAddTool(extra ...mcp.ToolOption) mcp.Tool {
	return mcp.NewTool("proxy_rule_add", append([]mcp.ToolOption{
		mcp.WithDescription(`Add a proxy rule that modifies request/response traffic.

Modes (determined by which fields are set):
  replace only       append text (e.g. add a new header)
  find + replace     find and replace
  find only          remove matching text

Types:
  HTTP:      request_header (default), request_body, response_header, response_body
  WebSocket: ws:to-server, ws:to-client, ws:both

Use is_regex=true for RE2 regex patterns. Labels must be unique.
To modify a rule, delete it with proxy_rule_delete and recreate.`),
		mcp.WithString("type", mcp.Required(), mcp.Description("Rule type: request_header, request_body, response_header, response_body, ws:to-server, ws:to-client, ws:both")),
		mcp.WithString("find", mcp.Description("Text or pattern to find. Use without replace to remove matches.")),
		mcp.WithString("replace", mcp.Description("Replacement text. Use without find to append instead of replace.")),
		mcp.WithString("label", mcp.Description("Optional unique label (usable as rule_id)")),
		mcp.WithBoolean("is_regex", mcp.Description("Treat find as regex pattern (RE2)")),
		// adapter scope param appended via extra in syncSidecarTools when a sidecar is connected
	}, extra...)...)
}

func (m *mcpServer) proxyRuleDeleteTool() mcp.Tool {
	return mcp.NewTool("proxy_rule_delete",
		mcp.WithDescription("Delete a proxy find/replace rule by rule_id or label (searches HTTP+WS)."),
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
				FlowID:   entry.flowID,
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
		Adapter:      req.GetString("adapter", ""),
		ProtocolTag:  req.GetString("protocol_tag", ""),
		ParentFlowID: req.GetString("parent_flow_id", ""),
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
	// parent_flow_id targets nested children: excluded from the top-level listing,
	// surfaced in emission order only through this dedicated path
	var allEntries []flowEntry
	var err error
	if listReq.ParentFlowID != "" {
		allEntries, err = m.service.fetchProxyChildren(ctx, listReq.ParentFlowID)
	} else {
		allEntries, err = m.service.fetchAllProxyEntries(ctx, needsFullText)
	}
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
	filtered := applyProxyFilters(allEntries, listReq, lastFlowID, searchHeaderRe, searchBodyRe, maxResults)

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

		flows := make([]protocol.FlowEntry, 0, len(filtered))
		for _, entry := range filtered {
			scheme := entry.scheme
			port := entry.port
			if scheme == "" || port == 0 {
				inferredScheme, inferredPort, _ := inferSchemeAndPort(entry.host)
				if scheme == "" {
					scheme = inferredScheme
				}
				if port == 0 {
					port = inferredPort
				}
			}

			flows = append(flows, protocol.FlowEntry{
				FlowID:            entry.flowID,
				Method:            entry.method,
				Scheme:            scheme,
				Host:              entry.host,
				Port:              port,
				Path:              util.TruncateString(entry.path, maxPathLength),
				Status:            entry.status,
				ResponseLength:    entry.respLen,
				Source:            entry.source,
				Adapter:           entry.adapter,
				ProtocolTag:       entry.protocolTag,
				Annotations:       entry.annotations,
				InvokedBy:         entry.invokedBy,
				SidecarInstanceID: entry.sidecarInstanceID,
			})
		}
		m.attachFlowNotes(flows)
		log.Printf("proxy/poll: %d flows (host=%q path=%q method=%q status=%q)", len(flows), listReq.Host, listReq.Path, listReq.Method, listReq.Status)

		if len(flows) > 0 {
			m.service.lastFlowID.Store(flows[len(flows)-1].FlowID)
		}

		noteStr := strings.Join(notes, "; ")
		return jsonResult(&protocol.ProxyPollResponse{Flows: flows, Note: noteStr})

	default: // summary
		agg := aggregateByTuple(filtered, func(e flowEntry) (string, string, string, int) {
			return e.host, e.path, e.method, e.status
		})
		totalCount := len(agg)
		if listReq.Limit > 0 && len(agg) > listReq.Limit {
			agg = agg[:listReq.Limit]
		}
		log.Printf("proxy/poll: %d aggregates from %d entries (host=%q path=%q method=%q status=%q)", len(agg), len(filtered), listReq.Host, listReq.Path, listReq.Method, listReq.Status)

		noteStr := strings.Join(notes, "; ")
		resp := &protocol.ProxyPollResponse{Aggregates: agg, Note: noteStr}
		if listReq.Limit > 0 && totalCount > listReq.Limit {
			resp.TotalCount = totalCount
		}
		return jsonResult(resp)
	}
}

func (m *mcpServer) handleFlowGet(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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
	rawReq := resolved.DisplayRequest()
	rawResp := resolved.RawResponse

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

	scheme := resolved.Scheme
	if scheme == "" {
		scheme, _, _ = inferSchemeAndPort(host)
	}
	fullURL := scheme + "://" + host + path

	log.Printf("flow/get: flow=%s method=%s url=%s source=%s", flowID, method, fullURL, resolved.Source)

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
		"source":        resolved.Source,
		"method":        method,
		"url":           fullURL,
		"status":        respCode,
		"status_line":   respStatusLine,
		"request_size":  len(reqBody),
		"response_size": len(respBody),
	}

	// Streaming flow still in progress: body grows across polls
	if resolved.InProgress {
		result["in_progress"] = true
		result["hint"] = "response still streaming; poll flow_get again for more data"
	}

	// Source-specific metadata
	if resolved.Duration > 0 {
		result["duration"] = resolved.Duration.Round(time.Millisecond).String()
	}
	if resolved.FoundOn != "" {
		result["found_on"] = resolved.FoundOn
	}
	if resolved.Depth > 0 {
		result["depth"] = resolved.Depth
	}
	if resolved.Truncated {
		result["truncated"] = true
	}
	if len(resolved.InterimResponses) > 0 {
		result["interim_responses"] = resolved.InterimResponses
	}
	if len(resolved.Annotations) > 0 {
		result["annotations"] = resolved.Annotations
	}
	if resolved.InvokedBy != "" {
		result["invoked_by"] = resolved.InvokedBy
	}
	if resolved.SidecarInstanceID != "" {
		result["sidecar_instance_id"] = resolved.SidecarInstanceID
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

	find := req.GetString("find", "")
	replace := req.GetString("replace", "")
	if find == "" && replace == "" {
		return errorResult("find or replace is required"), nil
	}
	label := req.GetString("label", "")

	isRegex := req.GetBool("is_regex", false)
	if isRegex {
		if fixed := unDoubleEscapeRegex(find); fixed != find {
			find = fixed
		}
	} else {
		find = unescapeLiteral(find)
		replace = unescapeLiteral(replace)
	}

	// reject a mistyped adapter scope that would orphan the rule;
	// empty scopes all traffic, AdapterScopeCore the native proxy
	adapter := req.GetString("adapter", "")
	if adapter != "" && adapter != types.AdapterScopeCore {
		if m.sidecars == nil || !m.sidecars.HasAdapter(adapter) {
			return errorResult(fmt.Sprintf("unknown adapter %q: not a connected sidecar; omit adapter to scope the rule to all traffic, or use %q for the native proxy", adapter, types.AdapterScopeCore)), nil
		}
	}

	rule, err := m.service.httpBackend.AddRule(ctx, protocol.RuleEntry{
		Label:   label,
		Type:    ruleType,
		IsRegex: isRegex,
		Find:    find,
		Replace: replace,
		Adapter: adapter,
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
	return jsonResult(protocol.RuleDeleteResponse{})
}

// flowEntry holds parsed metadata for a proxy or replay history entry.
type flowEntry struct {
	flowID            string
	timestamp         time.Time // primary sort key; flow_id breaks ties
	method            string
	host              string
	path              string
	scheme            string // "http" or "https" (empty = infer from host)
	port              int    // original port (0 = infer from scheme)
	status            int
	respLen           int
	request           string
	response          string
	source            string         // "proxy" or "replay"
	adapter           string         // emitting adapter name
	protocolTag       string         // protocol tag (e.g. "http/1.1", "http/2")
	annotations       map[string]any // sidecar-authored flow metadata
	invokedBy         string
	sidecarInstanceID string
}

// drainProxyHistory pages all proxy history entries from the backend in fetchBatchSize chunks.
// full=true loads request/response bodies via GetProxyHistory; full=false uses GetProxyHistoryMeta.
func drainProxyHistory(ctx context.Context, backend HttpBackend, full bool) ([]flowEntry, error) {
	var out []flowEntry
	var cursor string
	for {
		var page []flowEntry
		var fetched int // entries returned (incl. placeholders) for paging/termination
		if full {
			entries, err := backend.GetProxyHistory(ctx, fetchBatchSize, cursor)
			if err != nil {
				return nil, err
			}
			fetched = len(entries)
			for _, entry := range entries {
				if entry.Placeholder {
					continue
				}
				method, host, path := extractRequestMeta(entry.Request)
				status := readResponseStatusCode([]byte(entry.Response))
				_, respBody := splitHeadersBody([]byte(entry.Response))
				page = append(page, flowEntry{
					flowID:            entry.FlowID,
					timestamp:         entry.Timestamp,
					method:            method,
					host:              host,
					path:              path,
					scheme:            entry.Scheme,
					port:              entry.Port,
					status:            status,
					respLen:           len(respBody),
					request:           entry.Request,
					response:          entry.Response,
					source:            SourceProxy,
					adapter:           entry.Adapter,
					protocolTag:       entry.Protocol,
					annotations:       entry.Annotations,
					invokedBy:         entry.InvokedBy,
					sidecarInstanceID: entry.SidecarInstanceID,
				})
			}
		} else {
			metas, err := backend.GetProxyHistoryMeta(ctx, fetchBatchSize, cursor)
			if err != nil {
				return nil, err
			}
			fetched = len(metas)
			for _, m := range metas {
				if m.Placeholder {
					continue
				}
				page = append(page, flowEntry{
					flowID:            m.FlowID,
					timestamp:         m.Timestamp,
					method:            m.Method,
					host:              m.Host,
					path:              m.Path,
					scheme:            m.Scheme,
					port:              m.Port,
					status:            m.Status,
					respLen:           m.RespLen,
					source:            SourceProxy,
					adapter:           m.Adapter,
					protocolTag:       m.Protocol,
					annotations:       m.Annotations,
					invokedBy:         m.InvokedBy,
					sidecarInstanceID: m.SidecarInstanceID,
				})
			}
		}
		if fetched == 0 {
			break
		}
		out = append(out, page...)
		if fetched < fetchBatchSize {
			break
		}
		if len(page) == 0 {
			// full page was entirely placeholders: no flow_id to advance past, so paging cannot continue
			log.Printf("proxy history: full page of %d unparseable entries at cursor %q; stopping paging", fetched, cursor)
			break
		}
		cursor = page[len(page)-1].flowID
	}
	return out, nil
}

// collectReplayHistory returns all replay history entries.
// full=true loads request/response bodies via List; full=false uses ListMeta.
func collectReplayHistory(replayStore *store.ReplayHistoryStore, full bool) []flowEntry {
	if full {
		entries := replayStore.List()
		out := make([]flowEntry, len(entries))
		for i, re := range entries {
			out[i] = flowEntry{
				flowID:      re.FlowID,
				timestamp:   re.CreatedAt,
				method:      re.Method,
				host:        re.Host,
				path:        re.Path,
				scheme:      re.Scheme,
				port:        re.Port,
				status:      re.RespStatus,
				respLen:     len(re.RespBody),
				request:     string(re.RawRequest),
				response:    string(re.RespHeaders) + string(re.RespBody),
				source:      SourceReplay,
				adapter:     re.Adapter,
				protocolTag: re.Protocol,
				annotations: re.Annotations,
				invokedBy:   re.InvokedBy,
			}
		}
		return out
	}
	metas := replayStore.ListMeta()
	out := make([]flowEntry, len(metas))
	for i, rm := range metas {
		out[i] = flowEntry{
			flowID:      rm.FlowID,
			timestamp:   rm.CreatedAt,
			method:      rm.Method,
			host:        rm.Host,
			path:        rm.Path,
			scheme:      rm.Scheme,
			port:        rm.Port,
			status:      rm.RespStatus,
			respLen:     rm.RespLen,
			source:      SourceReplay,
			adapter:     rm.Adapter,
			protocolTag: rm.Protocol,
			annotations: rm.Annotations,
			invokedBy:   rm.InvokedBy,
		}
	}
	return out
}

// fetchAllProxyEntries retrieves all proxy history entries and replay entries, merged in chronological order.
// When needsFullText is false, uses metadata-only APIs (avoids deserializing full request/response bodies).
// When needsFullText is true, loads full entries for search_header/search_body filters.
func (s *Server) fetchAllProxyEntries(ctx context.Context, needsFullText bool) ([]flowEntry, error) {
	proxyEntries, err := drainProxyHistory(ctx, s.httpBackend, needsFullText)
	if err != nil {
		return nil, err
	}
	all := append(proxyEntries, collectReplayHistory(s.replayHistoryStore, needsFullText)...)
	// Sort: (timestamp, flow_id) merges proxy and replay chronologically
	slices.SortStableFunc(all, func(a, b flowEntry) int {
		return cmp.Or(a.timestamp.Compare(b.timestamp), cmp.Compare(a.flowID, b.flowID))
	})
	return all, nil
}

// fetchProxyChildren retrieves the child flows of parentFlowID in emission order
// (stream children, session inner flows), which are excluded from the top-level
// listing. Order is preserved as emitted, not re-sorted by timestamp.
func (s *Server) fetchProxyChildren(ctx context.Context, parentFlowID string) ([]flowEntry, error) {
	children, err := s.httpBackend.GetProxyChildren(ctx, parentFlowID)
	if err != nil {
		return nil, err
	}
	out := make([]flowEntry, 0, len(children))
	for _, entry := range children {
		method, host, path := extractRequestMeta(entry.Request)
		status := readResponseStatusCode([]byte(entry.Response))
		_, respBody := splitHeadersBody([]byte(entry.Response))
		out = append(out, flowEntry{
			flowID:            entry.FlowID,
			timestamp:         entry.Timestamp,
			method:            method,
			host:              host,
			path:              path,
			scheme:            entry.Scheme,
			port:              entry.Port,
			status:            status,
			respLen:           len(respBody),
			request:           entry.Request,
			response:          entry.Response,
			source:            SourceProxy,
			adapter:           entry.Adapter,
			protocolTag:       entry.Protocol,
			annotations:       entry.Annotations,
			invokedBy:         entry.InvokedBy,
			sidecarInstanceID: entry.SidecarInstanceID,
		})
	}
	return out, nil
}

// applyProxyFilters applies client-side filters to proxy history entries.
// When maxResults > 0, stops after collecting that many matches (early termination for offset+limit).
func applyProxyFilters(entries []flowEntry, req *ProxyListRequest, lastFlowID string, searchHeaderRe, searchBodyRe *regexp.Regexp, maxResults int) []flowEntry {
	if !req.HasFilters() {
		return entries
	}

	methods := parseCommaSeparated(req.Method)
	statuses := parseStatusFilter(req.Status)

	// Resolve since cursor by linear scan to find the flow_id's index, then drop everything up to and including it
	if req.Since != "" {
		sinceFlowID := req.Since
		if sinceFlowID == sinceLast {
			sinceFlowID = lastFlowID
		}
		if sinceFlowID != "" {
			for i, e := range entries {
				if e.flowID == sinceFlowID {
					entries = entries[i+1:]
					break
				}
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
		} else if req.Adapter != "" && !matchesGlob(e.adapter, req.Adapter) {
			continue
		} else if req.ProtocolTag != "" && !matchesGlob(e.protocolTag, req.ProtocolTag) {
			continue
		}
		// parent_flow_id is a source selector, not a row filter: when set, entries
		// already come from fetchProxyChildren (only that parent's children)
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
	wire.RuleTypeRequestHeader:  true,
	wire.RuleTypeRequestBody:    true,
	wire.RuleTypeResponseHeader: true,
	wire.RuleTypeResponseBody:   true,
	// WebSocket types
	wire.RuleTypeWSToServer: true,
	wire.RuleTypeWSToClient: true,
	wire.RuleTypeWSBoth:     true,
}

func validateRuleTypeAny(t string) error {
	if !validRuleTypes[t] {
		return fmt.Errorf("invalid rule type %q", t)
	}
	return nil
}

package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/go-analyze/bulk"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-harden/llm-security-toolbox/sectool/protocol"
	"github.com/go-harden/llm-security-toolbox/sectool/service/store"
)

func (m *mcpServer) proxyPollTool() mcp.Tool {
	return mcp.NewTool("proxy_poll",
		mcp.WithDescription(`Query proxy history: summary (default) or flows mode.

Output modes:
- "summary" (default): Returns traffic grouped by (host, path, method, status). Use first to understand available traffic.
- "flows": Returns individual flows with flow_id for use with proxy_get or replay_send. Requires at least one filter or limit.

Filters: host/path/exclude_host/exclude_path use glob (*, ?). method/status are comma-separated (status supports ranges like 2XX).
Search: contains searches URL+headers; contains_body searches bodies.
Incremental: since accepts flow_id or "last" (no timestamps). Flows mode only: pagination with limit/offset.`),
		mcp.WithString("output_mode", mcp.Description("Output mode: 'summary' (default) or 'flows'")),
		mcp.WithString("host", mcp.Description("Filter by host (glob pattern, e.g., '*.example.com')")),
		mcp.WithString("path", mcp.Description("Filter by path (glob pattern, e.g., '/api/*')")),
		mcp.WithString("method", mcp.Description("Filter by HTTP method(s), comma-separated (e.g., 'GET,POST')")),
		mcp.WithString("status", mcp.Description("Filter by status code(s) or ranges (e.g., '200,302' or '2XX,4XX')")),
		mcp.WithString("contains", mcp.Description("Filter by text in URL or headers (does not search body)")),
		mcp.WithString("contains_body", mcp.Description("Filter by text in request or response body")),
		mcp.WithString("since", mcp.Description("Entries after flow_id, or 'last' (cursor). No timestamp support.")),
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
Use flow_id from proxy_poll (output_mode=list) to identify the entry.`),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow ID from proxy_poll")),
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
		mcp.WithDescription(`Add proxy match/replace rule. Persists across all traffic (vs replay_send for one-off edits).

Types:
  HTTP:      request_header (default), request_body, response_header, response_body
  WebSocket: ws:to-server, ws:to-client, ws:both

Regex: is_regex=true (Java regex). Labels must be unique.`),
		mcp.WithString("type", mcp.Required(), mcp.Description("Rule type: request_header, request_body, response_header, response_body, ws:to-server, ws:to-client, ws:both")),
		mcp.WithString("match", mcp.Description("Pattern to find")),
		mcp.WithString("replace", mcp.Description("Replacement text")),
		mcp.WithString("label", mcp.Description("Optional unique label (usable as rule_id)")),
		mcp.WithBoolean("is_regex", mcp.Description("Treat match as regex pattern (Java regex syntax)")),
	)
}

func (m *mcpServer) proxyRuleUpdateTool() mcp.Tool {
	return mcp.NewTool("proxy_rule_update",
		mcp.WithDescription(`Update a proxy match/replace rule by rule_id or label (searches HTTP+WS).

Requires at least match or replace. To rename label only, resend existing values with new label.`),
		mcp.WithString("rule_id", mcp.Required(), mcp.Description("Rule ID or label to update")),
		mcp.WithString("type", mcp.Required(), mcp.Description("Rule type: HTTP uses request_header/request_body/response_header/response_body; WebSocket uses ws:to-server/ws:to-client/ws:both")),
		mcp.WithString("match", mcp.Description("Pattern to match")),
		mcp.WithString("replace", mcp.Description("Replacement text")),
		mcp.WithString("label", mcp.Description("Optional new label (unique); omit to keep existing")),
		mcp.WithBoolean("is_regex", mcp.Description("Treat match as regex pattern (Java regex syntax)")),
	)
}

func (m *mcpServer) proxyRuleDeleteTool() mcp.Tool {
	return mcp.NewTool("proxy_rule_delete",
		mcp.WithDescription("Delete a proxy match/replace rule by rule_id or label (searches HTTP+WS)."),
		mcp.WithString("rule_id", mcp.Required(), mcp.Description("Rule ID or label to delete")),
	)
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
		Contains:     req.GetString("contains", ""),
		ContainsBody: req.GetString("contains_body", ""),
		Since:        req.GetString("since", ""),
		ExcludeHost:  req.GetString("exclude_host", ""),
		ExcludePath:  req.GetString("exclude_path", ""),
		Limit:        req.GetInt("limit", 0),
		Offset:       req.GetInt("offset", 0),
	}

	// Flows mode requires at least one filter
	if outputMode == "flows" && !listReq.HasFilters() {
		return errorResult("flows mode requires at least one filter or limit; use output_mode=summary first to see available traffic"), nil
	}

	log.Printf("proxy/poll: mode=%s host=%q path=%q method=%q status=%q", outputMode, listReq.Host, listReq.Path, listReq.Method, listReq.Status)

	allEntries, err := m.service.fetchAllProxyEntries(ctx)
	if err != nil {
		return errorResult("failed to fetch proxy history: " + err.Error()), nil
	}

	lastOffset := m.service.proxyLastOffset.Load()
	filtered := applyProxyFilters(allEntries, listReq, m.service.flowStore, lastOffset)

	switch outputMode {
	case "flows":
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
			headerLines := extractHeaderLines(entry.request)
			_, reqBody := splitHeadersBody([]byte(entry.request))
			hash := store.ComputeFlowHashSimple(entry.method, entry.host, entry.path, headerLines, reqBody)
			flowID := m.service.flowStore.Register(entry.offset, hash)

			scheme, port, _ := inferSchemeAndPort(entry.host)

			flows = append(flows, protocol.FlowEntry{
				FlowID:         flowID,
				Method:         entry.method,
				Scheme:         scheme,
				Host:           entry.host,
				Port:           port,
				Path:           truncateString(entry.path, maxPathLength),
				Status:         entry.status,
				ResponseLength: entry.respLen,
			})
		}
		log.Printf("proxy/poll: returning %d flows", len(flows))

		if maxOffset > lastOffset {
			m.service.proxyLastOffset.Store(maxOffset)
		}

		return jsonResult(&protocol.ProxyPollResponse{Flows: flows})

	default: // summary
		agg := aggregateByTuple(filtered, func(e flowEntry) (string, string, string, int) {
			return e.host, e.path, e.method, e.status
		})
		log.Printf("proxy/poll: returning %d aggregates from %d entries", len(agg), len(filtered))

		return jsonResult(&protocol.ProxyPollResponse{Aggregates: agg})
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

	entry, ok := m.service.flowStore.Lookup(flowID)
	if !ok {
		return errorResult("flow_id not found: run proxy_poll to see available flows"), nil
	}

	proxyEntries, err := m.service.httpBackend.GetProxyHistory(ctx, 1, entry.Offset)
	if err != nil {
		return errorResult("failed to fetch flow: " + err.Error()), nil
	}
	if len(proxyEntries) == 0 {
		return errorResult("flow not found in proxy history"), nil
	}

	rawReq := []byte(proxyEntries[0].Request)
	rawResp := []byte(proxyEntries[0].Response)

	method, host, path := extractRequestMeta(proxyEntries[0].Request)
	reqHeaders, reqBody := splitHeadersBody(rawReq)
	respHeaders, respBody := splitHeadersBody(rawResp)
	respCode, respStatusLine := parseResponseStatus(respHeaders)

	// Extract version from request line
	var version string
	if idx := strings.Index(proxyEntries[0].Request, "\r\n"); idx > 0 {
		if parts := strings.SplitN(proxyEntries[0].Request[:idx], " ", 3); len(parts) >= 3 {
			version = parts[2]
		}
	}

	scheme, _, _ := inferSchemeAndPort(host)
	fullURL := scheme + "://" + host + path

	log.Printf("mcp/proxy_get: flow=%s method=%s url=%s", flowID, method, fullURL)

	// Format bodies based on full_body flag
	var reqBodyStr, respBodyStr string
	if fullBody {
		reqBodyStr = base64.StdEncoding.EncodeToString(reqBody)
		respBodyStr = base64.StdEncoding.EncodeToString(respBody)
	} else {
		reqBodyStr = previewBody(reqBody, fullBodyMaxSize)
		respBodyStr = previewBody(respBody, fullBodyMaxSize)
	}

	return jsonResult(protocol.ProxyGetResponse{
		FlowID:            flowID,
		Method:            method,
		URL:               fullURL,
		ReqHeaders:        string(reqHeaders),
		ReqHeadersParsed:  parseHeadersToMap(string(reqHeaders)),
		ReqLine:           &protocol.RequestLine{Path: path, Version: version},
		ReqBody:           reqBodyStr,
		ReqSize:           len(reqBody),
		Status:            respCode,
		StatusLine:        respStatusLine,
		RespHeaders:       string(respHeaders),
		RespHeadersParsed: parseHeadersToMap(string(respHeaders)),
		RespBody:          respBodyStr,
		RespSize:          len(respBody),
	})
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
			return errorResult("failed to list HTTP rules: " + err.Error()), nil
		}
		rules = httpRules
	case "websocket":
		wsRules, err := m.service.httpBackend.ListRules(ctx, true)
		if err != nil {
			return errorResult("failed to list WebSocket rules: " + err.Error()), nil
		}
		rules = wsRules
	case "all", "":
		httpRules, err := m.service.httpBackend.ListRules(ctx, false)
		if err != nil {
			return errorResult("failed to list HTTP rules: " + err.Error()), nil
		}
		wsRules, err := m.service.httpBackend.ListRules(ctx, true)
		if err != nil {
			return errorResult("failed to list WebSocket rules: " + err.Error()), nil
		}
		rules = append(httpRules, wsRules...)
	default:
		return errorResult("invalid type_filter: must be 'http', 'websocket', or 'all'"), nil
	}

	if limit > 0 && len(rules) > limit {
		rules = rules[:limit]
	}

	log.Printf("mcp/proxy_rule_list: returning %d rules (filter=%s)", len(rules), typeFilter)
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

	log.Printf("mcp/proxy_rule_add: type=%s label=%q", ruleType, label)

	isRegex := req.GetBool("is_regex", false)
	rule, err := m.service.httpBackend.AddRule(ctx, ProxyRuleInput{
		Label:   label,
		Type:    ruleType,
		IsRegex: &isRegex,
		Match:   match,
		Replace: replace,
	})
	if err != nil {
		if errors.Is(err, ErrLabelExists) {
			return errorResult("label already exists: " + err.Error()), nil
		}
		return errorResult("failed to add rule: " + err.Error()), nil
	}

	log.Printf("mcp/proxy_rule_add: created rule %s", rule.RuleID)
	return jsonResult(rule)
}

func (m *mcpServer) handleProxyRuleUpdate(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	ruleID := req.GetString("rule_id", "")
	if ruleID == "" {
		return errorResult("rule_id is required"), nil
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

	// Only set IsRegex if explicitly provided in request
	var isRegex *bool
	if args := req.GetArguments(); args != nil {
		if _, ok := args["is_regex"]; ok {
			v := req.GetBool("is_regex", false)
			isRegex = &v
		}
	}

	rule, err := m.service.httpBackend.UpdateRule(ctx, ruleID, ProxyRuleInput{
		Label:   req.GetString("label", ""),
		Type:    ruleType,
		IsRegex: isRegex,
		Match:   match,
		Replace: replace,
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("rule not found"), nil
		}
		if errors.Is(err, ErrLabelExists) {
			return errorResult("label already exists: " + err.Error()), nil
		}
		return errorResult("failed to update rule: " + err.Error()), nil
	}

	log.Printf("mcp/proxy_rule_update: updated rule %s", rule.RuleID)
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
		if errors.Is(err, ErrNotFound) {
			return errorResult("rule not found"), nil
		}
		return errorResult("failed to delete rule: " + err.Error()), nil
	}

	log.Printf("mcp/proxy_rule_delete: deleted rule %s", ruleID)
	return jsonResult(RuleDeleteResponse{})
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

// fetchAllProxyEntries retrieves all proxy history entries from the backend.
func (s *Server) fetchAllProxyEntries(ctx context.Context) ([]flowEntry, error) {
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
	return allEntries, nil
}

// applyProxyFilters applies filters that can't be expressed in Burp regex.
func applyProxyFilters(entries []flowEntry, req *ProxyListRequest, flowStore *store.FlowStore, lastOffset uint32) []flowEntry {
	if !req.HasFilters() {
		return entries
	}

	methods := parseCommaSeparated(req.Method)
	statuses := parseStatusFilter(req.Status)

	var sinceOffset uint32
	var hasSince bool
	if req.Since != "" {
		if req.Since == "last" {
			sinceOffset = lastOffset
			hasSince = true
		} else if entry, ok := flowStore.Lookup(req.Since); ok {
			sinceOffset = entry.Offset
			hasSince = true
		}
	}

	return bulk.SliceFilter(func(e flowEntry) bool {
		if hasSince && e.offset <= sinceOffset {
			return false // Since filter (exclusive - only entries after)
		} else if len(methods) > 0 && !slices.Contains(methods, e.method) {
			return false // Method filter
		} else if !statuses.Empty() && !statuses.Matches(e.status) {
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
			// Search URL and headers only (not body)
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

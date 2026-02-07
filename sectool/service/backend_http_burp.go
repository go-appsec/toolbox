package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/go-appsec/llm-security-toolbox/sectool/protocol"
	"github.com/go-appsec/llm-security-toolbox/sectool/service/ids"
	"github.com/go-appsec/llm-security-toolbox/sectool/service/mcp"
)

// BurpBackend implements HttpBackend using Burp Suite via MCP.
type BurpBackend struct {
	client *mcp.BurpClient
}

// Compile-time check that BurpBackend implements HttpBackend
var _ HttpBackend = (*BurpBackend)(nil)

// NewBurpBackend creates a new Burp HttpBackend with the given MCP URL.
func NewBurpBackend(url string, opts ...mcp.Option) *BurpBackend {
	return &BurpBackend{
		client: mcp.New(url, opts...),
	}
}

func (b *BurpBackend) Connect(ctx context.Context) error {
	b.client.OnConnectionLost(func(err error) {
		log.Printf("Burp MCP connection lost: %v", err)
	})
	if err := b.client.Connect(ctx); err != nil {
		return err
	}
	return nil
}

func (b *BurpBackend) Close() error {
	return b.client.Close()
}

func (b *BurpBackend) GetProxyHistory(ctx context.Context, count int, offset uint32) ([]ProxyEntry, error) {
	log.Printf("burp: sending proxy history offset: %d", offset)

	entries, err := b.client.GetProxyHistory(ctx, count, int(offset))
	if err != nil {
		return nil, err
	}

	result := make([]ProxyEntry, len(entries))
	for i, e := range entries {
		result[i] = ProxyEntry{
			Request:  e.Request,
			Response: e.Response,
			Notes:    e.Notes,
		}
	}
	return result, nil
}

func (b *BurpBackend) GetProxyHistoryMeta(ctx context.Context, count int, offset uint32) ([]ProxyEntryMeta, error) {
	entries, err := b.GetProxyHistory(ctx, count, offset)
	if err != nil {
		return nil, err
	}
	result := make([]ProxyEntryMeta, len(entries))
	for i, e := range entries {
		method, host, path := extractRequestMeta(e.Request)
		status := readResponseStatusCode([]byte(e.Response))
		_, respBody := splitHeadersBody([]byte(e.Response))
		result[i] = ProxyEntryMeta{
			Method:   method,
			Host:     host,
			Path:     path,
			Status:   status,
			RespLen:  len(respBody),
			Protocol: e.Protocol,
		}
	}
	return result, nil
}

func (b *BurpBackend) SendRequest(ctx context.Context, name string, req SendRequestInput) (*SendRequestResult, error) {
	scheme := schemeHTTP
	if req.Target.UsesHTTPS {
		scheme = schemeHTTPS
	}
	log.Printf("burp: sending request %s to %s://%s:%d (follow_redirects=%v)",
		name, scheme, req.Target.Hostname, req.Target.Port, req.FollowRedirects)

	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	return b.doSendRequest(ctx, name, req)
}

// doSendRequest builds a closure that creates a Repeater tab for every request
// (including redirect hops) and sends via the appropriate protocol.
func (b *BurpBackend) doSendRequest(ctx context.Context, name string, req SendRequestInput) (*SendRequestResult, error) {
	// Build descriptive tab name: st-domain/path [id]
	reqPath := extractRequestPath(req.RawRequest)
	if len(reqPath) > 8 {
		reqPath = reqPath[:8] + ".."
	}
	// Extract domain+TLD only (strip subdomains), but keep IP addresses intact
	domain := req.Target.Hostname
	if net.ParseIP(domain) == nil {
		parts := strings.Split(domain, ".")
		if len(parts) > 2 {
			// Handle multipart TLDs like co.uk: if second-to-last is short, keep 3 parts
			if len(parts[len(parts)-2]) <= 3 {
				domain = strings.Join(parts[len(parts)-3:], ".")
			} else {
				domain = strings.Join(parts[len(parts)-2:], ".")
			}
		}
	}
	id := strings.TrimPrefix(name, "sectool-")

	// Track redirect hop count for tab naming
	var hopCount int

	// Closure creates a Repeater tab and sends for every request including redirect hops
	sender := func(ctx context.Context, r SendRequestInput, start time.Time) (*SendRequestResult, error) {
		tabName := fmt.Sprintf("st-%s%s [%s]", domain, reqPath, id)
		if hopCount > 0 {
			tabName = fmt.Sprintf("st-%s%s [%s R%d]", domain, reqPath, id, hopCount)
		}
		hopCount++
		return b.sendWithRepeater(ctx, tabName, r, start)
	}

	start := time.Now()

	if req.FollowRedirects {
		return FollowRedirects(ctx, req, start, 10, sender)
	}
	return sender(ctx, req, start)
}

// sendWithRepeater creates a Repeater tab (best-effort) and sends the request
// using the appropriate protocol (H1 or H2).
func (b *BurpBackend) sendWithRepeater(ctx context.Context, tabName string, req SendRequestInput, start time.Time) (*SendRequestResult, error) {
	// Best-effort Repeater tab creation
	if err := b.client.CreateRepeaterTab(ctx, mcp.RepeaterTabParams{
		TabName:        tabName,
		Content:        string(req.RawRequest),
		TargetHostname: req.Target.Hostname,
		TargetPort:     req.Target.Port,
		UsesHTTPS:      req.Target.UsesHTTPS,
	}); err != nil {
		log.Printf("burp: failed to create repeater tab %q (continuing): %v", tabName, err)
	}

	// Route to appropriate send method
	var rawResponse string
	var err error
	if req.Protocol == "h2" {
		params := rawRequestToH2Params(req.RawRequest, req.Target)
		rawResponse, err = b.client.SendHTTP2Request(ctx, params)
	} else {
		rawResponse, err = b.client.SendHTTP1Request(ctx, mcp.SendRequestParams{
			Content:        string(req.RawRequest),
			TargetHostname: req.Target.Hostname,
			TargetPort:     req.Target.Port,
			UsesHTTPS:      req.Target.UsesHTTPS,
		})
	}
	if err != nil {
		return nil, err
	}

	headers, body, parseErr := parseBurpResponse(rawResponse)
	if parseErr != nil {
		return &SendRequestResult{
			Headers:  []byte(rawResponse),
			Body:     nil,
			Duration: time.Since(start),
		}, nil
	}

	return &SendRequestResult{
		Headers:  headers,
		Body:     body,
		Duration: time.Since(start),
	}, nil
}

// rawRequestToH2Params converts raw HTTP/1.1-format request bytes to H2 params.
// Extracts method and path from the request line, maps Host to :authority,
// and lowercases header names per H2 convention.
func rawRequestToH2Params(raw []byte, target Target) mcp.SendHTTP2RequestParams {
	// Extract request URI from first line
	requestURI := "/"
	lines := bytes.SplitN(raw, []byte("\r\n"), 2)
	if len(lines) > 0 {
		lineParts := bytes.SplitN(lines[0], []byte(" "), 3)
		if len(lineParts) >= 2 {
			requestURI = string(lineParts[1])
		}
	}

	scheme := schemeHTTPS
	if !target.UsesHTTPS {
		scheme = schemeHTTP
	}

	pseudos := map[string]string{
		":method": extractMethod(raw),
		":path":   requestURI,
		":scheme": scheme,
	}

	headers := make(map[string]string)
	for _, line := range extractHeaderLines(string(raw)) {
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		lower := strings.ToLower(name)
		if lower == "host" {
			pseudos[":authority"] = value
			continue
		}
		headers[lower] = value
	}

	// Ensure :authority is set from target if not in headers
	if _, ok := pseudos[":authority"]; !ok {
		host := target.Hostname
		if (target.UsesHTTPS && target.Port != 443) || (!target.UsesHTTPS && target.Port != 80) {
			host = fmt.Sprintf("%s:%d", target.Hostname, target.Port)
		}
		pseudos[":authority"] = host
	}

	_, body := splitHeadersBody(raw)

	return mcp.SendHTTP2RequestParams{
		PseudoHeaders:  pseudos,
		Headers:        headers,
		RequestBody:    string(body),
		TargetHostname: target.Hostname,
		TargetPort:     target.Port,
		UsesHTTPS:      target.UsesHTTPS,
	}
}

// parseBurpResponse extracts HTTP response from Burp's toString format.
// Format: HttpRequestResponse{httpRequest=..., httpResponse=..., messageAnnotations=...}
func parseBurpResponse(raw string) (headers, body []byte, err error) {
	// Find httpResponse section
	start := strings.Index(raw, "httpResponse=")
	if start < 0 {
		return nil, nil, errors.New("httpResponse not found in Burp output")
	}
	start += len("httpResponse=")

	// Find the end - could be ", messageAnnotations=" or just "}"
	end := strings.Index(raw[start:], ", messageAnnotations=")
	if end < 0 {
		end = strings.LastIndex(raw[start:], "}")
	}
	if end < 0 {
		return nil, nil, errors.New("could not find end of httpResponse")
	}

	response := raw[start : start+end]

	// Convert escaped newlines to actual CRLF bytes
	responseBytes := bytes.ReplaceAll([]byte(response), []byte(`\r\n`), []byte("\r\n"))

	// Look for the HTTP/ prefix to validate we found the response
	if !bytes.Contains(responseBytes, []byte("HTTP/")) {
		return nil, nil, errors.New("invalid response format: no HTTP/ found")
	}

	headers, body = splitHeadersBody(responseBytes)
	return
}

// SetInterceptState exposes Burp-specific intercept control.
// This is not part of the HttpBackend interface as it's Burp-specific.
func (b *BurpBackend) SetInterceptState(ctx context.Context, intercepting bool) error {
	return b.client.SetInterceptState(ctx, intercepting)
}

// sectool comment prefix identifies rules managed by sectool
const sectoolRulePrefix = "sectool:"

func (b *BurpBackend) ListRules(ctx context.Context, websocket bool) ([]protocol.RuleEntry, error) {
	burpRules, err := b.getAllRules(ctx, websocket)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}

	rules := make([]protocol.RuleEntry, 0, len(burpRules))
	for _, r := range burpRules {
		if !r.Enabled {
			continue
		}
		id, label, ok := parseSectoolComment(r.Comment)
		if !ok {
			continue
		}

		// Convert Burp's format to ws: prefixed types for WebSocket rules
		ruleType := r.RuleType
		if websocket {
			ruleType = burpToWSType(r.RuleType)
		}

		rules = append(rules, protocol.RuleEntry{
			RuleID:  id,
			Label:   label,
			Type:    ruleType,
			IsRegex: r.Category == mcp.RuleCategoryRegex,
			Match:   r.StringMatch,
			Replace: r.StringReplace,
		})
	}
	return rules, nil
}

func (b *BurpBackend) AddRule(ctx context.Context, input ProxyRuleInput) (*protocol.RuleEntry, error) {
	httpRules, err := b.getAllRules(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("add rule: %w", err)
	}
	wsRules, err := b.getAllRules(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("add rule: %w", err)
	}

	if input.Label != "" {
		if err := b.checkLabelUnique(input.Label, "", httpRules, wsRules); err != nil {
			return nil, err
		}
	}

	websocket := isWSType(input.Type)
	burpRules := httpRules
	if websocket {
		burpRules = wsRules
	}

	// Convert ws: prefixed types to Burp's format
	ruleType := input.Type
	if websocket {
		ruleType = wsToBurpType(input.Type)
	}

	id := ids.Generate(0)
	newRule := mcp.MatchReplaceRule{
		Category:      mcp.RuleCategoryLiteral,
		Comment:       formatSectoolComment(id, input.Label),
		Enabled:       true,
		RuleType:      ruleType,
		StringMatch:   input.Match,
		StringReplace: input.Replace,
	}
	if input.IsRegex != nil && *input.IsRegex {
		newRule.Category = mcp.RuleCategoryRegex
	}

	burpRules = append(burpRules, newRule)
	if err := b.setAllRules(ctx, websocket, burpRules); err != nil {
		return nil, fmt.Errorf("add rule: %w", err)
	}

	return &protocol.RuleEntry{
		RuleID:  id,
		Label:   input.Label,
		Type:    input.Type,
		IsRegex: newRule.Category == mcp.RuleCategoryRegex,
		Match:   input.Match,
		Replace: input.Replace,
	}, nil
}

func (b *BurpBackend) UpdateRule(ctx context.Context, idOrLabel string, input ProxyRuleInput) (*protocol.RuleEntry, error) {
	httpRules, err := b.getAllRules(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("update rule: %w", err)
	}
	wsRules, err := b.getAllRules(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("update rule: %w", err)
	}

	// Search HTTP rules first
	if idx := b.findRuleIndex(httpRules, idOrLabel); idx >= 0 {
		return b.updateRuleInSet(ctx, false, httpRules, idx, input, httpRules, wsRules)
	}
	// Search WebSocket rules
	if idx := b.findRuleIndex(wsRules, idOrLabel); idx >= 0 {
		return b.updateRuleInSet(ctx, true, wsRules, idx, input, httpRules, wsRules)
	}

	return nil, ErrNotFound
}

func (b *BurpBackend) updateRuleInSet(ctx context.Context, websocket bool, rules []mcp.MatchReplaceRule, idx int, input ProxyRuleInput, httpRules, wsRules []mcp.MatchReplaceRule) (*protocol.RuleEntry, error) {
	id, existingLabel, _ := parseSectoolComment(rules[idx].Comment)

	// Preserve existing label if none provided
	label := input.Label
	if label == "" {
		label = existingLabel
	}

	if label != "" && label != existingLabel {
		if err := b.checkLabelUnique(label, id, httpRules, wsRules); err != nil {
			return nil, err
		}
	}

	// Validate type matches rule category (ws:* for WebSocket, HTTP types for HTTP)
	ruleType := input.Type
	if websocket {
		if !isWSType(input.Type) {
			return nil, fmt.Errorf("cannot update WebSocket rule with HTTP type %q: use ws:to-server, ws:to-client, or ws:both", input.Type)
		}
		ruleType = wsToBurpType(input.Type)
	} else {
		if isWSType(input.Type) {
			return nil, fmt.Errorf("cannot update HTTP rule with WebSocket type %q", input.Type)
		}
	}

	rules[idx].Comment = formatSectoolComment(id, label)
	rules[idx].RuleType = ruleType
	rules[idx].StringMatch = input.Match
	rules[idx].StringReplace = input.Replace
	// Only change category if IsRegex was explicitly provided
	if input.IsRegex != nil {
		if *input.IsRegex {
			rules[idx].Category = mcp.RuleCategoryRegex
		} else {
			rules[idx].Category = mcp.RuleCategoryLiteral
		}
	}

	if err := b.setAllRules(ctx, websocket, rules); err != nil {
		return nil, fmt.Errorf("update rule: %w", err)
	}

	return &protocol.RuleEntry{
		RuleID:  id,
		Label:   label,
		Type:    input.Type,
		IsRegex: rules[idx].Category == mcp.RuleCategoryRegex,
		Match:   input.Match,
		Replace: input.Replace,
	}, nil
}

func (b *BurpBackend) DeleteRule(ctx context.Context, idOrLabel string) error {
	// Try HTTP rules first
	httpRules, err := b.getAllRules(ctx, false)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}

	if idx := b.findRuleIndex(httpRules, idOrLabel); idx >= 0 {
		httpRules = append(httpRules[:idx], httpRules[idx+1:]...)
		if err := b.setAllRules(ctx, false, httpRules); err != nil {
			return fmt.Errorf("delete rule: %w", err)
		}
		return nil
	}

	// Try WebSocket rules
	wsRules, err := b.getAllRules(ctx, true)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}

	if idx := b.findRuleIndex(wsRules, idOrLabel); idx >= 0 {
		wsRules = append(wsRules[:idx], wsRules[idx+1:]...)
		if err := b.setAllRules(ctx, true, wsRules); err != nil {
			return fmt.Errorf("delete rule: %w", err)
		}
		return nil
	}

	return ErrNotFound
}

func (b *BurpBackend) getAllRules(ctx context.Context, websocket bool) ([]mcp.MatchReplaceRule, error) {
	if websocket {
		return b.client.GetWSMatchReplaceRules(ctx)
	}
	return b.client.GetMatchReplaceRules(ctx)
}

func (b *BurpBackend) setAllRules(ctx context.Context, websocket bool, rules []mcp.MatchReplaceRule) error {
	var err error
	if websocket {
		err = b.client.SetWSMatchReplaceRules(ctx, rules)
	} else {
		err = b.client.SetMatchReplaceRules(ctx, rules)
	}
	if errors.Is(err, mcp.ErrConfigEditingDisabled) {
		return fmt.Errorf("%w; enable 'Edit config' in Burp's MCP settings", err)
	}
	return err
}

func (b *BurpBackend) findRuleIndex(rules []mcp.MatchReplaceRule, idOrLabel string) int {
	return slices.IndexFunc(rules, func(r mcp.MatchReplaceRule) bool {
		id, label, ok := parseSectoolComment(r.Comment)
		return ok && (id == idOrLabel || label == idOrLabel)
	})
}

// wsToBurpType converts ws: prefixed types to Burp's WebSocket rule_type values.
func wsToBurpType(wsType string) string {
	switch wsType {
	case "ws:to-server":
		return "client_to_server"
	case "ws:to-client":
		return "server_to_client"
	case "ws:both":
		return "both_directions"
	default:
		return wsType // pass through unknown types
	}
}

// burpToWSType converts Burp's WebSocket rule_type values to ws: prefixed types.
func burpToWSType(burpType string) string {
	switch burpType {
	case "client_to_server":
		return "ws:to-server"
	case "server_to_client":
		return "ws:to-client"
	case "both_directions":
		return "ws:both"
	default:
		return burpType // pass through unknown types
	}
}

// checkLabelUnique verifies a label is unique across both HTTP and WS rules.
// excludeID allows skipping a rule being updated.
func (b *BurpBackend) checkLabelUnique(label, excludeID string, httpRules, wsRules []mcp.MatchReplaceRule) error {
	for _, rules := range [][]mcp.MatchReplaceRule{httpRules, wsRules} {
		for _, r := range rules {
			id, existingLabel, ok := parseSectoolComment(r.Comment)
			if !ok || (excludeID != "" && id == excludeID) {
				continue
			}
			if existingLabel == label {
				return fmt.Errorf("%w: %s", ErrLabelExists, label)
			}
		}
	}
	return nil
}

// formatSectoolComment creates a comment string from ID and optional label.
func formatSectoolComment(id, label string) string {
	if label == "" {
		return sectoolRulePrefix + id
	}
	return sectoolRulePrefix + id + ":" + label
}

// parseSectoolComment extracts ID and optional label from a sectool comment.
// Format: "sectool:id" or "sectool:id:label"
func parseSectoolComment(comment string) (id, label string, ok bool) {
	if !strings.HasPrefix(comment, sectoolRulePrefix) {
		return "", "", false
	}
	rest := comment[len(sectoolRulePrefix):]
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) == 0 || parts[0] == "" {
		return "", "", false
	}
	id = parts[0]
	if len(parts) > 1 {
		label = parts[1]
	}
	return id, label, true
}

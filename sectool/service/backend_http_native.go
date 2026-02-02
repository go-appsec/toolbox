package service

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-appsec/llm-security-toolbox/sectool/protocol"
	"github.com/go-appsec/llm-security-toolbox/sectool/service/ids"
	"github.com/go-appsec/llm-security-toolbox/sectool/service/proxy"
)

// NativeProxyBackend implements HttpBackend using the native proxy.
// This backend provides wire-level fidelity for security testing including
// HTTP/1.1 and HTTP/2 support with header order preservation.
type NativeProxyBackend struct {
	server *proxy.ProxyServer

	// Rules (managed by service layer, applied in future phase)
	rulesMu   sync.RWMutex
	httpRules []nativeStoredRule
	wsRules   []nativeStoredRule

	closed atomic.Bool
}

// nativeStoredRule is the persistent format for rules.
type nativeStoredRule struct {
	ID      string `json:"id"`
	Label   string `json:"label,omitempty"`
	Type    string `json:"type"`
	IsRegex bool   `json:"is_regex"`
	Match   string `json:"match"`
	Replace string `json:"replace"`

	// compiled is the pre-compiled regex (nil if not a regex rule)
	compiled *regexp.Regexp
}

// Compile-time checks that NativeProxyBackend implements interfaces.
var _ HttpBackend = (*NativeProxyBackend)(nil)
var _ proxy.RuleApplier = (*NativeProxyBackend)(nil)

// NewNativeProxyBackend creates a new native proxy backend.
// Does NOT start serving - call Serve() separately (typically in a goroutine).
func NewNativeProxyBackend(port int, configDir string, maxBodyBytes int) (*NativeProxyBackend, error) {
	server, err := proxy.NewProxyServer(port, configDir, maxBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("create proxy server: %w", err)
	}

	b := &NativeProxyBackend{
		server: server,
	}

	// Wire backend as rule applier for the proxy handlers
	server.SetRuleApplier(b)

	return b, nil
}

// Serve starts the proxy server. Call in a goroutine.
func (b *NativeProxyBackend) Serve() error {
	return b.server.Serve()
}

// Addr returns the proxy listen address.
func (b *NativeProxyBackend) Addr() string {
	return b.server.Addr()
}

// WaitReady blocks until Serve() has entered its accept loop.
func (b *NativeProxyBackend) WaitReady(ctx context.Context) error {
	return b.server.WaitReady(ctx)
}

func (b *NativeProxyBackend) Close() error {
	if b.closed.Swap(true) {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return b.server.Shutdown(ctx)
}

// CACert returns the CA certificate used for MITM TLS interception.
func (b *NativeProxyBackend) CACert() *x509.Certificate {
	return b.server.CertManager().CACert()
}

func (b *NativeProxyBackend) GetProxyHistory(ctx context.Context, count int, offset uint32) ([]ProxyEntry, error) {
	entries := b.server.History().List(count, offset)

	result := make([]ProxyEntry, 0, len(entries))
	for _, entry := range entries {
		// Use FormatRequest/FormatResponse which handles both HTTP/1.1 and HTTP/2
		reqStr := string(entry.FormatRequest())
		respStr := string(entry.FormatResponse())
		result = append(result, ProxyEntry{
			Request:  reqStr,
			Response: respStr,
			Protocol: entry.Protocol,
		})
	}

	return result, nil
}

func (b *NativeProxyBackend) SendRequest(ctx context.Context, name string, req SendRequestInput) (*SendRequestResult, error) {
	scheme := schemeHTTP
	if req.Target.UsesHTTPS {
		scheme = schemeHTTPS
	}
	protocol := req.Protocol
	if protocol == "" {
		protocol = "http/1.1"
	}
	log.Printf("native: sending request %s to %s://%s:%d (protocol=%s, follow_redirects=%v)",
		name, scheme, req.Target.Hostname, req.Target.Port, protocol, req.FollowRedirects)

	// Build send options using the defaulted protocol for consistency with logging
	opts := proxy.SendOptions{
		RawRequest: req.RawRequest,
		Target: proxy.Target{
			Hostname:  req.Target.Hostname,
			Port:      req.Target.Port,
			UsesHTTPS: req.Target.UsesHTTPS,
		},
		Force:    req.Force,
		Timeout:  req.Timeout,
		Protocol: protocol,
	}

	// Create sender with JSON modifier
	sender := &proxy.Sender{
		JSONModifier: ModifyJSONBodyMap,
	}

	// Send request
	var result *proxy.SendResult
	var err error
	if req.FollowRedirects {
		result, err = sender.SendWithRedirects(ctx, opts)
	} else {
		result, err = sender.Send(ctx, opts)
	}
	if err != nil {
		return nil, err
	}

	// Convert response to SendRequestResult format
	var buf bytes.Buffer
	return &SendRequestResult{
		Headers:  result.Response.SerializeHeaders(&buf),
		Body:     result.Response.Body,
		Duration: result.Duration,
	}, nil
}

func (b *NativeProxyBackend) ListRules(ctx context.Context, websocket bool) ([]protocol.RuleEntry, error) {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	rules := b.httpRules
	if websocket {
		rules = b.wsRules
	}

	result := make([]protocol.RuleEntry, 0, len(rules))
	for _, r := range rules {
		result = append(result, protocol.RuleEntry{
			RuleID:  r.ID,
			Label:   r.Label,
			Type:    r.Type,
			IsRegex: r.IsRegex,
			Match:   r.Match,
			Replace: r.Replace,
		})
	}
	return result, nil
}

func (b *NativeProxyBackend) AddRule(ctx context.Context, input ProxyRuleInput) (*protocol.RuleEntry, error) {
	// Validate type (both HTTP and WebSocket types)
	if !validRuleTypes[input.Type] {
		return nil, fmt.Errorf("invalid rule type: %q", input.Type)
	}

	isRegex := input.IsRegex != nil && *input.IsRegex

	// Pre-compile regex if needed
	var compiled *regexp.Regexp
	if isRegex {
		var err error
		compiled, err = regexp.Compile(input.Match)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	b.rulesMu.Lock()
	defer b.rulesMu.Unlock()

	// Check label uniqueness across both slices
	if input.Label != "" {
		if b.labelExists(input.Label) {
			return nil, fmt.Errorf("%w: %s", ErrLabelExists, input.Label)
		}
	}

	rule := nativeStoredRule{
		ID:       ids.Generate(0),
		Label:    input.Label,
		Type:     input.Type,
		IsRegex:  isRegex,
		Match:    input.Match,
		Replace:  input.Replace,
		compiled: compiled,
	}
	if isWSType(input.Type) {
		b.wsRules = append(b.wsRules, rule)
	} else {
		b.httpRules = append(b.httpRules, rule)
	}

	return &protocol.RuleEntry{
		RuleID:  rule.ID,
		Label:   rule.Label,
		Type:    rule.Type,
		IsRegex: rule.IsRegex,
		Match:   rule.Match,
		Replace: rule.Replace,
	}, nil
}

func (b *NativeProxyBackend) UpdateRule(ctx context.Context, idOrLabel string, input ProxyRuleInput) (*protocol.RuleEntry, error) {
	b.rulesMu.Lock()
	defer b.rulesMu.Unlock()

	rule, isWS := b.findRule(idOrLabel)
	if rule == nil {
		return nil, ErrNotFound
	}

	// Validate type matches websocket category
	if isWSType(input.Type) != isWS {
		if isWS {
			return nil, fmt.Errorf("cannot update WebSocket rule with HTTP type %q", input.Type)
		}
		return nil, fmt.Errorf("cannot update HTTP rule with WebSocket type %q", input.Type)
	}

	// Validate rule type is known
	if !validRuleTypes[input.Type] {
		return nil, fmt.Errorf("invalid rule type: %q", input.Type)
	}

	// Check label uniqueness if changing
	if input.Label != "" && input.Label != rule.Label {
		if b.labelExistsExcluding(input.Label, rule.ID) {
			return nil, fmt.Errorf("%w: %s", ErrLabelExists, input.Label)
		}
		rule.Label = input.Label
	}

	// Determine new regex state
	newIsRegex := rule.IsRegex
	if input.IsRegex != nil {
		newIsRegex = *input.IsRegex
	}

	// Recompile regex if needed
	var compiled *regexp.Regexp
	if newIsRegex {
		var err error
		compiled, err = regexp.Compile(input.Match)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %w", err)
		}
	}

	rule.Type = input.Type
	rule.Match = input.Match
	rule.Replace = input.Replace
	rule.IsRegex = newIsRegex
	rule.compiled = compiled

	return &protocol.RuleEntry{
		RuleID:  rule.ID,
		Label:   rule.Label,
		Type:    rule.Type,
		IsRegex: rule.IsRegex,
		Match:   rule.Match,
		Replace: rule.Replace,
	}, nil
}

func (b *NativeProxyBackend) DeleteRule(ctx context.Context, idOrLabel string) error {
	b.rulesMu.Lock()
	defer b.rulesMu.Unlock()

	for i, r := range b.httpRules {
		if r.ID == idOrLabel || r.Label == idOrLabel {
			b.httpRules = slices.Delete(b.httpRules, i, i+1)
			return nil
		}
	}
	for i, r := range b.wsRules {
		if r.ID == idOrLabel || r.Label == idOrLabel {
			b.wsRules = slices.Delete(b.wsRules, i, i+1)
			return nil
		}
	}
	return ErrNotFound
}

// findRule finds a rule by ID or label, returning the rule and whether it's a WebSocket rule.
// Caller must hold rulesMu.
func (b *NativeProxyBackend) findRule(idOrLabel string) (*nativeStoredRule, bool) {
	for i := range b.httpRules {
		if b.httpRules[i].ID == idOrLabel || b.httpRules[i].Label == idOrLabel {
			return &b.httpRules[i], false
		}
	}
	for i := range b.wsRules {
		if b.wsRules[i].ID == idOrLabel || b.wsRules[i].Label == idOrLabel {
			return &b.wsRules[i], true
		}
	}
	return nil, false
}

// labelExists checks if a label is already in use. Caller must hold rulesMu.
func (b *NativeProxyBackend) labelExists(label string) bool {
	for _, r := range b.httpRules {
		if r.Label == label {
			return true
		}
	}
	for _, r := range b.wsRules {
		if r.Label == label {
			return true
		}
	}
	return false
}

// labelExistsExcluding checks if a label is in use by a rule other than excludeID.
// Caller must hold rulesMu.
func (b *NativeProxyBackend) labelExistsExcluding(label, excludeID string) bool {
	for _, r := range b.httpRules {
		if r.Label == label && r.ID != excludeID {
			return true
		}
	}
	for _, r := range b.wsRules {
		if r.Label == label && r.ID != excludeID {
			return true
		}
	}
	return false
}

// =============================================================================
// RuleApplier Implementation
// =============================================================================

// ApplyRequestRules applies request header and body rules.
// Rules are applied in the order they were added.
func (b *NativeProxyBackend) ApplyRequestRules(req *proxy.RawHTTP1Request) *proxy.RawHTTP1Request {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	var headerRules, bodyRules []nativeStoredRule
	for _, rule := range b.httpRules {
		switch rule.Type {
		case RuleTypeRequestHeader:
			headerRules = append(headerRules, rule)
		case RuleTypeRequestBody:
			bodyRules = append(bodyRules, rule)
		}
	}

	// Apply header rules
	if len(headerRules) > 0 {
		req = b.applyRequestHeaderRules(req, headerRules)
	}

	// Apply body rules
	if len(bodyRules) > 0 && len(req.Body) > 0 {
		req = b.applyRequestBodyRules(req, bodyRules)
	}

	return req
}

// ApplyResponseRules applies response header and body rules.
// Handles decompression/recompression for body rules.
func (b *NativeProxyBackend) ApplyResponseRules(resp *proxy.RawHTTP1Response) *proxy.RawHTTP1Response {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	var headerRules, bodyRules []nativeStoredRule
	for _, rule := range b.httpRules {
		switch rule.Type {
		case RuleTypeResponseHeader:
			headerRules = append(headerRules, rule)
		case RuleTypeResponseBody:
			bodyRules = append(bodyRules, rule)
		}
	}

	// Apply header rules
	if len(headerRules) > 0 {
		resp = b.applyResponseHeaderRules(resp, headerRules)
	}

	// Apply body rules with compression handling
	if len(bodyRules) > 0 && len(resp.Body) > 0 {
		resp = b.applyResponseBodyRules(resp, bodyRules)
	}

	return resp
}

// ApplyWSRules applies WebSocket rules to frame payload.
func (b *NativeProxyBackend) ApplyWSRules(payload []byte, direction string) []byte {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	for _, rule := range b.wsRules {
		if rule.Type != RuleTypeWSBoth && rule.Type != direction {
			continue
		}
		payload = applyMatchReplaceRule(payload, rule, false) // body content is case-sensitive
	}
	return payload
}

// HasBodyRules returns true if there are body rules for request or response.
// Used by HTTP/2 handler to decide whether to buffer full bodies.
func (b *NativeProxyBackend) HasBodyRules(isRequest bool) bool {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	targetType := RuleTypeResponseBody
	if isRequest {
		targetType = RuleTypeRequestBody
	}

	for _, rule := range b.httpRules {
		if rule.Type == targetType {
			return true
		}
	}
	return false
}

// ApplyRequestBodyOnlyRules applies only body rules to a request body.
// Used by HTTP/2 where headers are sent separately before body.
// If recompression fails, returns error so caller can reset the stream.
func (b *NativeProxyBackend) ApplyRequestBodyOnlyRules(body []byte, headers proxy.Headers) ([]byte, error) {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	var bodyRules []nativeStoredRule
	for _, rule := range b.httpRules {
		if rule.Type == RuleTypeRequestBody {
			bodyRules = append(bodyRules, rule)
		}
	}

	encoding := headers.Get("content-encoding")
	result := applyBodyRulesWithCompression(body, encoding, bodyRules)

	if result.err != nil {
		return nil, fmt.Errorf("recompression failed: %w", result.err)
	}
	return result.body, nil
}

// ApplyResponseBodyOnlyRules applies only body rules to a response body.
// Used by HTTP/2 where headers are sent separately before body.
// If recompression fails, returns original body to avoid corrupting response.
func (b *NativeProxyBackend) ApplyResponseBodyOnlyRules(body []byte, headers proxy.Headers) []byte {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	var bodyRules []nativeStoredRule
	for _, rule := range b.httpRules {
		if rule.Type == RuleTypeResponseBody {
			bodyRules = append(bodyRules, rule)
		}
	}

	encoding := headers.Get("content-encoding")
	result := applyBodyRulesWithCompression(body, encoding, bodyRules)

	if result.err != nil {
		log.Printf("proxy: recompression failed, returning original body: %v", result.err)
		return body // return original on recompression failure
	}
	return result.body
}

// applyRequestHeaderRules applies header rules to request.
func (b *NativeProxyBackend) applyRequestHeaderRules(req *proxy.RawHTTP1Request, rules []nativeStoredRule) *proxy.RawHTTP1Request {
	// Serialize headers to text format
	var headerBuf bytes.Buffer
	for _, h := range req.Headers {
		headerBuf.WriteString(h.Name)
		headerBuf.WriteString(": ")
		headerBuf.WriteString(h.Value)
		headerBuf.WriteString("\r\n")
	}

	original := headerBuf.Bytes()
	modified := original

	// Apply each rule in order (case-insensitive for headers to handle HTTP/2 lowercase)
	for _, rule := range rules {
		modified = applyMatchReplaceRule(modified, rule, true)
	}

	// If no changes, return original
	if bytes.Equal(modified, original) {
		return req
	}

	// Parse modified headers back
	req.Headers = parseHeadersFromText(modified)
	return req
}

// applyRequestBodyRules applies body rules to request with compression handling.
func (b *NativeProxyBackend) applyRequestBodyRules(req *proxy.RawHTTP1Request, rules []nativeStoredRule) *proxy.RawHTTP1Request {
	encoding := req.GetHeader("Content-Encoding")
	result := applyBodyRulesWithCompression(req.Body, encoding, rules)

	if result.err != nil {
		log.Printf("proxy: recompression failed, skipping request body rules: %v", result.err)
		return req
	}
	if !result.modified {
		return req
	}

	req.Body = result.body
	req.SetHeader("Content-Length", strconv.Itoa(len(result.body)))
	return req
}

// applyResponseHeaderRules applies header rules to response.
func (b *NativeProxyBackend) applyResponseHeaderRules(resp *proxy.RawHTTP1Response, rules []nativeStoredRule) *proxy.RawHTTP1Response {
	// Serialize headers to text format
	var headerBuf bytes.Buffer
	for _, h := range resp.Headers {
		headerBuf.WriteString(h.Name)
		headerBuf.WriteString(": ")
		headerBuf.WriteString(h.Value)
		headerBuf.WriteString("\r\n")
	}

	original := headerBuf.Bytes()
	modified := original

	// Apply each rule in order (case-insensitive for headers to handle HTTP/2 lowercase)
	for _, rule := range rules {
		modified = applyMatchReplaceRule(modified, rule, true)
	}

	// If no changes, return original
	if bytes.Equal(modified, original) {
		return resp
	}

	// Parse modified headers back
	resp.Headers = parseHeadersFromText(modified)
	return resp
}

// applyResponseBodyRules applies body rules to response with compression handling.
func (b *NativeProxyBackend) applyResponseBodyRules(resp *proxy.RawHTTP1Response, rules []nativeStoredRule) *proxy.RawHTTP1Response {
	encoding := resp.GetHeader("Content-Encoding")
	result := applyBodyRulesWithCompression(resp.Body, encoding, rules)

	if !result.modified {
		return resp
	}

	if result.err != nil {
		// Recompression failed - send uncompressed (HTTP/1.1 can adjust headers)
		log.Printf("proxy: recompression failed, sending uncompressed: %v", result.err)
		resp.RemoveHeader("Content-Encoding")
	}

	resp.Body = result.body
	resp.SetHeader("Content-Length", strconv.Itoa(len(result.body)))
	return resp
}

// bodyRuleResult holds the result of applying body rules with compression handling.
type bodyRuleResult struct {
	body     []byte // modified body (may be recompressed)
	modified bool   // true if rules changed the body
	err      error  // recompression error, if any
}

// applyBodyRulesWithCompression handles decompression, rule application, and recompression.
// Returns the result including whether the body was modified and any recompression error.
func applyBodyRulesWithCompression(body []byte, encoding string, rules []nativeStoredRule) bodyRuleResult {
	if len(rules) == 0 || len(body) == 0 {
		return bodyRuleResult{body: body, modified: false}
	}

	// Check if encoding is present but not supported
	if encoding != "" {
		_, supported := proxy.NormalizeEncoding(encoding)
		if !supported {
			log.Printf("proxy: unsupported Content-Encoding %q, skipping body rules", encoding)
			return bodyRuleResult{body: body, modified: false}
		}
	}

	// Decompress if needed
	decompressed, wasCompressed := proxy.Decompress(body, encoding)
	if wasCompressed && decompressed == nil {
		log.Printf("proxy: Content-Encoding %s but decompression failed, skipping body rules", encoding)
		return bodyRuleResult{body: body, modified: false}
	}

	workingBody := body
	if wasCompressed {
		workingBody = decompressed
	}

	// Apply each rule in order
	modified := workingBody
	for _, rule := range rules {
		modified = applyMatchReplaceRule(modified, rule, false) // body content is case-sensitive
	}

	// If no changes, return original
	if bytes.Equal(modified, workingBody) {
		return bodyRuleResult{body: body, modified: false}
	}

	// Recompress if originally compressed
	if wasCompressed {
		compressed, err := proxy.Compress(modified, encoding)
		if err != nil {
			return bodyRuleResult{body: modified, modified: true, err: err}
		}
		return bodyRuleResult{body: compressed, modified: true}
	}

	return bodyRuleResult{body: modified, modified: true}
}

// applyMatchReplaceRule applies a single match/replace rule to data.
// caseInsensitive makes literal (non-regex) matching case-insensitive.
func applyMatchReplaceRule(input []byte, rule nativeStoredRule, caseInsensitive bool) []byte {
	// Empty match means "append" - add the replacement at the end
	if rule.Match == "" {
		// For headers, ensure proper line ending before appending
		if len(input) > 0 && !bytes.HasSuffix(input, []byte("\r\n")) {
			input = append(input, '\r', '\n')
		}
		return append(input, []byte(rule.Replace)...)
	}

	if !rule.IsRegex {
		if caseInsensitive {
			return replaceCaseInsensitive(input, rule.Match, rule.Replace)
		}
		return bytes.ReplaceAll(input, []byte(rule.Match), []byte(rule.Replace))
	}

	re := rule.compiled
	if re == nil {
		var err error
		re, err = regexp.Compile(rule.Match)
		if err != nil {
			return input
		}
	}
	return re.ReplaceAll(input, []byte(rule.Replace))
}

// replaceCaseInsensitive replaces all occurrences of match in input, case-insensitively.
func replaceCaseInsensitive(input []byte, match, replace string) []byte {
	if match == "" {
		return input
	}

	matchBytes := []byte(match)
	replaceBytes := []byte(replace)
	inputLower := bytes.ToLower(input)
	matchLower := bytes.ToLower(matchBytes)

	var result []byte
	start := 0
	for {
		idx := bytes.Index(inputLower[start:], matchLower)
		if idx < 0 {
			result = append(result, input[start:]...)
			break
		}
		result = append(result, input[start:start+idx]...)
		result = append(result, replaceBytes...)
		start = start + idx + len(matchBytes)
	}
	return result
}

// parseHeadersFromText parses "Name: Value\r\n" lines into Header slice.
func parseHeadersFromText(text []byte) []proxy.Header {
	lines := bytes.Split(text, []byte("\r\n"))
	headers := make([]proxy.Header, 0, len(lines))
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		idx := bytes.IndexByte(line, ':')
		if idx < 0 {
			// No colon - skip malformed line
			continue
		}
		name := string(line[:idx])
		value := string(bytes.TrimSpace(line[idx+1:]))
		headers = append(headers, proxy.Header{Name: name, Value: value})
	}
	return headers
}

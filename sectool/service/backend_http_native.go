package service

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/go-analyze/bulk"
	"github.com/go-appsec/toolbox/pkg/mutate"
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/ids"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

const (
	ruleKeyHTTP = "http_rules"
	ruleKeyWS   = "ws_rules"
)

// NativeProxyBackend implements HttpBackend using the native proxy.
// This backend provides wire-level fidelity for security testing including
// HTTP/1.1 and HTTP/2 support with header order preservation.
type NativeProxyBackend struct {
	server   *proxy.ProxyServer
	timeouts proxy.TimeoutConfig

	// Rules: cached from ruleStorage for hot path access
	rulesMu     sync.RWMutex
	httpRules   []nativeStoredRule
	wsRules     []nativeStoredRule
	ruleStorage store.Storage

	// Responders: cached from responderStorage for hot path access
	respondersMu     sync.RWMutex
	responders       []nativeStoredResponder
	responderStorage store.Storage

	// Sidecar IPC listener and registry; nil when sidecars are disabled.
	sidecarListener *sidecar.Listener
	sidecarManager  *sidecar.Manager

	closed atomic.Bool
}

// nativeStoredRule is the persistent format for rules.
type nativeStoredRule struct {
	ID      string `json:"id" msgpack:"id"`
	Label   string `json:"label,omitempty" msgpack:"l,omitempty"`
	Type    string `json:"type" msgpack:"t"`
	IsRegex bool   `json:"is_regex" msgpack:"ir"`
	Find    string `json:"find" msgpack:"f"`
	Replace string `json:"replace" msgpack:"r"`
	Adapter string `json:"adapter,omitempty" msgpack:"a,omitempty"`

	// compiled is the pre-compiled regex (nil if not a regex rule)
	compiled *regexp.Regexp `msgpack:"-"`
}

// Compile-time interface checks
var _ HttpBackend = (*NativeProxyBackend)(nil)
var _ types.RuleApplier = (*NativeProxyBackend)(nil)
var _ proxy.ResponseInterceptor = (*NativeProxyBackend)(nil)
var _ ResponderBackend = (*NativeProxyBackend)(nil)
var _ sidecar.RuleSource = (*NativeProxyBackend)(nil)
var _ SidecarRegistry = (*sidecar.Manager)(nil)

// NewNativeProxyBackend creates a new native proxy backend.
// Does NOT start serving - call Serve() separately (typically in a goroutine).
// Call EnableSidecars before Serve to host the out-of-process sidecar listener.
func NewNativeProxyBackend(port int, configDir string, maxBodyBytes int, storage store.Provider, timeouts proxy.TimeoutConfig, fullBuffer bool) (*NativeProxyBackend, error) {
	historyStorage, err := storage("hist")
	if err != nil {
		return nil, fmt.Errorf("history storage: %w", err)
	}
	ruleStorage, err := storage("rule")
	if err != nil {
		_ = historyStorage.Close()
		return nil, fmt.Errorf("rule storage: %w", err)
	}
	responderStorage, err := storage("resp")
	if err != nil {
		_ = historyStorage.Close()
		_ = ruleStorage.Close()
		return nil, fmt.Errorf("responder storage: %w", err)
	}

	server, err := proxy.NewProxyServer(port, configDir, maxBodyBytes, historyStorage, timeouts, fullBuffer)
	if err != nil {
		_ = historyStorage.Close()
		_ = ruleStorage.Close()
		_ = responderStorage.Close()
		return nil, fmt.Errorf("create proxy server: %w", err)
	}

	b := &NativeProxyBackend{
		server:           server,
		timeouts:         timeouts,
		ruleStorage:      ruleStorage,
		responderStorage: responderStorage,
	}

	if b.httpRules, err = b.loadRuleList(ruleKeyHTTP); err != nil {
		_ = b.Close(context.Background())
		return nil, fmt.Errorf("load HTTP rules: %w", err)
	} else if b.wsRules, err = b.loadRuleList(ruleKeyWS); err != nil {
		_ = b.Close(context.Background())
		return nil, fmt.Errorf("load WebSocket rules: %w", err)
	}

	if b.responders, err = b.loadResponders(); err != nil {
		_ = b.Close(context.Background())
		return nil, fmt.Errorf("load responders: %w", err)
	}

	server.SetRuleApplier(b)
	server.SetResponseInterceptor(b)

	return b, nil
}

// EnableSidecars binds the sidecar IPC listener and registry. Call once before
// Serve, which starts accepting. cfg.NativeProxyPort should be the proxy's listen
// port; the built-in adapter names are reserved automatically. coreInvoke backs
// the sidecar core_invoke method; it resolves the read-side tools lazily so it can
// be supplied before the MCP server exists.
func (b *NativeProxyBackend) EnableSidecars(cfg sidecar.Config, coreInvoke sidecar.CoreService, replayStore *store.ReplayHistoryStore) error {
	cfg.ReservedNames = []string{types.ProtocolHTTP11, types.ProtocolH2, types.ProtocolTagWS, types.AdapterScopeCore}
	// Route sidecar-performed replays into the replay store so they report source
	// "replay" like native replays; other flows go to proxy history.
	sink := &replayRoutingSink{history: b.server.History(), replay: replayStore}
	b.sidecarManager = sidecar.NewManager(cfg, b.server.Registry(), sink, coreInvoke, b)
	lst, err := sidecar.NewListener(cfg, b.sidecarManager)
	if err != nil {
		return err
	}
	b.sidecarListener = lst
	return nil
}

// Sidecars returns the sidecar registry, or nil when sidecars are not enabled.
func (b *NativeProxyBackend) Sidecars() SidecarRegistry {
	if b.sidecarManager == nil {
		return nil // avoid a non-nil interface wrapping a nil *Manager
	}
	return b.sidecarManager
}

// SetCaptureFilter configures the proxy to skip storing entries that the filter rejects.
// Filtered requests are still proxied normally.
func (b *NativeProxyBackend) SetCaptureFilter(f proxy.CaptureFilter) {
	b.server.SetCaptureFilter(f)
}

// Serve starts the proxy server and, when enabled, accepts sidecar connections.
// Call in a goroutine, and only once the core MCP tools exist so sidecar
// registrations are checked against the complete tool set.
func (b *NativeProxyBackend) Serve() error {
	if b.sidecarListener != nil {
		go func() {
			if err := b.sidecarListener.Serve(); err != nil {
				log.Printf("sidecar: listener error: %v", err)
			}
		}()
	}
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

func (b *NativeProxyBackend) loadRuleList(key string) ([]nativeStoredRule, error) {
	data, found, err := b.ruleStorage.Get(key)
	if err != nil {
		return nil, fmt.Errorf("load rules %s: %w", key, err)
	} else if !found {
		return nil, nil
	}
	var rules []nativeStoredRule
	if err := store.Deserialize(data, &rules); err != nil {
		return nil, fmt.Errorf("deserialize rules %s: %w", key, err)
	}
	// Recompile regexes
	for i := range rules {
		if rules[i].IsRegex {
			if rules[i].compiled, err = regexp.Compile(rules[i].Find); err != nil {
				return nil, fmt.Errorf("invalid stored regex in rule %s (find=%q): %w", rules[i].ID, rules[i].Find, err)
			}
		}
	}
	return rules, nil
}

// saveRules writes the rule list to storage. Caller must hold rulesMu.
func (b *NativeProxyBackend) saveRules(key string, rules []nativeStoredRule) error {
	if len(rules) == 0 {
		return b.ruleStorage.Delete(key)
	}
	data, err := store.Serialize(rules)
	if err != nil {
		return fmt.Errorf("serialize rules: %w", err)
	}
	return b.ruleStorage.Set(key, data)
}

func (b *NativeProxyBackend) Close(ctx context.Context) error {
	if b.closed.Swap(true) {
		return nil
	}

	// Drain proxy before closing the listener so in-flight flows can reach their sidecar adapter
	errs := []error{b.server.Shutdown(ctx)}
	if b.sidecarListener != nil {
		errs = append(errs, b.sidecarListener.Close(ctx))
	}
	errs = append(errs, b.ruleStorage.Close(), b.responderStorage.Close())
	return errors.Join(errs...)
}

// CACert returns the CA certificate used for MITM TLS interception.
func (b *NativeProxyBackend) CACert() *x509.Certificate {
	return b.server.CertManager().CACert()
}

func (b *NativeProxyBackend) GetProxyHistory(ctx context.Context, count int, afterFlowID string) ([]ProxyEntry, error) {
	entries := b.server.History().Page(count, afterFlowID)

	var buf bytes.Buffer
	result := make([]ProxyEntry, 0, len(entries))
	for _, entry := range entries {
		// Use FormatRequest/FormatResponse which handles both HTTP/1.1 and HTTP/2
		reqStr := string(entry.FormatRequest(&buf))
		respStr := string(entry.FormatResponse(&buf))
		result = append(result, ProxyEntry{
			FlowID:            entry.FlowID,
			Timestamp:         entry.StartedAt,
			Request:           reqStr,
			Response:          respStr,
			Protocol:          entry.ProtocolTag,
			Adapter:           entry.Adapter,
			ParentFlowID:      entry.ParentFlowID,
			Scheme:            entry.Scheme,
			Port:              entry.Port,
			Annotations:       entry.Annotations,
			InvokedBy:         entry.InvokedBy,
			SidecarInstanceID: entry.SidecarInstanceID,
		})
	}

	return result, nil
}

func (b *NativeProxyBackend) GetProxyHistoryMeta(ctx context.Context, count int, afterFlowID string) ([]ProxyEntryMeta, error) {
	metas := b.server.History().PageMeta(count, afterFlowID)
	result := make([]ProxyEntryMeta, len(metas))
	for i, m := range metas {
		result[i] = ProxyEntryMeta{
			FlowID:            m.FlowID,
			Timestamp:         m.Timestamp,
			Method:            m.Method,
			Host:              m.Host,
			Path:              m.Path,
			Status:            m.Status,
			RespLen:           m.RespLen,
			Protocol:          m.Protocol,
			Adapter:           m.Adapter,
			ParentFlowID:      m.ParentFlowID,
			Scheme:            m.Scheme,
			Port:              m.Port,
			ContentType:       m.ContentType,
			Annotations:       m.Annotations,
			InvokedBy:         m.InvokedBy,
			SidecarInstanceID: m.SidecarInstanceID,
		}
	}
	return result, nil
}

func (b *NativeProxyBackend) GetProxyEntry(ctx context.Context, flowID string) (*ProxyEntry, error) {
	entry, ok := b.server.History().Get(flowID)
	if !ok {
		return nil, ErrNotFound
	}
	var buf bytes.Buffer
	reqStr := string(entry.FormatRequest(&buf))
	respStr := string(entry.FormatResponse(&buf))
	return &ProxyEntry{
		FlowID:            entry.FlowID,
		Timestamp:         entry.StartedAt,
		Request:           reqStr,
		Response:          respStr,
		InterimResponses:  entry.FormatInterimResponses(&buf),
		Protocol:          entry.ProtocolTag,
		Adapter:           entry.Adapter,
		ParentFlowID:      entry.ParentFlowID,
		Scheme:            entry.Scheme,
		Port:              entry.Port,
		Annotations:       entry.Annotations,
		InvokedBy:         entry.InvokedBy,
		SidecarInstanceID: entry.SidecarInstanceID,
		InProgress:        entry.CompletedAt.IsZero(),
	}, nil
}

func (b *NativeProxyBackend) GetProxyChildren(ctx context.Context, parentFlowID string) ([]ProxyEntry, error) {
	children := b.server.History().Children(parentFlowID)
	var buf bytes.Buffer
	result := make([]ProxyEntry, 0, len(children))
	for _, entry := range children {
		result = append(result, ProxyEntry{
			FlowID:            entry.FlowID,
			Timestamp:         entry.StartedAt,
			Request:           string(entry.FormatRequest(&buf)),
			Response:          string(entry.FormatResponse(&buf)),
			InterimResponses:  entry.FormatInterimResponses(&buf),
			Protocol:          entry.ProtocolTag,
			Adapter:           entry.Adapter,
			ParentFlowID:      entry.ParentFlowID,
			Scheme:            entry.Scheme,
			Port:              entry.Port,
			Annotations:       entry.Annotations,
			InvokedBy:         entry.InvokedBy,
			SidecarInstanceID: entry.SidecarInstanceID,
		})
	}
	return result, nil
}

func (b *NativeProxyBackend) DeleteProxyEntries(ctx context.Context, flowIDs []string) (int, error) {
	return b.server.History().Delete(flowIDs...), nil
}

func (b *NativeProxyBackend) SendRequest(ctx context.Context, name string, req SendRequestInput) (*SendRequestResult, error) {
	protocol := req.Protocol
	if protocol == "" {
		protocol = "http/1.1"
	}

	rawRequest := req.RawRequest
	var modifiedRequest []byte

	// Non-redirect path pre-applies rules here (Send ignores RequestRuleApplier). Redirect path
	// leaves rawRequest pristine; the sender applies rules per hop. Malformed requests skip rules.
	if b.hasRequestRules() && !req.FollowRedirects {
		unframedBody := protocol == types.ProtocolH2 || req.Force
		if parsed, parseErr := proxy.ParseRequest(bytes.NewReader(rawRequest), unframedBody); parseErr == nil {
			var buf bytes.Buffer
			modified := b.ApplyRequestRules(parsed).SerializeRaw(&buf)
			if !bytes.Equal(rawRequest, modified) {
				rawRequest = slices.Clone(modified)
				modifiedRequest = rawRequest
			}
		}
	}

	opts := proxy.SendOptions{
		RawRequest: rawRequest,
		Target: types.Target{
			Hostname:  req.Target.Hostname,
			Port:      req.Target.Port,
			UsesHTTPS: req.Target.UsesHTTPS,
		},
		Force:    req.Force,
		Protocol: protocol,
	}

	sender := &proxy.Sender{
		Timeouts: b.timeouts,
	}
	if b.hasRequestRules() {
		sender.RequestRuleApplier = b.ApplyRequestRules
	}

	var result *proxy.SendResult
	var err error
	if req.FollowRedirects {
		result, err = sender.SendWithRedirects(ctx, opts)
		if err == nil {
			modifiedRequest = result.ModifiedRequest
		}
	} else {
		result, err = sender.Send(ctx, opts)
	}
	if err != nil {
		return nil, err
	}

	// Response rules are NOT applied here, they modify browser-bound proxy traffic,
	// not programmatic send results where the caller needs raw server responses

	var buf bytes.Buffer
	return &SendRequestResult{
		Headers:         result.Response.SerializeHeaders(&buf),
		Body:            result.Response.Body,
		Duration:        result.Duration,
		ModifiedRequest: modifiedRequest,
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
			Find:    r.Find,
			Replace: r.Replace,
			Adapter: r.Adapter,
		})
	}
	return result, nil
}

func (b *NativeProxyBackend) AddRule(ctx context.Context, input protocol.RuleEntry) (*protocol.RuleEntry, error) {
	out, err := b.addRuleLocked(input)
	if err != nil {
		return nil, err
	}
	b.pushRules(ctx)
	return out, nil
}

// addRuleLocked validates, persists, and caches a rule.
// Returns before the sidecar push so the caller pushes outside rulesMu.
func (b *NativeProxyBackend) addRuleLocked(input protocol.RuleEntry) (*protocol.RuleEntry, error) {
	// Validate type (both HTTP and WebSocket types)
	if !validRuleTypes[input.Type] {
		return nil, fmt.Errorf("invalid rule type: %q", input.Type)
	}

	var compiled *regexp.Regexp
	if input.IsRegex {
		var err error
		compiled, err = regexp.Compile(input.Find)
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
		ID:       ids.Generate(ids.EntityLength),
		Label:    input.Label,
		Type:     input.Type,
		IsRegex:  input.IsRegex,
		Find:     input.Find,
		Replace:  input.Replace,
		Adapter:  input.Adapter,
		compiled: compiled,
	}

	// Save to storage (source of truth), then update cache
	target := &b.httpRules
	key := ruleKeyHTTP
	if isWSType(input.Type) {
		target = &b.wsRules
		key = ruleKeyWS
	}
	updated := append(slices.Clone(*target), rule)
	if err := b.saveRules(key, updated); err != nil {
		return nil, fmt.Errorf("persist rule: %w", err)
	}
	*target = updated

	return &protocol.RuleEntry{
		RuleID:  rule.ID,
		Label:   rule.Label,
		Type:    rule.Type,
		IsRegex: rule.IsRegex,
		Find:    rule.Find,
		Replace: rule.Replace,
		Adapter: rule.Adapter,
	}, nil
}

func (b *NativeProxyBackend) DeleteRule(ctx context.Context, idOrLabel string) error {
	if err := b.deleteRuleLocked(idOrLabel); err != nil {
		return err
	}
	b.pushRules(ctx)
	return nil
}

// deleteRuleLocked removes a rule by id or label. Returns ErrNotFound when no rule
// matches, before any sidecar push.
func (b *NativeProxyBackend) deleteRuleLocked(idOrLabel string) error {
	b.rulesMu.Lock()
	defer b.rulesMu.Unlock()

	for i, r := range b.httpRules {
		if r.ID == idOrLabel || r.Label == idOrLabel {
			updated := slices.Delete(slices.Clone(b.httpRules), i, i+1)
			if err := b.saveRules(ruleKeyHTTP, updated); err != nil {
				return fmt.Errorf("persist rule: %w", err)
			}
			b.httpRules = updated
			return nil
		}
	}
	for i, r := range b.wsRules {
		if r.ID == idOrLabel || r.Label == idOrLabel {
			updated := slices.Delete(slices.Clone(b.wsRules), i, i+1)
			if err := b.saveRules(ruleKeyWS, updated); err != nil {
				return fmt.Errorf("persist rule: %w", err)
			}
			b.wsRules = updated
			return nil
		}
	}
	return ErrNotFound
}

// pushRules re-pushes the rule snapshot to connected sidecars after a change.
func (b *NativeProxyBackend) pushRules(ctx context.Context) {
	if b.sidecarManager != nil {
		b.sidecarManager.PushRules(ctx)
	}
}

// RuleSnapshot returns the rules scoped to the named adapter (scope empty or equal
// to the name), in apply order (HTTP rules then WS).
func (b *NativeProxyBackend) RuleSnapshot(adapter string) []wire.Rule {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	var out []wire.Rule
	appendScoped := func(rules []nativeStoredRule) {
		for _, r := range rules {
			if r.Adapter == "" || r.Adapter == adapter {
				out = append(out, wire.Rule{
					RuleID:  r.ID,
					Type:    r.Type,
					Label:   r.Label,
					IsRegex: r.IsRegex,
					Find:    r.Find,
					Replace: r.Replace,
					Adapter: r.Adapter,
				})
			}
		}
	}
	appendScoped(b.httpRules)
	appendScoped(b.wsRules)
	return out
}

// hasRequestRules returns true if any request header or body rules exist.
func (b *NativeProxyBackend) hasRequestRules() bool {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()
	for _, rule := range b.httpRules {
		if rule.Adapter != "" && rule.Adapter != types.AdapterScopeCore {
			continue
		}
		if rule.Type == wire.RuleTypeRequestHeader || rule.Type == wire.RuleTypeRequestBody {
			return true
		}
	}
	return false
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

// ApplyRequestRules applies request header and body rules.
// Rules are applied in the order they were added.
// When response body rules are active, strips unsupported encodings
// from Accept-Encoding so the server responds with an encoding we can decompress.
func (b *NativeProxyBackend) ApplyRequestRules(req *types.RawHTTP1Request) *types.RawHTTP1Request {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	var headerRules, bodyRules []nativeStoredRule
	var hasRespBodyRules bool
	for _, rule := range b.httpRules {
		if rule.Adapter != "" && rule.Adapter != types.AdapterScopeCore {
			continue
		}
		switch rule.Type {
		case wire.RuleTypeRequestHeader:
			headerRules = append(headerRules, rule)
		case wire.RuleTypeRequestBody:
			bodyRules = append(bodyRules, rule)
		case wire.RuleTypeResponseBody:
			hasRespBodyRules = true
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

	// Ensure server responds with an encoding we can decompress for body rules
	if hasRespBodyRules {
		if ae := req.GetHeader("Accept-Encoding"); ae != "" {
			if filtered := proxy.FilterSupportedEncodings(ae); filtered != ae {
				req.SetHeader("Accept-Encoding", filtered)
			}
		}
	}

	return req
}

// ApplyResponseRules applies response header and body rules.
// Handles decompression/recompression for body rules.
func (b *NativeProxyBackend) ApplyResponseRules(resp *types.RawHTTP1Response) *types.RawHTTP1Response {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	var headerRules, bodyRules []nativeStoredRule
	for _, rule := range b.httpRules {
		if rule.Adapter != "" && rule.Adapter != types.AdapterScopeCore {
			continue
		}
		switch rule.Type {
		case wire.RuleTypeResponseHeader:
			headerRules = append(headerRules, rule)
		case wire.RuleTypeResponseBody:
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
		if rule.Adapter != "" && rule.Adapter != types.AdapterScopeCore {
			continue
		}
		if rule.Type != wire.RuleTypeWSBoth && rule.Type != direction {
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

	targetType := wire.RuleTypeResponseBody
	if isRequest {
		targetType = wire.RuleTypeRequestBody
	}

	for _, rule := range b.httpRules {
		if rule.Adapter != "" && rule.Adapter != types.AdapterScopeCore {
			continue
		}
		if rule.Type == targetType {
			return true
		}
	}
	return false
}

// ApplyRequestBodyOnlyRules applies only body rules to a request body.
// Used by HTTP/2 where headers are sent separately before body.
// If recompression fails, returns error so caller can reset the stream.
func (b *NativeProxyBackend) ApplyRequestBodyOnlyRules(body []byte, headers types.Headers) ([]byte, error) {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	var bodyRules []nativeStoredRule
	for _, rule := range b.httpRules {
		if rule.Adapter != "" && rule.Adapter != types.AdapterScopeCore {
			continue
		}
		if rule.Type == wire.RuleTypeRequestBody {
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
func (b *NativeProxyBackend) ApplyResponseBodyOnlyRules(body []byte, headers types.Headers) []byte {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	var bodyRules []nativeStoredRule
	for _, rule := range b.httpRules {
		if rule.Adapter != "" && rule.Adapter != types.AdapterScopeCore {
			continue
		}
		if rule.Type == wire.RuleTypeResponseBody {
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

// ApplyRequestHeaderOnlyRules applies only request header rules to headers.
// Used when a request head is processed before its body.
func (b *NativeProxyBackend) ApplyRequestHeaderOnlyRules(headers types.Headers) types.Headers {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	headerRules := b.coreRulesOfTypeLocked(wire.RuleTypeRequestHeader)
	if len(headerRules) == 0 {
		return headers
	}
	req := b.applyRequestHeaderRules(&types.RawHTTP1Request{Headers: headers}, headerRules)
	return req.Headers
}

// ApplyResponseHeaderOnlyRules applies only response header rules to headers.
// Used when a response head is forwarded before its body arrives.
func (b *NativeProxyBackend) ApplyResponseHeaderOnlyRules(headers types.Headers) types.Headers {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	headerRules := b.coreRulesOfTypeLocked(wire.RuleTypeResponseHeader)
	if len(headerRules) == 0 {
		return headers
	}
	resp := b.applyResponseHeaderRules(&types.RawHTTP1Response{Headers: headers}, headerRules)
	return resp.Headers
}

// coreRulesOfTypeLocked returns core-adapter httpRules of the given type. Caller must hold rulesMu.
func (b *NativeProxyBackend) coreRulesOfTypeLocked(ruleType string) []nativeStoredRule {
	return bulk.SliceFilter(func(rule nativeStoredRule) bool {
		return (rule.Adapter == "" || rule.Adapter == types.AdapterScopeCore) && rule.Type == ruleType
	}, b.httpRules)
}

// applyRequestHeaderRules applies header rules to request.
func (b *NativeProxyBackend) applyRequestHeaderRules(req *types.RawHTTP1Request, rules []nativeStoredRule) *types.RawHTTP1Request {
	original := renderHeaderText(req.Headers)
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
func (b *NativeProxyBackend) applyRequestBodyRules(req *types.RawHTTP1Request, rules []nativeStoredRule) *types.RawHTTP1Request {
	encoding := req.GetHeader("Content-Encoding")
	result := applyBodyRulesWithCompression(req.Body, encoding, rules)

	if result.err != nil {
		log.Printf("proxy: recompression failed, skipping request body rules: %v", result.err)
		return req
	}
	if !result.modified {
		return req
	}

	req.SetBody(result.body)
	// refresh a declared CL only; an unframed body (H2, force) must stay unframed
	if (req.Wire == nil || !req.Wire.WasChunked) && req.GetHeader("Content-Length") != "" {
		req.SetHeader("Content-Length", strconv.Itoa(len(result.body)))
	}
	return req
}

// applyResponseHeaderRules applies header rules to response.
func (b *NativeProxyBackend) applyResponseHeaderRules(resp *types.RawHTTP1Response, rules []nativeStoredRule) *types.RawHTTP1Response {
	original := renderHeaderText(resp.Headers)
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
func (b *NativeProxyBackend) applyResponseBodyRules(resp *types.RawHTTP1Response, rules []nativeStoredRule) *types.RawHTTP1Response {
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

	resp.SetBody(result.body)
	if resp.Wire == nil || !resp.Wire.WasChunked {
		resp.SetHeader("Content-Length", strconv.Itoa(len(result.body)))
	}
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

// applyMatchReplaceRule applies a single find/replace rule to data.
// caseInsensitive makes literal (non-regex) matching case-insensitive.
func applyMatchReplaceRule(input []byte, rule nativeStoredRule, caseInsensitive bool) []byte {
	// Empty find means "append" - add the replacement at the end
	if rule.Find == "" {
		// For headers, ensure proper line ending before appending
		if caseInsensitive && len(input) > 0 && !bytes.HasSuffix(input, []byte("\r\n")) {
			input = append(input, '\r', '\n')
		}
		return append(input, []byte(rule.Replace)...)
	}

	if !rule.IsRegex {
		if caseInsensitive {
			return mutate.ReplaceCaseInsensitive(input, rule.Find, rule.Replace)
		}
		return bytes.ReplaceAll(input, []byte(rule.Find), []byte(rule.Replace))
	}

	re := rule.compiled
	if re == nil {
		var err error
		re, err = regexp.Compile(rule.Find)
		if err != nil {
			return input
		}
	}
	return re.ReplaceAll(input, []byte(rule.Replace))
}

// renderHeaderText serializes headers as "Name: Value\r\n" lines for rule application.
func renderHeaderText(headers types.Headers) []byte {
	return mutate.RenderHeaders([]types.Header(headers),
		func(h types.Header) string { return h.Name },
		func(h types.Header) string { return h.Value })
}

// parseHeadersFromText parses "Name: Value\r\n" lines into a Header slice,
// keeping colon-less lines and preserving each line's raw bytes for wire fidelity.
func parseHeadersFromText(text []byte) []types.Header {
	return mutate.ParseHeaders(text, func(name, value string, raw []byte) types.Header {
		return types.Header{Name: name, Value: value, RawLine: raw, LineEnding: types.EndingCRLF}
	})
}

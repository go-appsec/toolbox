package service

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/go-analyze/bulk"

	"github.com/go-harden/llm-security-toolbox/sectool/protocol"
	"github.com/go-harden/llm-security-toolbox/sectool/service/ids"
	"github.com/go-harden/llm-security-toolbox/sectool/service/store"
)

const (
	proxyHistoryPrefix = "proxy:history:"

	caCertFile = "ca.pem"
	caKeyFile  = "ca-key.pem"

	maxWebSocketFrameSize = 100 * 1024 * 1024 // 100 MB
)

// TODO - FUTURE - Replace goproxy with custom proxy implementation
//
// goproxy is providing diminishing value for this security testing use case.
// We've already bypassed it significantly and would benefit from full wire control.
//
// What goproxy currently provides:
//   - CONNECT tunnel handling for HTTPS MITM
//   - Proxy-form request parsing (GET http://host/path vs GET /path)
//   - Basic request forwarding to upstream servers
//   - TLSConfigFromCA helper for per-host certificate generation
//
// What we've already worked around:
//   - WebSocket: Complete bypass via wsAwareHandler wrapper because goproxy
//     doesn't support connection hijacking for bidirectional frame proxying
//   - HTTPS WebSocket: Cannot apply frame-level rules - goproxy handles 101
//     responses natively without exposing the upgraded connection
//   - Global state: Per-instance tlsConfigGen to avoid goproxy's global TLS config
//   - Direct sends: sendSingle() uses net/http.Transport directly, not goproxy
//
// Wire fidelity issues (critical for security testing):
//   - net/http normalizes headers to canonical casing (Content-Type not content-type)
//   - Header order is lost (map-based storage)
//   - Duplicate header formatting not preserved
//   - These matter for WAF bypasses, parser differentials, and request smuggling
//
// Replacement implementation would need:
//   1. CONNECT handler: Parse "CONNECT host:port HTTP/1.1", respond with
//      "200 Connection Established", wrap connection in tls.Server with per-host cert
//   2. Proxy-form detection: Distinguish "GET http://host/path" from "GET /path"
//   3. Raw forwarding loop: Read bytes from client, optionally modify, send to upstream
//   4. Per-host TLS cert generation: Already have CA, just need on-demand signing
//
// Benefits of custom implementation:
//   - Full control over header serialization (preserve order, casing, duplicates)
//   - Unified WebSocket handling for both HTTP and HTTPS
//   - Simpler architecture without wrapper handlers
//   - Ability to log/modify raw bytes for smuggling tests
//   - No dependency on library that doesn't match our precise needs
//
// The CONNECT + MITM plumbing is ~100-150 lines. We've already written more than
// that working around goproxy (WebSocket handling alone is ~180 lines).

// GoProxyBackend implements HttpBackend using elazarl/goproxy.
type GoProxyBackend struct {
	proxy    *goproxy.ProxyHttpServer
	server   *http.Server
	listener net.Listener
	addr     string

	// Proxy history tracking (all fields protected by mu)
	mu             sync.RWMutex
	historyStorage store.Storage
	nextOffset     uint32            // TODO - should be removed and indexed from storage records
	offsetToKey    map[uint32]string // TODO - this should be captured in the storage

	// Match/replace rules (separated by type for efficient iteration)
	rulesMu   sync.RWMutex
	httpRules []storedRule
	wsRules   []storedRule

	// CA certificate for HTTPS MITM
	caCert       *x509.Certificate
	caKey        *rsa.PrivateKey
	tlsConfigGen func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) // per-instance TLS config generator for MITM

	// Shutdown coordination
	closed atomic.Bool
}

// storedRule is the persistent format for rules.
type storedRule struct {
	ID      string `json:"id"`
	Label   string `json:"label,omitempty"`
	Type    string `json:"type"`
	IsRegex bool   `json:"is_regex"`
	Match   string `json:"match"`
	Replace string `json:"replace"`

	// compiled is the pre-compiled regex (nil if not a regex rule)
	compiled *regexp.Regexp
}

// Compile-time check that GoProxyBackend implements HttpBackend.
var _ HttpBackend = (*GoProxyBackend)(nil)

// NewGoProxyBackend creates a new built-in proxy backend.
// configDir is the directory for CA certificates (e.g., ~/.sectool).
func NewGoProxyBackend(port int, configDir string) (*GoProxyBackend, error) {
	b := &GoProxyBackend{
		historyStorage: store.NewMemStorage(),
		offsetToKey:    make(map[uint32]string),
	}

	// Load or generate CA certificate
	if err := b.loadOrGenerateCA(configDir); err != nil {
		return nil, fmt.Errorf("CA setup: %w", err)
	}

	// Initialize goproxy
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	// Configure HTTPS MITM
	if err := b.configureMITM(proxy); err != nil {
		return nil, fmt.Errorf("MITM setup: %w", err)
	}

	// Install request/response handlers
	b.installHandlers(proxy)
	b.proxy = proxy

	// Start HTTP server
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	b.listener = listener
	b.addr = listener.Addr().String()

	// Wrap goproxy with WebSocket-aware handler for connection hijacking
	wsHandler := &wsAwareHandler{backend: b, proxy: proxy}
	b.server = &http.Server{
		Handler:      wsHandler,
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 5 * time.Minute,
	}

	go func() {
		if err := b.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Sprintf("goproxy: server error: %v", err))
		}
	}()

	log.Printf("goproxy: built-in proxy listening on %s", b.addr)
	return b, nil
}

// Addr returns the proxy listener address (e.g., "127.0.0.1:12345").
func (b *GoProxyBackend) Addr() string {
	return b.addr
}

func (b *GoProxyBackend) Close() error {
	if b.closed.Swap(true) {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var errs []error
	if b.server != nil {
		if err := b.server.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("server shutdown: %w", err))
		}
	}
	if b.historyStorage != nil {
		b.historyStorage.Close()
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (b *GoProxyBackend) GetProxyHistory(ctx context.Context, count int, offset uint32) ([]ProxyEntry, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var result []ProxyEntry
	for off := offset; off < b.nextOffset && len(result) < count; off++ {
		key, ok := b.offsetToKey[off]
		if !ok {
			continue
		}

		data, found, err := b.historyStorage.Load(key)
		if err != nil {
			return nil, fmt.Errorf("load history entry %d: %w", off, err)
		} else if !found {
			continue
		}

		var entry ProxyEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			return nil, fmt.Errorf("unmarshal history entry %d: %w", off, err)
		}
		result = append(result, entry)
	}

	return result, nil
}

func (b *GoProxyBackend) SendRequest(ctx context.Context, name string, req SendRequestInput) (*SendRequestResult, error) {
	scheme := schemeHTTP
	if req.Target.UsesHTTPS {
		scheme = schemeHTTPS
	}
	log.Printf("goproxy: sending request %s to %s://%s:%d (follow_redirects=%v)",
		name, scheme, req.Target.Hostname, req.Target.Port, req.FollowRedirects)

	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	if req.FollowRedirects {
		return FollowRedirects(ctx, req, time.Now(), 10, b.sendSingle)
	}
	return b.sendSingle(ctx, req, time.Now())
}

// sendSingle sends a single HTTP request and returns the response.
//
// Wire format note: This uses net/http which normalizes headers (canonical casing,
// map-based ordering). Exact wire-level fidelity (header order, original casing,
// duplicate header formatting) is not preserved. The implementation minimizes
// mutation by disabling compression injection and HTTP/2 upgrades.
func (b *GoProxyBackend) sendSingle(ctx context.Context, req SendRequestInput, start time.Time) (*SendRequestResult, error) {
	// Parse raw request
	httpReq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(req.RawRequest)))
	if err != nil {
		return nil, fmt.Errorf("parse request: %w", err)
	}

	// Set the URL
	scheme := schemeHTTP
	if req.Target.UsesHTTPS {
		scheme = schemeHTTPS
	}
	httpReq.URL.Scheme = scheme
	httpReq.URL.Host = fmt.Sprintf("%s:%d", req.Target.Hostname, req.Target.Port)
	httpReq.RequestURI = "" // Must clear for client requests

	body, err := io.ReadAll(httpReq.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	_ = httpReq.Body.Close()
	httpReq.Body = io.NopCloser(bytes.NewReader(body))

	// Create HTTP client with settings to preserve wire format as closely as possible
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   false, // Prevent HTTP/2 upgrade to match HTTP/1.1 request format
		DisableCompression:  true,  // Prevent Accept-Encoding injection
		Proxy:               nil,   // Ignore environment proxy settings
		MaxIdleConnsPerHost: -1,    // Disable connection pooling
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer transport.CloseIdleConnections()

	httpReq = httpReq.WithContext(ctx)
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Dump response
	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, fmt.Errorf("dump response: %w", err)
	}

	headers, respBody := splitHeadersBody(respDump)
	return &SendRequestResult{
		Headers:  headers,
		Body:     respBody,
		Duration: time.Since(start),
	}, nil
}

func (b *GoProxyBackend) ListRules(ctx context.Context, websocket bool) ([]protocol.RuleEntry, error) {
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

func (b *GoProxyBackend) AddRule(ctx context.Context, input ProxyRuleInput) (*protocol.RuleEntry, error) {
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

	rule := storedRule{
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

func (b *GoProxyBackend) UpdateRule(ctx context.Context, idOrLabel string, input ProxyRuleInput) (*protocol.RuleEntry, error) {
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

func (b *GoProxyBackend) DeleteRule(ctx context.Context, idOrLabel string) error {
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
func (b *GoProxyBackend) findRule(idOrLabel string) (*storedRule, bool) {
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
func (b *GoProxyBackend) labelExists(label string) bool {
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
func (b *GoProxyBackend) labelExistsExcluding(label, excludeID string) bool {
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

// storeHistoryEntry stores a request/response pair in proxy history.
func (b *GoProxyBackend) storeHistoryEntry(req, resp string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	entry := ProxyEntry{
		Request:  req,
		Response: resp,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal history entry: %w", err)
	}

	offset := b.nextOffset
	key := fmt.Sprintf("%s%d", proxyHistoryPrefix, offset)

	if err := b.historyStorage.Save(key, data); err != nil {
		return fmt.Errorf("store history entry: %w", err)
	}

	// Update tracking state only after successful storage
	b.offsetToKey[offset] = key
	b.nextOffset++
	return nil
}

// loadOrGenerateCA loads existing CA or generates a new one.
func (b *GoProxyBackend) loadOrGenerateCA(configDir string) error {
	certPath := filepath.Join(configDir, caCertFile)
	keyPath := filepath.Join(configDir, caKeyFile)

	// Check file existence
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	certExists := certErr == nil
	keyExists := keyErr == nil

	// Error if only one file exists (orphaned state)
	if certExists != keyExists {
		if certExists {
			return fmt.Errorf("CA certificate exists at %s but key is missing at %s; delete both to regenerate", certPath, keyPath)
		}
		return fmt.Errorf("CA key exists at %s but certificate is missing at %s; delete both to regenerate", keyPath, certPath)
	}

	// Both missing - generate new CA
	if !certExists {
		log.Printf("goproxy: generating new CA certificate")
		return b.generateCA(configDir)
	}

	// Both exist - load them
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return errors.New("failed to parse CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("failed to parse CA key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA key: %w", err)
	}

	// Validate certificate properties
	if !cert.IsCA {
		return fmt.Errorf("certificate at %s is not a CA certificate; delete both files to regenerate", certPath)
	} else if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("certificate at %s lacks KeyUsageCertSign; delete both files to regenerate", certPath)
	} else if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("certificate at %s has expired; delete both files to regenerate", certPath)
	}

	b.caCert = cert
	b.caKey = key
	log.Printf("goproxy: loaded CA certificate from %s", certPath)
	return nil
}

func (b *GoProxyBackend) generateCA(configDir string) error {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	// Create CA certificate template
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"sectool"},
			CommonName:   "sectool CA",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	// Parse back the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	// Ensure config directory exists
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	// Write certificate
	certPath := filepath.Join(configDir, caCertFile)
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create cert file: %w", err)
	}
	defer func() { _ = certFile.Close() }()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	// Write key (restricted permissions)
	keyPath := filepath.Join(configDir, caKeyFile)
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer func() { _ = keyFile.Close() }()
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	b.caCert = cert
	b.caKey = key
	log.Printf("goproxy: generated CA certificate at %s", certPath)
	return nil
}

// configureMITM sets up HTTPS interception using the CA certificate.
// Uses per-instance TLS config instead of goproxy globals for isolation.
func (b *GoProxyBackend) configureMITM(proxy *goproxy.ProxyHttpServer) error {
	tlsCert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.caCert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(b.caKey)}),
	)
	if err != nil {
		return fmt.Errorf("create TLS cert: %w", err)
	}

	// Store per-instance TLS config generator
	b.tlsConfigGen = goproxy.TLSConfigFromCA(&tlsCert)

	// Create per-instance MITM handler instead of using goproxy globals
	mitmAction := &goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: b.tlsConfigGen,
	}

	proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return mitmAction, host
	})

	return nil
}

// installHandlers sets up request/response interception for regular HTTP.
// WebSocket over plain HTTP is handled by wsAwareHandler before goproxy sees it.
// WebSocket over HTTPS (MITM) is handled by goproxy's native 101 handling;
// frame-level rule application is not supported for HTTPS WebSocket.
func (b *GoProxyBackend) installHandlers(proxy *goproxy.ProxyHttpServer) {
	// Request handler - apply rules then capture modified request
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// Log warning for HTTPS WebSocket if rules exist (goproxy handles these
		// natively without frame-level rule support)
		if isWebSocketUpgrade(req) && b.hasWebSocketRules() {
			log.Printf("goproxy: HTTPS WebSocket detected; frame-level rules will not be applied (use ws:// for rule support)")
		}

		// Apply rules first
		var err error
		req, err = b.applyRequestRules(req)
		if err != nil {
			log.Printf("goproxy: failed to apply request rules: %v", err)
			return nil, goproxy.NewResponse(req, "text/plain", http.StatusBadGateway,
				fmt.Sprintf("proxy error: %v", err))
		}

		// Capture modified request for history (what was actually sent)
		reqDump, err := httputil.DumpRequest(req, true)
		if err != nil {
			log.Printf("goproxy: failed to dump request: %v", err)
			return req, nil
		}
		ctx.UserData = string(reqDump)

		return req, nil
	})

	// Response handler - apply rules then capture modified response
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil {
			return nil
		}

		// Apply rules first
		var err error
		resp, err = b.applyResponseRules(resp)
		if err != nil {
			log.Printf("goproxy: failed to apply response rules: %v", err)
			// Continue with original response on error (best effort)
		}

		// Capture modified response for history (what was actually received after rules)
		reqStr, _ := ctx.UserData.(string)
		respDump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			log.Printf("goproxy: failed to dump response: %v", err)
			return resp
		}

		if err := b.storeHistoryEntry(reqStr, string(respDump)); err != nil {
			log.Printf("goproxy: failed to store history: %v", err)
		}

		return resp
	})
}

// hasWebSocketRules returns true if any WebSocket rules are configured.
func (b *GoProxyBackend) hasWebSocketRules() bool {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	return len(b.wsRules) > 0
}

// wsAwareHandler wraps goproxy to intercept WebSocket upgrades before goproxy processes them.
// This allows proper connection hijacking for bidirectional WebSocket proxying.
type wsAwareHandler struct {
	backend *GoProxyBackend
	proxy   *goproxy.ProxyHttpServer
}

func (h *wsAwareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isWebSocketUpgrade(r) {
		h.backend.handleWebSocket(w, r)
		return
	}
	h.proxy.ServeHTTP(w, r)
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// handleWebSocket hijacks the client connection and proxies WebSocket frames bidirectionally.
func (b *GoProxyBackend) handleWebSocket(w http.ResponseWriter, req *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket hijacking not supported", http.StatusInternalServerError)
		return
	}

	host := req.Host
	isSecure := req.TLS != nil || req.URL.Scheme == schemeHTTPS || req.URL.Scheme == "wss"

	// Connect to upstream and perform handshake
	upstreamConn, upstreamResp, err := b.dialWebSocket(req.Context(), host, isSecure, req)
	if err != nil {
		log.Printf("goproxy: websocket dial failed: %v", err)
		http.Error(w, fmt.Sprintf("WebSocket connection failed: %v", err), http.StatusBadGateway)
		return
	}

	// Store the upgrade request/response in history
	reqDump, _ := httputil.DumpRequest(req, false)
	respDump, _ := httputil.DumpResponse(upstreamResp, false)
	if err := b.storeHistoryEntry(string(reqDump), string(respDump)); err != nil {
		log.Printf("goproxy: failed to store websocket history: %v", err)
	}

	// Hijack the client connection
	clientConn, clientBuf, err := hijacker.Hijack()
	if err != nil {
		log.Printf("goproxy: websocket hijack failed: %v", err)
		_ = upstreamConn.Close()
		return
	}

	// Send 101 response to client, stripping extensions to match upstream request
	var respBuf bytes.Buffer
	respBuf.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	for name, values := range upstreamResp.Header {
		// Skip extensions header to match stripped request (ensures no compression)
		if strings.EqualFold(name, "Sec-WebSocket-Extensions") {
			continue
		}
		for _, v := range values {
			respBuf.WriteString(name + ": " + v + "\r\n")
		}
	}
	respBuf.WriteString("\r\n")
	if _, err := clientConn.Write(respBuf.Bytes()); err != nil {
		log.Printf("goproxy: failed to send websocket upgrade response: %v", err)
		_ = clientConn.Close()
		_ = upstreamConn.Close()
		return
	}

	// Start bidirectional proxy
	proxy := &wsProxy{
		backend:      b,
		clientConn:   clientConn,
		clientBuf:    clientBuf,
		upstreamConn: upstreamConn,
	}
	proxy.run()
}

// wsProxy handles bidirectional WebSocket frame proxying with rule application.
type wsProxy struct {
	backend      *GoProxyBackend
	clientConn   net.Conn
	clientBuf    *bufio.ReadWriter
	upstreamConn net.Conn
	closeOnce    sync.Once
	done         chan struct{} // signals all goroutines to exit
}

func (p *wsProxy) run() {
	p.done = make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)

	// Client → Upstream: proxy acts as client, MUST mask per RFC 6455 §5.1
	go func() {
		defer wg.Done()
		p.proxyFrames(p.clientBuf, p.upstreamConn, "ws:to-server", true)
	}()

	// Upstream → Client: proxy acts as server, MUST NOT mask per RFC 6455 §5.1
	go func() {
		defer wg.Done()
		p.proxyFrames(bufio.NewReader(p.upstreamConn), p.clientConn, "ws:to-client", false)
	}()

	wg.Wait()
	p.close()
}

// proxyFrames reads frames from src and writes to dst, applying rules.
// outputMasked indicates whether to mask frames when encoding (per RFC 6455).
//
// Rules are only applied to complete, uncompressed text frames per RFC 6455:
//   - opcode=1 (text frame), FIN=1 (not fragmented), RSV=0 (no extensions active)
//
// TODO - FUTURE - To support fragmented message rule application:
//   - Buffer frames until FIN=1 is received (track by opcode 1/2 start, 0 continuation)
//   - Reassemble payload from all fragments
//   - Apply rules to complete message
//   - Re-fragment if needed (may change frame boundaries)
//   - Handle interleaved control frames (ping/pong) during reassembly
//
// Current limitation: Rules do not apply to fragmented WebSocket messages.
func (p *wsProxy) proxyFrames(src io.Reader, dst net.Conn, direction string, outputMasked bool) {
	for {
		select {
		case <-p.done:
			return
		default:
		}

		frame, err := readWSFrame(src)
		if err != nil {
			p.close()
			return
		}

		// Apply rules only to complete, uncompressed text frames per RFC 6455 §5.4:
		// - opcode=1: text frame (not continuation opcode=0 or binary opcode=2)
		// - fin=true: final fragment (complete message, not part of fragmented sequence)
		// - rsv=0: no extension bits set (no compression like permessage-deflate)
		if frame.opcode == 1 && frame.fin && frame.rsv == 0 {
			frame.payload = p.backend.applyWSRules(frame.payload, direction)
		}

		// Set masking for output per RFC 6455
		frame.masked = outputMasked
		if outputMasked {
			// Generate fresh random mask for outgoing masked frames
			if _, err := io.ReadFull(rand.Reader, frame.mask[:]); err != nil {
				p.close()
				return
			}
		}

		encoded := encodeWSFrame(frame)
		if _, err := dst.Write(encoded); err != nil {
			p.close()
			return
		}

		// Handle close frame
		if frame.opcode == 8 {
			p.close()
			return
		}
	}
}

func (p *wsProxy) close() {
	p.closeOnce.Do(func() {
		close(p.done)
		// Close connections to unblock any pending reads
		_ = p.clientConn.Close()
		_ = p.upstreamConn.Close()
	})
}

// dialWebSocket establishes a WebSocket connection to the upstream server.
// Transforms proxy-form requests to origin-form per RFC 6455 §4.1 before sending.
func (b *GoProxyBackend) dialWebSocket(ctx context.Context, host string, isSecure bool, req *http.Request) (net.Conn, *http.Response, error) {
	if !strings.Contains(host, ":") {
		if isSecure {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	dialer := &net.Dialer{}
	var conn net.Conn
	var err error

	if isSecure {
		// Determine SNI server name: prefer URL hostname, fallback to Host header
		serverName := req.URL.Hostname()
		if serverName == "" {
			serverName, _, _ = net.SplitHostPort(req.Host)
			if serverName == "" {
				serverName = req.Host
			}
		}
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         serverName,
			},
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", host)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("dial: %w", err)
	}

	// Set deadline from context for write/read operations
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// Transform request to origin-form for upstream server per RFC 6455 §4.1.
	// Proxy clients may send proxy-form (GET http://host/path HTTP/1.1) but
	// upstream servers expect origin-form (GET /path HTTP/1.1).
	upstreamReq := req.Clone(req.Context())
	upstreamReq.RequestURI = "" // Clear to allow http.Request.Write to work

	// Preserve original Host header if present; only use dial address as fallback.
	// This avoids changing "Host: example.com" to "Host: example.com:80".
	if upstreamReq.Host == "" {
		upstreamReq.Host = host
	}

	// Strip WebSocket compression extensions to ensure rules can be applied to
	// uncompressed text frames. Without this, permessage-deflate would set RSV1
	// and payload would be compressed, making text rule application corrupt data.
	upstreamReq.Header.Del("Sec-WebSocket-Extensions")

	if err := upstreamReq.Write(conn); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("write request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), upstreamReq)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("read response: %w", err)
	}

	// Clear deadline after handshake; WebSocket frames have no timeout
	_ = conn.SetDeadline(time.Time{})

	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = conn.Close()
		return nil, resp, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return conn, resp, nil
}

// wsFrame represents a WebSocket frame.
type wsFrame struct {
	fin     bool
	rsv     byte // RSV1, RSV2, RSV3 bits (upper 3 bits of first byte after FIN)
	opcode  byte
	masked  bool
	mask    [4]byte
	payload []byte
}

// readWSFrame reads a single WebSocket frame from the reader.
func readWSFrame(r io.Reader) (*wsFrame, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	frame := &wsFrame{
		fin:    header[0]&0x80 != 0,
		rsv:    (header[0] >> 4) & 0x07, // extract RSV1, RSV2, RSV3
		opcode: header[0] & 0x0F,
		masked: header[1]&0x80 != 0,
	}

	length := uint64(header[1] & 0x7F)
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return nil, err
		}
		length = binary.BigEndian.Uint64(ext)
	}

	if length > maxWebSocketFrameSize {
		return nil, fmt.Errorf("frame payload too large: %d bytes (max %d)", length, maxWebSocketFrameSize)
	}

	if frame.masked {
		if _, err := io.ReadFull(r, frame.mask[:]); err != nil {
			return nil, err
		}
	}

	frame.payload = make([]byte, length)
	if _, err := io.ReadFull(r, frame.payload); err != nil {
		return nil, err
	}

	// Unmask payload
	if frame.masked {
		for i := range frame.payload {
			frame.payload[i] ^= frame.mask[i%4]
		}
	}

	return frame, nil
}

// encodeWSFrame encodes a WebSocket frame to bytes.
func encodeWSFrame(frame *wsFrame) []byte {
	var buf bytes.Buffer

	// First byte: FIN + RSV + opcode
	firstByte := frame.opcode | (frame.rsv << 4)
	if frame.fin {
		firstByte |= 0x80
	}
	buf.WriteByte(firstByte)

	// Second byte: mask flag + length
	length := len(frame.payload)
	var secondByte byte
	if frame.masked {
		secondByte |= 0x80
	}

	if length <= 125 {
		secondByte |= byte(length)
		buf.WriteByte(secondByte)
	} else if length <= 65535 {
		secondByte |= 126
		buf.WriteByte(secondByte)
		_ = binary.Write(&buf, binary.BigEndian, uint16(length))
	} else {
		secondByte |= 127
		buf.WriteByte(secondByte)
		_ = binary.Write(&buf, binary.BigEndian, uint64(length))
	}

	// Mask key and masked payload (if masked)
	if frame.masked {
		buf.Write(frame.mask[:])
		masked := make([]byte, length)
		for i := range frame.payload {
			masked[i] = frame.payload[i] ^ frame.mask[i%4]
		}
		buf.Write(masked)
	} else {
		buf.Write(frame.payload)
	}

	return buf.Bytes()
}

// applyWSRules applies WebSocket match/replace rules to text payload.
// Only called for text frames (opcode 1); binary frames bypass this entirely.
func (b *GoProxyBackend) applyWSRules(payload []byte, direction string) []byte {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	for _, rule := range b.wsRules {
		if rule.Type != "ws:both" && rule.Type != direction {
			continue
		}
		payload = applyMatchReplace(payload, rule)
	}
	return payload
}

// applyRequestRules applies match/replace rules to requests.
// Body is read once and all body rules applied before updating Content-Length.
func (b *GoProxyBackend) applyRequestRules(req *http.Request) (*http.Request, error) {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	var headerRules, bodyRules []storedRule
	for _, rule := range b.httpRules {
		switch rule.Type {
		case RuleTypeRequestHeader:
			headerRules = append(headerRules, rule)
		case RuleTypeRequestBody:
			bodyRules = append(bodyRules, rule)
		}
	}

	// Apply header rules including Host (which net/http stores in req.Host, not req.Header)
	for _, rule := range headerRules {
		req.Header, req.Host = b.applyRequestHeaderRule(req.Header, req.Host, rule)
	}

	if len(bodyRules) > 0 && req.Body != nil {
		body, err := io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		for _, rule := range bodyRules {
			body = applyMatchReplace(body, rule)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
		// Clear Transfer-Encoding to ensure consistent message framing
		req.TransferEncoding = nil
		req.Header.Del("Transfer-Encoding")
	}

	return req, nil
}

// applyResponseRules applies match/replace rules to responses.
// Handles Content-Encoding (gzip, deflate) transparently for body rules.
func (b *GoProxyBackend) applyResponseRules(resp *http.Response) (*http.Response, error) {
	b.rulesMu.RLock()
	defer b.rulesMu.RUnlock()

	var headerRules, bodyRules []storedRule
	for _, rule := range b.httpRules {
		switch rule.Type {
		case RuleTypeResponseHeader:
			headerRules = append(headerRules, rule)
		case RuleTypeResponseBody:
			bodyRules = append(bodyRules, rule)
		}
	}

	for _, rule := range headerRules {
		resp.Header = b.applyHeaderRule(resp.Header, rule)
	}

	if len(bodyRules) > 0 && resp.Body != nil {
		body, encoding, skipRules, err := readAndDecompressBody(resp)
		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}

		// Skip body rules if decompression failed (body is opaque)
		if !skipRules {
			for _, rule := range bodyRules {
				body = applyMatchReplace(body, rule)
			}

			// Re-compress if originally compressed, otherwise send uncompressed
			body, err = compressBody(body, encoding)
			if err != nil {
				// Compression failed; send uncompressed and update headers
				resp.Header.Del("Content-Encoding")
			}
		}

		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		// Clear Transfer-Encoding to ensure consistent message framing
		resp.TransferEncoding = nil
		resp.Header.Del("Transfer-Encoding")
	}

	return resp, nil
}

// readAndDecompressBody reads the response body, decompressing if needed.
// Returns the body, the original encoding (for re-compression), whether to skip
// body rules, and any error. skipRules is true when decompression fails - the
// body is returned as-is and should not be modified to avoid corruption.
func readAndDecompressBody(resp *http.Response) (body []byte, encoding string, skipRules bool, err error) {
	body, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, "", false, err
	}

	encoding = strings.ToLower(resp.Header.Get("Content-Encoding"))
	switch encoding {
	case "gzip":
		gr, gzErr := gzip.NewReader(bytes.NewReader(body))
		if gzErr != nil {
			log.Printf("goproxy: Content-Encoding gzip but decompression failed, skipping body rules: %v", gzErr)
			return body, encoding, true, nil
		}
		defer func() { _ = gr.Close() }()
		decompressed, readErr := io.ReadAll(gr)
		if readErr != nil {
			log.Printf("goproxy: gzip decompression read failed, skipping body rules: %v", readErr)
			return body, encoding, true, nil
		}
		return decompressed, encoding, false, nil

	case "deflate":
		fr := flate.NewReader(bytes.NewReader(body))
		defer func() { _ = fr.Close() }()
		decompressed, readErr := io.ReadAll(fr)
		if readErr != nil {
			log.Printf("goproxy: deflate decompression failed, skipping body rules: %v", readErr)
			return body, encoding, true, nil
		}
		return decompressed, encoding, false, nil

	default:
		return body, "", false, nil
	}
}

// compressBody compresses body with the specified encoding.
// Returns original body if encoding is empty or unknown.
func compressBody(body []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "gzip":
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write(body); err != nil {
			return body, err
		}
		if err := gw.Close(); err != nil {
			return body, err
		}
		return buf.Bytes(), nil

	case "deflate":
		var buf bytes.Buffer
		fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			return body, err
		}
		if _, err := fw.Write(body); err != nil {
			return body, err
		}
		if err := fw.Close(); err != nil {
			return body, err
		}
		return buf.Bytes(), nil

	default:
		return body, nil
	}
}

// applyRequestHeaderRule applies a rule to request headers including Host.
// net/http stores Host separately in req.Host, so we include it in serialization
// to allow rules to match "Host:" patterns. Returns modified headers and Host.
func (b *GoProxyBackend) applyRequestHeaderRule(header http.Header, host string, rule storedRule) (http.Header, string) {
	keys := bulk.MapKeysSlice(header)
	sort.Strings(keys)

	var headerBuf bytes.Buffer
	// Include Host first (standard position in HTTP requests)
	if host != "" {
		headerBuf.WriteString("Host: " + host + "\r\n")
	}
	for _, name := range keys {
		for _, v := range header[name] {
			headerBuf.WriteString(name + ": " + v + "\r\n")
		}
	}

	original := headerBuf.Bytes()
	modified := applyMatchReplace(original, rule)
	if bytes.Equal(modified, original) {
		return header, host
	}

	// Parse back, extracting Host separately
	result := make(http.Header)
	newHost := host
	for _, line := range strings.Split(string(modified), "\r\n") {
		if line == "" {
			continue
		}
		var name, value string
		if idx := strings.Index(line, ": "); idx > 0 {
			name, value = line[:idx], line[idx+2:]
		} else if idx := strings.Index(line, ":"); idx > 0 {
			name, value = line[:idx], strings.TrimSpace(line[idx+1:])
		} else {
			continue
		}
		if strings.EqualFold(name, "Host") {
			newHost = value
		} else {
			result[name] = append(result[name], value)
		}
	}
	return result, newHost
}

// applyHeaderRule applies a rule to headers (sorted keys for determinism).
func (b *GoProxyBackend) applyHeaderRule(header http.Header, rule storedRule) http.Header {
	keys := bulk.MapKeysSlice(header)
	sort.Strings(keys)

	var headerBuf bytes.Buffer
	for _, name := range keys {
		for _, v := range header[name] {
			headerBuf.WriteString(name + ": " + v + "\r\n")
		}
	}

	original := headerBuf.Bytes()
	modified := applyMatchReplace(original, rule)
	if bytes.Equal(modified, original) {
		return header
	}

	// Parse back preserving exact names and duplicates
	result := make(http.Header)
	for _, line := range strings.Split(string(modified), "\r\n") {
		if line == "" {
			continue
		}
		if idx := strings.Index(line, ": "); idx > 0 {
			result[line[:idx]] = append(result[line[:idx]], line[idx+2:])
		} else if idx := strings.Index(line, ":"); idx > 0 {
			result[line[:idx]] = append(result[line[:idx]], line[idx+1:])
		}
	}
	return result
}

// applyMatchReplace applies a match/replace rule to data.
func applyMatchReplace(input []byte, rule storedRule) []byte {
	if !rule.IsRegex {
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

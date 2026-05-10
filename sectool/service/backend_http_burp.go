package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/ids"
	"github.com/go-appsec/toolbox/sectool/service/mcp"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

const burpFlowIndexKeyPrefix = "b:off:"

// burpFlowRecord is the persisted form of a single offset's flow_id mapping.
type burpFlowRecord struct {
	FlowID     string    `msgpack:"f"`
	ObservedAt time.Time `msgpack:"o"`
	// Fingerprint is FNV-1a of the request bytes.
	Fingerprint uint64 `msgpack:"fp"`
}

// ErrConfigEditDisabled is returned when a write operation fails because config editing is not enabled.
var ErrConfigEditDisabled = errors.New("config editing disabled")

// BurpBackend implements HttpBackend using Burp Suite via MCP.
type BurpBackend struct {
	client    *mcp.BurpClient
	flowIndex *burpFlowIndex
}

// Compile-time check that BurpBackend implements HttpBackend
var _ HttpBackend = (*BurpBackend)(nil)

// ConnectBurpBackend creates a new Burp HttpBackend with the given MCP URL.
// storage backs the offset<->flow_id index for the lifetime of the backend.
func ConnectBurpBackend(ctx context.Context, url string, storage store.Storage, opts ...mcp.Option) (*BurpBackend, error) {
	backend := NewBurpBackend(mcp.New(url, opts...), storage)
	return backend, backend.Connect(ctx)
}

// NewBurpBackend creates a new Burp HttpBackend with the given MCP client and index storage.
func NewBurpBackend(client *mcp.BurpClient, storage store.Storage) *BurpBackend {
	return &BurpBackend{
		client:    client,
		flowIndex: newBurpFlowIndex(storage),
	}
}

// burpFlowIndex maps Burp offsets, observation timestamps, and request fingerprints to flow_ids.
// The fingerprint detects when a Burp UI delete shifts entries down into existing offsets so
// flow_id identity is preserved across reshuffles via byFingerprint.
type burpFlowIndex struct {
	mu             sync.RWMutex
	storage        store.Storage
	byOffset       map[int]burpFlowEntry
	byFlowID       map[string]int    // flow_id -> offset
	byFingerprint  map[uint64]string // fp -> flow_id, used to relocate shifted entries
	maxObservedOff int
	hasObserved    bool
}

type burpFlowEntry struct {
	flowID      string
	observedAt  time.Time
	fingerprint uint64
}

// newBurpFlowIndex constructs an index, recovering persisted state from storage.
func newBurpFlowIndex(storage store.Storage) *burpFlowIndex {
	idx := &burpFlowIndex{
		storage:       storage,
		byOffset:      make(map[int]burpFlowEntry),
		byFlowID:      make(map[string]int),
		byFingerprint: make(map[uint64]string),
	}
	idx.recover()
	return idx
}

// recover rebuilds in-memory maps from persisted b:off:<offset> records.
func (i *burpFlowIndex) recover() {
	for _, key := range i.storage.KeySet() {
		if !strings.HasPrefix(key, burpFlowIndexKeyPrefix) {
			continue
		}
		offsetStr := key[len(burpFlowIndexKeyPrefix):]
		offset, err := strconv.Atoi(offsetStr)
		if err != nil {
			continue
		}
		data, found, err := i.storage.Get(key)
		if err != nil || !found {
			continue
		}
		var rec burpFlowRecord
		if err := store.Deserialize(data, &rec); err != nil {
			log.Printf("burp index: recover deserialize %s: %v", key, err)
			continue
		}
		if rec.FlowID == "" || rec.Fingerprint == 0 {
			continue
		}
		i.byOffset[offset] = burpFlowEntry{
			flowID:      rec.FlowID,
			observedAt:  rec.ObservedAt.UTC(),
			fingerprint: rec.Fingerprint,
		}
		i.byFlowID[rec.FlowID] = offset
		i.byFingerprint[rec.Fingerprint] = rec.FlowID
		if !i.hasObserved || offset > i.maxObservedOff {
			i.maxObservedOff = offset
			i.hasObserved = true
		}
	}
}

// RegisterOrLookup resolves the flow_id and observation timestamp for a Burp entry at offset and request bytes.
// New content mints a fresh flow_id; matching content elsewhere relocates the existing flow_id.
func (i *burpFlowIndex) RegisterOrLookup(offset int, request string) (flowID string, observedAt time.Time) {
	fp := fnv1aHash(request)

	i.mu.Lock()
	defer i.mu.Unlock()

	if e, ok := i.byOffset[offset]; ok {
		if e.fingerprint == fp {
			i.advanceMaxLocked(offset)
			return e.flowID, e.observedAt
		}
		// drift, the cached entry's content no longer lives at this offset
		i.evictOffsetLocked(offset)
	}

	// Same content may have shifted from another offset (mid-history delete)
	if existingFlowID, ok := i.byFingerprint[fp]; ok {
		oldOff, hasOld := i.byFlowID[existingFlowID]
		var oldObservedAt time.Time
		if hasOld {
			if e, ok := i.byOffset[oldOff]; ok {
				oldObservedAt = e.observedAt
			}
			// remove the offset's mapping without marking its flow_id stale; the flow_id is being moved to a new offset
			delete(i.byOffset, offset)
			if err := i.storage.Delete(burpFlowIndexKey(offset)); err != nil {
				log.Printf("burp index: delete relocated record %d: %v", offset, err)
			}
		}
		if oldObservedAt.IsZero() {
			oldObservedAt = time.Now().UTC()
		}
		i.byOffset[offset] = burpFlowEntry{flowID: existingFlowID, observedAt: oldObservedAt, fingerprint: fp}
		i.byFlowID[existingFlowID] = offset
		i.persistRecordLocked(offset, existingFlowID, oldObservedAt, fp)
		i.advanceMaxLocked(offset)
		return existingFlowID, oldObservedAt
	}

	// new entry
	for {
		candidate := ids.Generate(ids.DefaultLength)
		if _, exists := i.byFlowID[candidate]; !exists {
			flowID = candidate
			break
		}
	}
	observedAt = time.Now().UTC()
	i.byOffset[offset] = burpFlowEntry{flowID: flowID, observedAt: observedAt, fingerprint: fp}
	i.byFlowID[flowID] = offset
	i.byFingerprint[fp] = flowID
	i.persistRecordLocked(offset, flowID, observedAt, fp)
	i.advanceMaxLocked(offset)
	return flowID, observedAt
}

// advanceMaxLocked bumps maxObservedOff if offset is higher. Caller must hold mu.
func (i *burpFlowIndex) advanceMaxLocked(offset int) {
	if !i.hasObserved || offset > i.maxObservedOff {
		i.maxObservedOff = offset
		i.hasObserved = true
	}
}

// evictOffsetLocked drops every cache reference (and the storage record) for
// the entry currently held at offset. Caller must hold mu.
func (i *burpFlowIndex) evictOffsetLocked(offset int) {
	e, ok := i.byOffset[offset]
	if !ok {
		return
	}
	delete(i.byOffset, offset)
	if i.byFlowID[e.flowID] == offset {
		delete(i.byFlowID, e.flowID)
	}
	if got, ok := i.byFingerprint[e.fingerprint]; ok && got == e.flowID {
		delete(i.byFingerprint, e.fingerprint)
	}
	if err := i.storage.Delete(burpFlowIndexKey(offset)); err != nil {
		log.Printf("burp index: delete record %d: %v", offset, err)
	}
}

// persistRecordLocked writes the offset's record to storage. Caller must hold mu.
func (i *burpFlowIndex) persistRecordLocked(offset int, flowID string, observedAt time.Time, fp uint64) {
	rec := burpFlowRecord{FlowID: flowID, ObservedAt: observedAt, Fingerprint: fp}
	data, err := store.Serialize(&rec)
	if err != nil {
		log.Printf("burp index: serialize record %d: %v", offset, err)
		return
	}
	if err := i.storage.Set(burpFlowIndexKey(offset), data); err != nil {
		log.Printf("burp index: persist record %d: %v", offset, err)
	}
}

// SweepTail evicts every cached offset >= fromOffset. Called after a Burp fetch returns fewer entries than requested,
// indicating the live history ends at fromOffset. Maintains maxObservedOff.
func (i *burpFlowIndex) SweepTail(fromOffset int) {
	i.mu.Lock()
	defer i.mu.Unlock()

	var toRemove []int
	for off := range i.byOffset {
		if off >= fromOffset {
			toRemove = append(toRemove, off)
		}
	}
	for _, off := range toRemove {
		i.evictOffsetLocked(off)
	}
	if i.hasObserved && i.maxObservedOff >= fromOffset {
		if fromOffset == 0 {
			i.hasObserved = false
			i.maxObservedOff = 0
		} else {
			i.maxObservedOff = fromOffset - 1
		}
	}
}

// fnv1aHash returns the 64-bit FNV-1a hash of s.
func fnv1aHash(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return h.Sum64()
}

// OffsetFor returns the burp offset for a flow_id, if known.
func (i *burpFlowIndex) OffsetFor(flowID string) (int, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	off, ok := i.byFlowID[flowID]
	return off, ok
}

// MaxObserved returns the highest offset registered, and whether anything has been observed.
func (i *burpFlowIndex) MaxObserved() (int, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	return i.maxObservedOff, i.hasObserved
}

// Count returns the number of observed entries.
func (i *burpFlowIndex) Count() int {
	i.mu.RLock()
	defer i.mu.RUnlock()

	return len(i.byOffset)
}

func burpFlowIndexKey(offset int) string {
	return burpFlowIndexKeyPrefix + strconv.Itoa(offset)
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

func (b *BurpBackend) GetProxyHistory(ctx context.Context, count int, afterFlowID string) ([]ProxyEntry, error) {
	startOffset, err := b.resolveCursor(afterFlowID)
	if err != nil {
		return nil, err
	}
	entries, fetchCount, err := b.fetchHistorySlice(ctx, count, startOffset)
	if err != nil {
		return nil, err
	}
	result := make([]ProxyEntry, 0, min(len(entries), count))
	for i, e := range entries {
		flowID, observedAt := b.flowIndex.RegisterOrLookup(startOffset+i, e.Request)
		if i >= count {
			continue // tail probe entry; cache is updated, but not returned
		}
		result = append(result, ProxyEntry{
			FlowID:    flowID,
			Timestamp: observedAt,
			Request:   e.Request,
			Response:  e.Response,
			Notes:     e.Notes,
		})
	}
	if len(entries) < fetchCount {
		// Burp returned fewer than requested: hit the live tail.
		b.flowIndex.SweepTail(startOffset + len(entries))
	}
	return result, nil
}

func (b *BurpBackend) GetProxyHistoryMeta(ctx context.Context, count int, afterFlowID string) ([]ProxyEntryMeta, error) {
	startOffset, err := b.resolveCursor(afterFlowID)
	if err != nil {
		return nil, err
	}
	entries, fetchCount, err := b.fetchHistorySlice(ctx, count, startOffset)
	if err != nil {
		return nil, err
	}
	result := make([]ProxyEntryMeta, 0, min(len(entries), count))
	for i, e := range entries {
		flowID, observedAt := b.flowIndex.RegisterOrLookup(startOffset+i, e.Request)
		if i >= count {
			continue
		}
		method, host, path := extractRequestMeta(e.Request)
		status := readResponseStatusCode([]byte(e.Response))
		_, respBody := splitHeadersBody([]byte(e.Response))
		result = append(result, ProxyEntryMeta{
			FlowID:    flowID,
			Timestamp: observedAt,
			Method:    method,
			Host:      host,
			Path:      path,
			Status:    status,
			RespLen:   len(respBody),
		})
	}
	if len(entries) < fetchCount {
		b.flowIndex.SweepTail(startOffset + len(entries))
	}
	return result, nil
}

// fetchHistorySlice retrieves up to `count` proxy history entries starting at `startOffset`.
// It may request an extra entry to detect the live tail and handles full history clears.
// Returns the fetched entries, the actual number requested, and any error.
func (b *BurpBackend) fetchHistorySlice(ctx context.Context, count, startOffset int) ([]mcp.ProxyHistoryEntry, int, error) {
	fetchCount := count
	if maxOff, ok := b.flowIndex.MaxObserved(); ok && maxOff >= startOffset+count {
		fetchCount = count + 1
	}
	entries, err := b.client.GetProxyHistory(ctx, fetchCount, startOffset)
	if err != nil {
		return nil, 0, err
	}
	if len(entries) == 0 && startOffset > 0 {
		// Burp returned nothing past the cursor; cached offsets below the cursor may also be stale
		probe, perr := b.client.GetProxyHistory(ctx, 1, 0) // Probe offset 0 to detect a full clear
		if perr != nil {
			return nil, 0, perr
		}
		if len(probe) == 0 {
			b.flowIndex.SweepTail(0)
		}
	}
	return entries, fetchCount, nil
}

func (b *BurpBackend) GetProxyEntry(ctx context.Context, flowID string) (*ProxyEntry, error) {
	offset, ok := b.flowIndex.OffsetFor(flowID)
	if !ok {
		return nil, ErrNotFound
	}
	entries, err := b.client.GetProxyHistory(ctx, 1, offset)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		// The slot is gone; this offset is past Burp's live tail
		b.flowIndex.SweepTail(offset)
		return nil, ErrNotFound
	}
	resolvedFlowID, observedAt := b.flowIndex.RegisterOrLookup(offset, entries[0].Request)
	if resolvedFlowID != flowID {
		// Drift detected at the cached offset; the requested flow_id is gone.
		return nil, ErrNotFound
	}
	return &ProxyEntry{
		FlowID:    flowID,
		Timestamp: observedAt,
		Request:   entries[0].Request,
		Response:  entries[0].Response,
		Notes:     entries[0].Notes,
	}, nil
}

func (b *BurpBackend) DeleteProxyEntries(ctx context.Context, flowIDs []string) (int, error) {
	return 0, ErrNotSupported
}

// resolveCursor maps a flow_id cursor to the next burp offset to fetch.
// Empty cursor or unknown flow_id starts at offset 0.
func (b *BurpBackend) resolveCursor(afterFlowID string) (int, error) {
	if afterFlowID == "" {
		return 0, nil
	}
	offset, ok := b.flowIndex.OffsetFor(afterFlowID)
	if !ok {
		return 0, nil
	}
	return offset + 1, nil
}

func (b *BurpBackend) SendRequest(ctx context.Context, name string, req SendRequestInput) (*SendRequestResult, error) {
	original := req.RawRequest
	var firstHopRequest []byte

	result, err := b.doSendRequest(ctx, name, req, &firstHopRequest)
	if err != nil {
		return nil, err
	}
	if len(firstHopRequest) > 0 && !bytes.Equal(original, firstHopRequest) {
		result.ModifiedRequest = firstHopRequest
	}
	return result, nil
}

// doSendRequest builds a closure that creates a Repeater tab for every request
// (including redirect hops) and sends via the appropriate protocol.
// Rules are applied per-hop inside the closure. firstHopRequest captures the
// post-rule bytes of the initial request for ModifiedRequest tracking.
func (b *BurpBackend) doSendRequest(ctx context.Context, name string, req SendRequestInput, firstHopRequest *[]byte) (*SendRequestResult, error) {
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

	// Closure creates a Repeater tab and sends for every request including redirect hops.
	// Rules are applied per-hop so redirect requests also get rule modifications.
	sender := func(ctx context.Context, r SendRequestInput, start time.Time) (*SendRequestResult, error) {
		if rules, err := b.ListRules(ctx, false); err == nil && len(rules) > 0 {
			r.RawRequest = applyRequestRulesToRaw(r.RawRequest, rules)
		}
		if hopCount == 0 {
			*firstHopRequest = r.RawRequest
		}
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
		":method": proxy.ExtractMethod(raw),
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
			Find:    r.StringMatch,
			Replace: r.StringReplace,
		})
	}
	return rules, nil
}

func (b *BurpBackend) AddRule(ctx context.Context, input protocol.RuleEntry) (*protocol.RuleEntry, error) {
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

	id := ids.Generate(ids.EntityLength)
	newRule := mcp.MatchReplaceRule{
		Category:      mcp.RuleCategoryLiteral,
		Comment:       formatSectoolComment(id, input.Label),
		Enabled:       true,
		RuleType:      ruleType,
		StringMatch:   input.Find,
		StringReplace: input.Replace,
	}
	if input.IsRegex {
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
		Find:    input.Find,
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
		return fmt.Errorf("%w: %w", ErrConfigEditDisabled, err)
	} else if err != nil {
		return err
	}

	return nil
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

// applyRequestRulesToRaw applies protocol-level request rules to raw HTTP bytes.
// Used by backends that read rules dynamically (e.g., Burp via MCP).
// Returns the original bytes unchanged if parsing fails (intentionally malformed requests).
func applyRequestRulesToRaw(rawRequest []byte, rules []protocol.RuleEntry) []byte {
	var headerRules, bodyRules []nativeStoredRule
	for _, r := range rules {
		stored := nativeStoredRule{
			Find:    r.Find,
			Replace: r.Replace,
			IsRegex: r.IsRegex,
		}
		if r.IsRegex {
			compiled, err := regexp.Compile(r.Find)
			if err != nil {
				continue
			}
			stored.compiled = compiled
		}
		switch r.Type {
		case RuleTypeRequestHeader:
			headerRules = append(headerRules, stored)
		case RuleTypeRequestBody:
			bodyRules = append(bodyRules, stored)
		}
	}
	if len(headerRules) == 0 && len(bodyRules) == 0 {
		return rawRequest
	}

	parsed, err := proxy.ParseRequest(bytes.NewReader(rawRequest))
	if err != nil {
		return rawRequest
	}

	// Apply header rules (case-insensitive for HTTP header matching)
	if len(headerRules) > 0 {
		var headerBuf bytes.Buffer
		for _, h := range parsed.Headers {
			headerBuf.WriteString(h.Name)
			headerBuf.WriteString(": ")
			headerBuf.WriteString(h.Value)
			headerBuf.WriteString("\r\n")
		}
		original := headerBuf.Bytes()
		modified := original
		for _, rule := range headerRules {
			modified = applyMatchReplaceRule(modified, rule, true)
		}
		if !bytes.Equal(modified, original) {
			parsed.Headers = parseHeadersFromText(modified)
		}
	}

	// Apply body rules with compression handling
	if len(bodyRules) > 0 && len(parsed.Body) > 0 {
		encoding := parsed.GetHeader("Content-Encoding")
		result := applyBodyRulesWithCompression(parsed.Body, encoding, bodyRules)
		if result.modified && result.err == nil {
			parsed.SetBody(result.body)
			if parsed.Wire == nil || !parsed.Wire.WasChunked {
				parsed.SetHeader("Content-Length", strconv.Itoa(len(result.body)))
			}
		}
	}

	var buf bytes.Buffer
	result := parsed.SerializeRaw(&buf)
	if bytes.Equal(rawRequest, result) {
		return rawRequest
	}
	return result
}

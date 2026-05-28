package proxy

import (
	"bytes"
	"cmp"
	"log"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/ids"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

const (
	historyKeyPrefix  = "proxy:history:f:"
	historyPayloadSuf = ":p"
)

func historyMetaKey(flowID string) string {
	return historyKeyPrefix + flowID
}

func historyPayloadKey(flowID string) string {
	return historyKeyPrefix + flowID + historyPayloadSuf
}

// orderedFlow is the in-memory ordering record for a stored history entry.
type orderedFlow struct {
	flowID    string
	timestamp time.Time
}

// lessOrder is the canonical (timestamp, flow_id) order. flow_id breaks ties so
// same-instant captures sort deterministically across recovery and platform clock resolution.
func lessOrder(aTime time.Time, aID string, bTime time.Time, bID string) bool {
	if !aTime.Equal(bTime) {
		return aTime.Before(bTime)
	}
	return aID < bID
}

// HistoryStore provides typed access to proxy history backed by store.Storage.
// Entries are keyed by flow_id; merge ordering uses (Timestamp, FlowID).
type HistoryStore struct {
	mu              sync.RWMutex
	storage         store.Storage
	flowOrder       []orderedFlow        // ordered by (timestamp, flowID) ascending
	timestampByFlow map[string]time.Time // flow_id -> timestamp, for cursor resolution
	captureFilter   atomic.Value         // stores CaptureFilter
}

// newHistoryStore creates a history store using the provided storage backend.
// Recovers in-memory ordering by scanning meta keys.
func newHistoryStore(storage store.Storage) *HistoryStore {
	h := &HistoryStore{
		storage:         storage,
		timestampByFlow: make(map[string]time.Time),
	}
	h.recover()
	return h
}

// recover rebuilds in-memory order from persisted meta keys.
func (h *HistoryStore) recover() {
	for _, key := range h.storage.KeySet() {
		if !strings.HasPrefix(key, historyKeyPrefix) || strings.HasSuffix(key, historyPayloadSuf) {
			continue
		}
		data, found, err := h.storage.Get(key)
		if err != nil || !found {
			continue
		}
		var meta HistoryMeta
		if err := store.Deserialize(data, &meta); err != nil {
			log.Printf("proxy: history recover deserialize error %s: %v", key, err)
			continue
		}
		if meta.FlowID == "" {
			continue
		}
		ts := meta.Timestamp.UTC()
		h.flowOrder = append(h.flowOrder, orderedFlow{flowID: meta.FlowID, timestamp: ts})
		h.timestampByFlow[meta.FlowID] = ts
	}
	slices.SortFunc(h.flowOrder, func(a, b orderedFlow) int {
		return cmp.Or(a.timestamp.Compare(b.timestamp), cmp.Compare(a.flowID, b.flowID))
	})
}

// Store mints a flow_id, assigns it to entry, persists, and returns the flow_id. entry.Timestamp must be set by the caller.
func (h *HistoryStore) Store(entry *HistoryEntry) string {
	h.mu.Lock()
	defer h.mu.Unlock()

	flowID := h.mintUniqueFlowIDLocked()
	entry.FlowID = flowID
	ts := entry.Timestamp.UTC()
	entry.Timestamp = ts

	h.writeEntryLocked(entry)
	h.insertOrderLocked(orderedFlow{flowID: flowID, timestamp: ts})
	h.timestampByFlow[flowID] = ts
	return flowID
}

// mintUniqueFlowIDLocked generates a flow_id, retrying on collision. Caller must hold mu.
func (h *HistoryStore) mintUniqueFlowIDLocked() string {
	for {
		candidate := ids.Generate(ids.DefaultLength)
		if _, exists := h.timestampByFlow[candidate]; exists {
			continue
		} else if _, found, _ := h.storage.Get(historyMetaKey(candidate)); found {
			continue
		}
		return candidate
	}
}

// writeEntryLocked serializes and writes both payload and meta keys for an entry. Caller must hold mu.
func (h *HistoryStore) writeEntryLocked(entry *HistoryEntry) {
	meta := entry.extractMeta()
	metaData, err := store.Serialize(&meta)
	if err != nil {
		log.Printf("proxy: serialize history meta %s: %v", entry.FlowID, err)
		return
	}
	payloadData, err := store.Serialize(entry)
	if err != nil {
		log.Printf("proxy: serialize history entry %s: %v", entry.FlowID, err)
		return
	}
	// payload first, meta second: torn write leaves invisible orphan payload
	if err := h.storage.Set(historyPayloadKey(entry.FlowID), payloadData); err != nil {
		log.Printf("proxy: save history payload %s: %v", entry.FlowID, err)
		return
	}
	if err := h.storage.Set(historyMetaKey(entry.FlowID), metaData); err != nil {
		log.Printf("proxy: save history meta %s: %v", entry.FlowID, err)
	}
}

// insertOrderLocked inserts e into flowOrder, preserving (timestamp, flowID) ascending order.
// Caller must hold mu.
func (h *HistoryStore) insertOrderLocked(e orderedFlow) {
	idx := sort.Search(len(h.flowOrder), func(i int) bool {
		return !lessOrder(h.flowOrder[i].timestamp, h.flowOrder[i].flowID, e.timestamp, e.flowID)
	})
	h.flowOrder = slices.Insert(h.flowOrder, idx, e)
}

// Get retrieves an entry by flow_id.
func (h *HistoryStore) Get(flowID string) (*HistoryEntry, bool) {
	data, found, err := h.storage.Get(historyPayloadKey(flowID))
	if err != nil || !found {
		return nil, false
	}
	var entry HistoryEntry
	if err := store.Deserialize(data, &entry); err != nil {
		return nil, false
	}
	// msgpack timestamps lose timezone info; normalize to UTC
	entry.Timestamp = entry.Timestamp.UTC()
	return &entry, true
}

// GetMeta retrieves lightweight metadata for an entry by flow_id.
func (h *HistoryStore) GetMeta(flowID string) (*HistoryMeta, bool) {
	data, found, err := h.storage.Get(historyMetaKey(flowID))
	if err != nil || !found {
		return nil, false
	}
	var meta HistoryMeta
	if err := store.Deserialize(data, &meta); err != nil {
		return nil, false
	}
	meta.Timestamp = meta.Timestamp.UTC()
	return &meta, true
}

// Page returns up to count entries strictly after afterFlowID, ordered oldest-first.
func (h *HistoryStore) Page(count int, afterFlowID string) []*HistoryEntry {
	if count <= 0 {
		return nil
	}
	flowIDs := h.pageFlowIDs(count, afterFlowID)
	entries := make([]*HistoryEntry, 0, len(flowIDs))
	for _, fid := range flowIDs {
		if e, ok := h.Get(fid); ok {
			entries = append(entries, e)
		}
	}
	return entries
}

// PageMeta returns up to count meta entries strictly after afterFlowID, ordered oldest-first.
func (h *HistoryStore) PageMeta(count int, afterFlowID string) []HistoryMeta {
	if count <= 0 {
		return nil
	}
	flowIDs := h.pageFlowIDs(count, afterFlowID)
	metas := make([]HistoryMeta, 0, len(flowIDs))
	for _, fid := range flowIDs {
		if m, ok := h.GetMeta(fid); ok {
			metas = append(metas, *m)
		}
	}
	return metas
}

// pageFlowIDs returns up to count flow IDs after afterFlowID, oldest-first.
// Copies the slice while holding the lock so a concurrent Store cannot realloc the backing array.
func (h *HistoryStore) pageFlowIDs(count int, afterFlowID string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var startIdx int
	if afterFlowID != "" {
		if ts, ok := h.timestampByFlow[afterFlowID]; ok {
			startIdx = sort.Search(len(h.flowOrder), func(i int) bool {
				return lessOrder(ts, afterFlowID, h.flowOrder[i].timestamp, h.flowOrder[i].flowID)
			})
		}
	}
	end := min(startIdx+count, len(h.flowOrder))
	if startIdx >= end {
		return nil
	}
	flowIDs := make([]string, 0, end-startIdx)
	for i := startIdx; i < end; i++ {
		flowIDs = append(flowIDs, h.flowOrder[i].flowID)
	}
	return flowIDs
}

// Count returns the number of entries currently stored.
func (h *HistoryStore) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return len(h.flowOrder)
}

// Update persists changes to an existing entry.
// entry.FlowID must be set (from a prior Store).
func (h *HistoryStore) Update(entry *HistoryEntry) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if _, exists := h.timestampByFlow[entry.FlowID]; !exists {
		log.Printf("proxy: cannot update unknown history entry %s", entry.FlowID)
		return
	}
	h.writeEntryLocked(entry)
}

// Delete removes entries by flow_id. Idempotent; unknown ids are skipped.
// Returns the number of entries actually removed.
func (h *HistoryStore) Delete(flowIDs ...string) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	var deleted int
	for _, fid := range flowIDs {
		ts, ok := h.timestampByFlow[fid]
		if !ok {
			continue
		}
		if err := h.storage.Delete(historyMetaKey(fid)); err != nil {
			log.Printf("proxy: delete history meta %s: %v", fid, err)
			continue
		}
		if err := h.storage.Delete(historyPayloadKey(fid)); err != nil {
			log.Printf("proxy: delete history payload %s: %v", fid, err)
		}
		delete(h.timestampByFlow, fid)
		idx := sort.Search(len(h.flowOrder), func(i int) bool {
			return !lessOrder(h.flowOrder[i].timestamp, h.flowOrder[i].flowID, ts, fid)
		})
		if idx < len(h.flowOrder) && h.flowOrder[idx].flowID == fid {
			h.flowOrder = slices.Delete(h.flowOrder, idx, idx+1)
		}
		deleted++
	}
	return deleted
}

// Close closes the underlying storage.
func (h *HistoryStore) Close() {
	_ = h.storage.Close()
}

// extractMeta builds HistoryMeta from a HistoryEntry using existing accessor methods.
func (e *HistoryEntry) extractMeta() HistoryMeta {
	return HistoryMeta{
		FlowID:      e.FlowID,
		Protocol:    e.Protocol,
		Method:      e.GetMethod(),
		Host:        e.GetHost(),
		Path:        e.getFullPath(),
		Status:      e.GetStatusCode(),
		ContentType: e.GetResponseHeader("content-type"),
		RespLen:     e.responseBodyLen(),
		H2StreamID:  e.H2StreamID,
		Timestamp:   e.Timestamp,
		Duration:    e.Duration,
	}
}

// getFullPath returns path including query string for summary/meta display.
// For HTTP/1.1, concatenates Path + "?" + Query when Query is non-empty.
// For H2, Path already includes query.
func (e *HistoryEntry) getFullPath() string {
	switch e.Protocol {
	case "h2":
		if e.H2Request != nil {
			return e.H2Request.Path
		}
	default:
		if e.Request != nil {
			if e.Request.Query != "" {
				return e.Request.Path + "?" + e.Request.Query
			}
			return e.Request.Path
		}
	}
	return ""
}

// responseBodyLen returns the length of the response body.
func (e *HistoryEntry) responseBodyLen() int {
	switch e.Protocol {
	case "h2":
		if e.H2Response != nil {
			return len(e.H2Response.Body)
		}
	default:
		if e.Response != nil {
			return len(e.Response.Body)
		}
	}
	return 0
}

// FormatRequest returns the request in wire-compatible format.
// For HTTP/1.1, uses SerializeRaw to preserve anomalies like bare-LF.
// For HTTP/2, builds a similar text format from pseudo-headers and headers.
func (e *HistoryEntry) FormatRequest(buf *bytes.Buffer) []byte {
	switch e.Protocol {
	case "h2":
		if e.H2Request == nil {
			return nil
		}
		return formatH2Request(buf, e.H2Request)

	default:
		// HTTP/1.1 or websocket
		if e.Request == nil {
			return nil
		}
		return e.Request.SerializeRaw(buf)
	}
}

// FormatResponse returns the response in wire-compatible format.
// For HTTP/1.1, uses SerializeRaw to preserve anomalies like bare-LF.
// For HTTP/2, builds a similar text format from pseudo-headers and headers.
func (e *HistoryEntry) FormatResponse(buf *bytes.Buffer) []byte {
	switch e.Protocol {
	case "h2":
		if e.H2Response == nil {
			return nil
		}
		return formatH2Response(buf, e.H2Response)

	default:
		// HTTP/1.1 or websocket
		if e.Response == nil {
			return nil
		}
		return e.Response.SerializeRaw(buf)
	}
}

// GetMethod returns the request method for any protocol.
func (e *HistoryEntry) GetMethod() string {
	switch e.Protocol {
	case "h2":
		if e.H2Request != nil {
			return e.H2Request.Method
		}
	default:
		if e.Request != nil {
			return e.Request.Method
		}
	}
	return ""
}

// GetPath returns the URL path without query string for any protocol.
// For H2, strips the query portion since :path includes it.
func (e *HistoryEntry) GetPath() string {
	switch e.Protocol {
	case "h2":
		if e.H2Request != nil {
			if idx := strings.IndexByte(e.H2Request.Path, '?'); idx >= 0 {
				return e.H2Request.Path[:idx]
			}
			return e.H2Request.Path
		}
	default:
		if e.Request != nil {
			return e.Request.Path
		}
	}
	return ""
}

// GetHost returns the host for any protocol.
func (e *HistoryEntry) GetHost() string {
	switch e.Protocol {
	case "h2":
		if e.H2Request != nil {
			return e.H2Request.Authority
		}
	default:
		if e.Request != nil {
			return e.Request.GetHeader("Host")
		}
	}
	return ""
}

// GetStatusCode returns the response status code for any protocol.
func (e *HistoryEntry) GetStatusCode() int {
	switch e.Protocol {
	case "h2":
		if e.H2Response != nil {
			return e.H2Response.StatusCode
		}
	default:
		if e.Response != nil {
			return e.Response.StatusCode
		}
	}
	return 0
}

// GetRequestHeader returns a request header value (case-insensitive).
func (e *HistoryEntry) GetRequestHeader(name string) string {
	switch e.Protocol {
	case "h2":
		if e.H2Request != nil {
			return e.H2Request.GetHeader(name)
		}
	default:
		if e.Request != nil {
			return e.Request.GetHeader(name)
		}
	}
	return ""
}

// GetResponseHeader returns a response header value (case-insensitive).
func (e *HistoryEntry) GetResponseHeader(name string) string {
	switch e.Protocol {
	case "h2":
		if e.H2Response != nil {
			return e.H2Response.GetHeader(name)
		}
	default:
		if e.Response != nil {
			return e.Response.GetHeader(name)
		}
	}
	return ""
}

// formatH2Request formats an H2 request as HTTP/1.1 text for display and replay.
// Uses HTTP/1.1 version in the request line so it can be parsed by the standard
// HTTP/1.1 parser. The actual protocol ("h2") is tracked separately in HistoryEntry.Protocol.
func formatH2Request(buf *bytes.Buffer, req *H2RequestData) []byte {
	buf.Reset()

	// Request line - use HTTP/1.1 for parser compatibility; actual protocol tracked separately
	buf.WriteString(req.Method)
	buf.WriteByte(' ')
	buf.WriteString(req.Path)
	buf.WriteString(" HTTP/1.1\r\n")

	// Host from authority
	buf.WriteString("host: ")
	buf.WriteString(req.Authority)
	buf.WriteString("\r\n")

	for _, h := range req.Headers {
		buf.WriteString(h.Name)
		buf.WriteString(": ")
		buf.WriteString(h.Value)
		buf.WriteString("\r\n")
	}

	buf.WriteString("\r\n")
	buf.Write(req.Body)

	return buf.Bytes()
}

// formatH2Response formats an H2 response for display.
func formatH2Response(buf *bytes.Buffer, resp *H2ResponseData) []byte {
	buf.Reset()

	buf.WriteString("HTTP/2 ")
	buf.WriteString(strconv.Itoa(resp.StatusCode))
	text := http.StatusText(resp.StatusCode)
	if text != "" {
		buf.WriteByte(' ')
		buf.WriteString(text)
	}
	buf.WriteString("\r\n")

	for _, h := range resp.Headers {
		buf.WriteString(h.Name)
		buf.WriteString(": ")
		buf.WriteString(h.Value)
		buf.WriteString("\r\n")
	}

	buf.WriteString("\r\n")
	buf.Write(resp.Body)

	return buf.Bytes()
}

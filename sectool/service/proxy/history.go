package proxy

import (
	"bytes"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-appsec/toolbox/sectool/service/store"
)

const nextOffsetKey = "proxy:history:_next"

func historyMetaKey(offset uint32) string {
	return "proxy:history:" + strconv.FormatUint(uint64(offset), 10)
}

func historyPayloadKey(offset uint32) string {
	return "proxy:history:" + strconv.FormatUint(uint64(offset), 10) + ":p"
}

// HistoryStore provides typed access to proxy history backed by store.Storage.
type HistoryStore struct {
	mu            sync.RWMutex
	storage       store.Storage
	nextOffset    uint32
	captureFilter atomic.Value // stores CaptureFilter
}

// newHistoryStore creates a history store using the provided storage backend.
// Recovers nextOffset from storage so the store is usable after a reload.
func newHistoryStore(storage store.Storage) *HistoryStore {
	h := &HistoryStore{storage: storage}
	if data, found, err := storage.Get(nextOffsetKey); err == nil && found {
		if v, err := strconv.ParseUint(string(data), 10, 32); err == nil {
			h.nextOffset = uint32(v)
		}
	}
	return h
}

// Store adds an entry and assigns the next offset.
// Returns the assigned offset.
func (h *HistoryStore) Store(entry *HistoryEntry) uint32 {
	h.mu.Lock()
	defer h.mu.Unlock()

	offset := h.nextOffset
	h.nextOffset++

	// Persist counter before entry so offset is never reused on reload
	if err := h.storage.Set(nextOffsetKey, []byte(strconv.FormatUint(uint64(h.nextOffset), 10))); err != nil {
		log.Printf("proxy: failed to persist next offset: %v", err)
	}

	entry.Offset = offset
	h.writeEntry(entry)
	return offset
}

// writeEntry serializes and writes both meta and payload keys for an entry.
func (h *HistoryStore) writeEntry(entry *HistoryEntry) {
	meta := entry.extractMeta()
	if metaData, err := store.Serialize(&meta); err != nil {
		log.Printf("proxy: failed to serialize history meta %d: %v", entry.Offset, err)
	} else if payloadData, err := store.Serialize(entry); err != nil {
		log.Printf("proxy: failed to serialize history entry %d: %v", entry.Offset, err)
	} else if err := h.storage.Set(historyMetaKey(entry.Offset), metaData); err != nil {
		log.Printf("proxy: failed to save history meta %d: %v", entry.Offset, err)
	} else if err := h.storage.Set(historyPayloadKey(entry.Offset), payloadData); err != nil {
		log.Printf("proxy: failed to save history entry %d: %v", entry.Offset, err)
	}
}

// Get retrieves an entry by offset.
func (h *HistoryStore) Get(offset uint32) (*HistoryEntry, bool) {
	data, found, err := h.storage.Get(historyPayloadKey(offset))
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

// GetMeta retrieves lightweight metadata for an entry by offset.
func (h *HistoryStore) GetMeta(offset uint32) (*HistoryMeta, bool) {
	data, found, err := h.storage.Get(historyMetaKey(offset))
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

// List returns entries starting from startOffset, up to count.
// Returns entries in offset order.
func (h *HistoryStore) List(count int, startOffset uint32) []*HistoryEntry {
	h.mu.RLock()
	maxOffset := h.nextOffset
	h.mu.RUnlock()

	var entries []*HistoryEntry
	for offset := startOffset; offset < maxOffset && len(entries) < count; offset++ {
		if entry, ok := h.Get(offset); ok {
			entries = append(entries, entry)
		}
	}

	return entries
}

// ListMeta returns metadata for entries starting from startOffset, up to count.
// Only deserializes lightweight metadata, skipping full request/response bodies.
func (h *HistoryStore) ListMeta(count int, startOffset uint32) []HistoryMeta {
	h.mu.RLock()
	maxOffset := h.nextOffset
	h.mu.RUnlock()

	var metas []HistoryMeta
	for offset := startOffset; offset < maxOffset && len(metas) < count; offset++ {
		if meta, ok := h.GetMeta(offset); ok {
			metas = append(metas, *meta)
		}
	}
	return metas
}

// Count returns total number of entries.
func (h *HistoryStore) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return int(h.nextOffset)
}

// Update persists changes to an existing entry.
// The entry must have been previously stored (Offset must be valid).
func (h *HistoryStore) Update(entry *HistoryEntry) {
	h.mu.RLock()
	exists := entry.Offset < h.nextOffset
	h.mu.RUnlock()

	if !exists {
		log.Printf("proxy: cannot update non-existent history entry %d", entry.Offset)
		return
	}

	h.writeEntry(entry)
}

// Close closes the underlying storage.
func (h *HistoryStore) Close() {
	_ = h.storage.Close()
}

// extractMeta builds HistoryMeta from a HistoryEntry using existing accessor methods.
func (e *HistoryEntry) extractMeta() HistoryMeta {
	return HistoryMeta{
		Offset:      e.Offset,
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
		return e.Request.SerializeRaw(buf, false)
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
		return e.Response.SerializeRaw(buf, false)
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

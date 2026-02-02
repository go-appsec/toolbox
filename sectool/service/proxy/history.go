package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"

	"github.com/go-appsec/llm-security-toolbox/sectool/service/store"
)

// HistoryStore provides typed access to proxy history backed by store.Storage.
type HistoryStore struct {
	mu         sync.RWMutex
	storage    store.Storage
	nextOffset uint32
	offsetKeys map[uint32]string // offset → storage key
}

// newHistoryStore creates a history store using the provided storage backend.
func newHistoryStore(storage store.Storage) *HistoryStore {
	return &HistoryStore{
		storage:    storage,
		offsetKeys: make(map[uint32]string),
	}
}

// Store adds an entry and assigns the next offset.
// Returns the assigned offset.
func (h *HistoryStore) Store(entry *HistoryEntry) uint32 {
	h.mu.Lock()
	defer h.mu.Unlock()

	offset := h.nextOffset
	h.nextOffset++

	entry.Offset = offset
	key := fmt.Sprintf("proxy:history:%d", offset)
	h.offsetKeys[offset] = key

	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("proxy: failed to marshal history entry %d: %v", offset, err)
		return offset
	}

	if err := h.storage.Save(key, data); err != nil {
		log.Printf("proxy: failed to save history entry %d: %v", offset, err)
	}
	return offset
}

// Get retrieves an entry by offset.
func (h *HistoryStore) Get(offset uint32) (*HistoryEntry, bool) {
	h.mu.RLock()
	key, exists := h.offsetKeys[offset]
	h.mu.RUnlock()

	if !exists {
		return nil, false
	}

	data, found, err := h.storage.Load(key)
	if err != nil || !found {
		return nil, false
	}

	var entry HistoryEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}

	return &entry, true
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
	key, exists := h.offsetKeys[entry.Offset]
	h.mu.RUnlock()

	if !exists {
		log.Printf("proxy: cannot update non-existent history entry %d", entry.Offset)
		return
	}

	data, err := json.Marshal(entry)
	if err != nil {
		log.Printf("proxy: failed to marshal history entry %d for update: %v", entry.Offset, err)
		return
	}

	if err := h.storage.Save(key, data); err != nil {
		log.Printf("proxy: failed to update history entry %d: %v", entry.Offset, err)
	}
}

// Close closes the underlying storage.
func (h *HistoryStore) Close() {
	h.storage.Close()
}

// FormatRequest returns the request in wire-compatible format.
// For HTTP/1.1, uses SerializeRaw to preserve anomalies like bare-LF.
// For HTTP/2, builds a similar text format from pseudo-headers and headers.
func (e *HistoryEntry) FormatRequest() []byte {
	switch e.Protocol {
	case "h2":
		if e.H2Request == nil {
			return nil
		}
		return formatH2Request(e.H2Request)

	default:
		// HTTP/1.1 or websocket
		if e.Request == nil {
			return nil
		}
		var buf bytes.Buffer
		return e.Request.SerializeRaw(&buf, false)
	}
}

// FormatResponse returns the response in wire-compatible format.
// For HTTP/1.1, uses SerializeRaw to preserve anomalies like bare-LF.
// For HTTP/2, builds a similar text format from pseudo-headers and headers.
func (e *HistoryEntry) FormatResponse() []byte {
	switch e.Protocol {
	case "h2":
		if e.H2Response == nil {
			return nil
		}
		return formatH2Response(e.H2Response)

	default:
		// HTTP/1.1 or websocket
		if e.Response == nil {
			return nil
		}
		var buf bytes.Buffer
		return e.Response.SerializeRaw(&buf, false)
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

// GetPath returns the request path for any protocol.
func (e *HistoryEntry) GetPath() string {
	switch e.Protocol {
	case "h2":
		if e.H2Request != nil {
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
func formatH2Request(req *H2RequestData) []byte {
	var buf bytes.Buffer

	// Request line - use HTTP/1.1 for parser compatibility; actual protocol tracked separately
	buf.WriteString(req.Method)
	buf.WriteByte(' ')
	buf.WriteString(req.Path)
	buf.WriteString(" HTTP/1.1\r\n")

	// Host from authority
	buf.WriteString("host: ")
	buf.WriteString(req.Authority)
	buf.WriteString("\r\n")

	// Headers
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
func formatH2Response(resp *H2ResponseData) []byte {
	var buf bytes.Buffer

	// Status line
	buf.WriteString("HTTP/2 ")
	buf.WriteString(strconv.Itoa(resp.StatusCode))
	text := http.StatusText(resp.StatusCode)
	if text != "" {
		buf.WriteByte(' ')
		buf.WriteString(text)
	}
	buf.WriteString("\r\n")

	// Headers
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

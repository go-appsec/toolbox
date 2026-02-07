package store

import (
	"encoding/binary"
	"log"
	"sync"

	"github.com/go-appsec/llm-security-toolbox/sectool/service/ids"
)

const reverseKeyPrefix = "_r:"

// ProxyIndex is a bidirectional flowID <-> offset map for proxy history entries. Thread-safe.
type ProxyIndex struct {
	mu      sync.RWMutex
	storage Storage
	count   int
}

// NewProxyIndex creates a new ProxyIndex backed by the given storage.
func NewProxyIndex(storage Storage) *ProxyIndex {
	return &ProxyIndex{
		storage: storage,
	}
}

// Register creates a new flow_id for the given offset.
// If an entry with the same offset already exists, it returns the existing flow_id.
func (p *ProxyIndex) Register(offset uint32) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	rKey := reverseKey(offset)
	if data, found, _ := p.storage.Get(rKey); found {
		return string(data)
	}

	flowID := ids.Generate(ids.DefaultLength)
	for _, found, _ := p.storage.Get(flowID); found; _, found, _ = p.storage.Get(flowID) {
		flowID = ids.Generate(ids.DefaultLength)
	}

	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, offset)

	if err := p.storage.Set(flowID, buf); err != nil {
		log.Printf("proxy index save error: %v", err)
		return flowID
	}
	if err := p.storage.Set(rKey, []byte(flowID)); err != nil {
		log.Printf("proxy index save reverse error: %v", err)
		_ = p.storage.Delete(flowID) // rollback forward key
		return flowID
	}
	p.count++

	return flowID
}

// Offset retrieves the proxy history offset for a flow_id.
func (p *ProxyIndex) Offset(flowID string) (uint32, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	data, found, _ := p.storage.Get(flowID)
	if !found || len(data) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(data), true
}

// Clear removes all entries.
func (p *ProxyIndex) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.storage.DeleteAll(); err != nil {
		log.Printf("proxy index clear error: %v", err)
	}
	p.count = 0
}

// Count returns the number of registered flow IDs.
func (p *ProxyIndex) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.count
}

// Close releases storage resources.
func (p *ProxyIndex) Close() {
	_ = p.storage.Close()
}

func reverseKey(offset uint32) string {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, offset)
	return reverseKeyPrefix + string(buf)
}

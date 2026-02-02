package store

import (
	"slices"
	"sync"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/llm-security-toolbox/sectool/service/ids"
)

// FlowEntry represents a cached mapping from flow_id to Burp history offset.
type FlowEntry struct {
	Offset uint32 // Burp history offset
	Hash   string // Content hash for re-identification
}

// FlowStore manages the mapping between short flow IDs and Burp history offsets. Thread-safe.
type FlowStore struct {
	mu       sync.RWMutex
	byID     map[string]*FlowEntry // flow_id -> entry
	byHash   map[string][]string   // hash -> []flow_id (collision handling)
	byOffset map[uint32]string     // offset -> flow_id (for updates)
}

// NewFlowStore creates a new empty FlowStore.
func NewFlowStore() *FlowStore {
	return &FlowStore{
		byID:     make(map[string]*FlowEntry),
		byHash:   make(map[string][]string),
		byOffset: make(map[uint32]string),
	}
}

// Register creates a new flow_id for the given offset and hash.
// If an entry with the same offset already exists, it returns the existing flow_id.
func (s *FlowStore) Register(offset uint32, hash string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existingID, ok := s.byOffset[offset]; ok {
		return existingID
	}

	flowID := ids.Generate(ids.DefaultLength)
	for s.byID[flowID] != nil {
		flowID = ids.Generate(ids.DefaultLength)
	}

	s.byID[flowID] = &FlowEntry{
		Offset: offset,
		Hash:   hash,
	}
	s.byOffset[offset] = flowID

	if hash != "" {
		s.byHash[hash] = append(s.byHash[hash], flowID)
	}

	return flowID
}

// Lookup retrieves a FlowEntry by flow_id.
// Returns nil and false if not found.
func (s *FlowStore) Lookup(flowID string) (*FlowEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.byID[flowID]
	if !ok {
		return nil, false
	}

	// Return a copy to prevent external modification
	entryCopy := *entry
	return &entryCopy, true
}

// LookupByHash finds flow_ids with matching hash.
// Returns empty slice if not found. Useful for re-identification after offset shifts.
func (s *FlowStore) LookupByHash(hash string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return slices.Clone(s.byHash[hash])
}

// LookupByOffset finds the flow_id for a given offset.
func (s *FlowStore) LookupByOffset(offset uint32) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	flowID, ok := s.byOffset[offset]
	return flowID, ok
}

// UpdateOffset updates the offset for an existing flow_id.
func (s *FlowStore) UpdateOffset(flowID string, newOffset uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.byID[flowID]
	if !ok {
		return false
	}

	delete(s.byOffset, entry.Offset)
	entry.Offset = newOffset
	s.byOffset[newOffset] = flowID

	return true
}

func (s *FlowStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.byID = make(map[string]*FlowEntry)
	s.byHash = make(map[string][]string)
	s.byOffset = make(map[uint32]string)
}

func (s *FlowStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.byID)
}

// AllFlowIDs returns all registered flow IDs.
func (s *FlowStore) AllFlowIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return bulk.MapKeysSlice(s.byID)
}

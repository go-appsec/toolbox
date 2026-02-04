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
	Source string // "proxy" or "replay"
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

// Register creates a new flow_id for the given offset, hash, and source.
// If an entry with the same offset already exists, it returns the existing flow_id.
// Source should be "proxy" or "replay".
func (s *FlowStore) Register(offset uint32, hash string, source string) string {
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
		Source: source,
	}
	s.byOffset[offset] = flowID

	if hash != "" {
		s.byHash[hash] = append(s.byHash[hash], flowID)
	}

	return flowID
}

// RegisterKnown registers a pre-assigned flow_id (e.g., from replay history).
// Does not use offset-based deduplication. Idempotent for the same flowID.
func (s *FlowStore) RegisterKnown(flowID, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.byID[flowID]; ok {
		return // already registered
	}

	s.byID[flowID] = &FlowEntry{
		Offset: 0, // not applicable for replays
		Source: source,
	}
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

// ClearBySource removes all entries with the given source (e.g., "proxy").
// Used when proxy history is cleared to invalidate stale flow IDs while keeping replay entries.
func (s *FlowStore) ClearBySource(source string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for flowID, entry := range s.byID {
		if entry.Source != source {
			continue
		}
		delete(s.byID, flowID)
		delete(s.byOffset, entry.Offset)
		if entry.Hash != "" {
			s.byHash[entry.Hash] = slices.DeleteFunc(s.byHash[entry.Hash], func(id string) bool {
				return id == flowID
			})
			if len(s.byHash[entry.Hash]) == 0 {
				delete(s.byHash, entry.Hash)
			}
		}
	}
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

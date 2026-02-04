package store

import (
	"sync"
	"time"
)

// ReplayHistoryEntry stores a replay request/response with positioning info.
type ReplayHistoryEntry struct {
	FlowID          string    // Same as replay_id from replay_send
	CreatedAt       time.Time // When replay was executed
	ReferenceOffset uint32    // Max proxy offset at time of replay (for ordering)

	// Request data (for display and export)
	RawRequest []byte
	Method     string
	Host       string
	Path       string
	Protocol   string // "http/1.1" or "h2"

	// Response data
	RespHeaders []byte
	RespBody    []byte
	RespStatus  int
	Duration    time.Duration

	// Lineage
	SourceFlowID string // Original flow_id that was replayed (empty for request_send)
}

// ReplayHistoryStore manages replay entries with thread-safe access.
type ReplayHistoryStore struct {
	mu              sync.RWMutex
	entries         []*ReplayHistoryEntry          // ordered by creation time
	byFlowID        map[string]*ReplayHistoryEntry // flowID -> entry
	lastKnownOffset uint32                         // for history clear detection
}

// NewReplayHistoryStore creates a new ReplayHistoryStore.
func NewReplayHistoryStore() *ReplayHistoryStore {
	return &ReplayHistoryStore{
		byFlowID: make(map[string]*ReplayHistoryEntry),
	}
}

// Store adds a replay entry. Called after successful replay_send/request_send.
func (s *ReplayHistoryStore) Store(entry *ReplayHistoryEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}
	s.entries = append(s.entries, entry)
	s.byFlowID[entry.FlowID] = entry
}

// Get retrieves a replay entry by flow_id.
func (s *ReplayHistoryStore) Get(flowID string) (*ReplayHistoryEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.byFlowID[flowID]
	return e, ok
}

// List returns all replay entries ordered by creation time.
func (s *ReplayHistoryStore) List() []*ReplayHistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*ReplayHistoryEntry, len(s.entries))
	copy(result, s.entries)
	return result
}

// UpdateReferenceOffset updates the max proxy offset and detects history clear.
// If history was cleared (offset decreased), marks all existing entries with ref=0.
// Returns the reference offset to use for new replay entries, and whether history was cleared.
func (s *ReplayHistoryStore) UpdateReferenceOffset(currentMaxOffset uint32) (uint32, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Detect history clear: current max is less than what we've seen
	var cleared bool
	if currentMaxOffset < s.lastKnownOffset && s.lastKnownOffset > 0 {
		// History was cleared - mark all existing entries to appear at top
		for _, e := range s.entries {
			e.ReferenceOffset = 0
		}
		cleared = true
	}

	s.lastKnownOffset = currentMaxOffset
	return currentMaxOffset, cleared
}

// Count returns the number of stored replay entries.
func (s *ReplayHistoryStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// Clear removes all entries.
func (s *ReplayHistoryStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = nil
	s.byFlowID = make(map[string]*ReplayHistoryEntry)
	s.lastKnownOffset = 0
}

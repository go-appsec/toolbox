package store

import (
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-analyze/bulk"
)

const replayPayloadSuffix = ":p"

// ReplayHistoryMeta holds lightweight metadata for a replay entry.
// Used by summary/list paths to avoid deserializing full request/response bodies.
type ReplayHistoryMeta struct {
	FlowID          string        `msgpack:"fid"`
	Method          string        `msgpack:"m"`
	Host            string        `msgpack:"h"`
	Path            string        `msgpack:"p"`
	Protocol        string        `msgpack:"pr"`
	SourceFlowID    string        `msgpack:"sf"`
	CreatedAt       time.Time     `msgpack:"ca"`
	ReferenceOffset uint32        `msgpack:"ro"`
	RespStatus      int           `msgpack:"rs"`
	RespLen         int           `msgpack:"rl"`
	Duration        time.Duration `msgpack:"d"`
}

// ReplayHistoryPayload holds the heavy request/response data for a replay entry.
type ReplayHistoryPayload struct {
	RawRequest  []byte `msgpack:"rq"`
	RespHeaders []byte `msgpack:"rh"`
	RespBody    []byte `msgpack:"rb"`
}

// ReplayHistoryEntry stores a replay request/response with positioning info.
type ReplayHistoryEntry struct {
	FlowID          string
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
	storage         Storage
	mu              sync.RWMutex
	count           int
	lastKnownOffset uint32 // for history clear detection
}

// NewReplayHistoryStore creates a new ReplayHistoryStore backed by the given storage.
func NewReplayHistoryStore(storage Storage) *ReplayHistoryStore {
	return &ReplayHistoryStore{
		storage: storage,
	}
}

// Store adds a replay entry. Called after successful replay_send/request_send.
func (s *ReplayHistoryStore) Store(entry *ReplayHistoryEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}

	meta := ReplayHistoryMeta{
		FlowID:          entry.FlowID,
		Method:          entry.Method,
		Host:            entry.Host,
		Path:            entry.Path,
		Protocol:        entry.Protocol,
		SourceFlowID:    entry.SourceFlowID,
		CreatedAt:       entry.CreatedAt,
		ReferenceOffset: entry.ReferenceOffset,
		RespStatus:      entry.RespStatus,
		RespLen:         len(entry.RespBody),
		Duration:        entry.Duration,
	}
	payload := ReplayHistoryPayload{
		RawRequest:  entry.RawRequest,
		RespHeaders: entry.RespHeaders,
		RespBody:    entry.RespBody,
	}

	if metaData, err := Serialize(&meta); err != nil {
		log.Printf("replay history store serialize meta error: %v", err)
		return
	} else if payloadData, err := Serialize(&payload); err != nil {
		log.Printf("replay history store serialize payload error: %v", err)
		return
	} else if err := s.storage.Set(entry.FlowID, metaData); err != nil {
		log.Printf("replay history store save meta error: %v", err)
		return
	} else if err := s.storage.Set(entry.FlowID+replayPayloadSuffix, payloadData); err != nil {
		log.Printf("replay history store save payload error: %v", err)
		_ = s.storage.Delete(entry.FlowID) // rollback meta key
		return
	}
	s.count++
}

// Get retrieves a replay entry by flow_id.
func (s *ReplayHistoryStore) Get(flowID string) (*ReplayHistoryEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.getLocked(flowID)
}

// getLocked retrieves a replay entry. Caller must hold mu.
func (s *ReplayHistoryStore) getLocked(flowID string) (*ReplayHistoryEntry, bool) {
	metaData, found, err := s.storage.Get(flowID)
	if err != nil || !found {
		return nil, false
	}
	var meta ReplayHistoryMeta
	if err := Deserialize(metaData, &meta); err != nil {
		log.Printf("replay history store deserialize meta error: %v", err)
		return nil, false
	}

	payloadData, found, err := s.storage.Get(flowID + replayPayloadSuffix)
	if err != nil || !found {
		return nil, false
	}
	var payload ReplayHistoryPayload
	if err := Deserialize(payloadData, &payload); err != nil {
		log.Printf("replay history store deserialize payload error: %v", err)
		return nil, false
	}

	return &ReplayHistoryEntry{
		FlowID:          meta.FlowID,
		CreatedAt:       meta.CreatedAt,
		ReferenceOffset: meta.ReferenceOffset,
		RawRequest:      payload.RawRequest,
		Method:          meta.Method,
		Host:            meta.Host,
		Path:            meta.Path,
		Protocol:        meta.Protocol,
		RespHeaders:     payload.RespHeaders,
		RespBody:        payload.RespBody,
		RespStatus:      meta.RespStatus,
		Duration:        meta.Duration,
		SourceFlowID:    meta.SourceFlowID,
	}, true
}

// metaKeys returns all meta keys (excluding payload keys). Caller must hold mu.
func (s *ReplayHistoryStore) metaKeys() []string {
	return bulk.SliceFilterInPlace(func(k string) bool {
		return !strings.HasSuffix(k, replayPayloadSuffix)
	}, s.storage.KeySet())
}

// List returns all replay entries ordered by creation time.
func (s *ReplayHistoryStore) List() []*ReplayHistoryEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := s.metaKeys()
	result := make([]*ReplayHistoryEntry, 0, len(keys))
	for _, key := range keys {
		if entry, ok := s.getLocked(key); ok {
			result = append(result, entry)
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result
}

// ListMeta returns lightweight metadata for all replay entries, ordered by creation time.
func (s *ReplayHistoryStore) ListMeta() []ReplayHistoryMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := s.metaKeys()
	result := make([]ReplayHistoryMeta, 0, len(keys))
	for _, key := range keys {
		data, found, err := s.storage.Get(key)
		if err != nil || !found {
			continue
		}
		var meta ReplayHistoryMeta
		if err := Deserialize(data, &meta); err != nil {
			continue
		}
		result = append(result, meta)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
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
		// History was cleared - only iterate meta keys, rewrite only meta
		for _, key := range s.metaKeys() {
			data, found, err := s.storage.Get(key)
			if err != nil || !found {
				continue
			}
			var meta ReplayHistoryMeta
			if err := Deserialize(data, &meta); err != nil {
				continue
			}
			meta.ReferenceOffset = 0
			if data, err = Serialize(&meta); err != nil {
				log.Printf("replay history store serialize error: %v", err)
				continue
			} else if err := s.storage.Set(key, data); err != nil {
				log.Printf("replay history store save error: %v", err)
			}
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

	return s.count
}

// Clear removes all entries.
func (s *ReplayHistoryStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lastKnownOffset = 0
	s.count = 0
	if err := s.storage.DeleteAll(); err != nil {
		log.Printf("replay history store clear error: %v", err)
	}
}

// Close releases storage resources.
func (s *ReplayHistoryStore) Close() {
	_ = s.storage.Close()
}

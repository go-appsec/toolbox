package store

import (
	"cmp"
	"context"
	"log"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-analyze/bulk"
)

const replayPayloadSuffix = ":p"

// ReplayHistoryMeta holds lightweight metadata for a replay entry.
// Used by summary/list paths to avoid deserializing full request/response bodies.
type ReplayHistoryMeta struct {
	FlowID       string        `msgpack:"fid"`
	Method       string        `msgpack:"m"`
	Host         string        `msgpack:"h"`
	Path         string        `msgpack:"p"`
	Scheme       string        `msgpack:"sc,omitempty"` // "http" or "https"
	Port         int           `msgpack:"po,omitempty"` // original port (0 = infer from scheme)
	Protocol     string        `msgpack:"pr"`
	SourceFlowID string        `msgpack:"sf"`
	CreatedAt    time.Time     `msgpack:"ca"`
	RespStatus   int           `msgpack:"rs"`
	RespLen      int           `msgpack:"rl"`
	Duration     time.Duration `msgpack:"d"`
	// Annotations carries sidecar-authored flow metadata; nil for native sends.
	Annotations map[string]any `msgpack:"an,omitempty"`
	// InvokedBy names the sidecar that originated a native send via invoke_adapter.
	InvokedBy string `msgpack:"ib,omitempty"`
	// Adapter names the sidecar that performed a replay; empty for native sends.
	Adapter string `msgpack:"ad,omitempty"`
}

// ReplayHistoryPayload holds the heavy request/response data for a replay entry.
type ReplayHistoryPayload struct {
	RawRequest      []byte `msgpack:"rq"`
	ModifiedRequest []byte `msgpack:"mq,omitempty"` // post-rule request; nil if no rules applied
	RespHeaders     []byte `msgpack:"rh"`
	RespBody        []byte `msgpack:"rb"`
}

// ReplayHistoryEntry stores a replay request/response with positioning info.
type ReplayHistoryEntry struct {
	FlowID    string
	CreatedAt time.Time // When replay was executed

	// Request data (for display and export)
	RawRequest      []byte // pre-rule request (base for replay)
	ModifiedRequest []byte // post-rule request (what was sent); nil if no rules applied
	Method          string
	Host            string
	Path            string
	Scheme          string // "http" or "https"
	Port            int    // original port (0 = infer from scheme)
	Protocol        string // "http/1.1" or "http/2"

	// Response data
	RespHeaders []byte
	RespBody    []byte
	RespStatus  int
	Duration    time.Duration

	// Lineage
	SourceFlowID string // Original flow_id that was replayed (empty for request_send)

	// Annotations carries sidecar-authored flow metadata; nil for native sends.
	Annotations map[string]any
	// InvokedBy names the sidecar that originated a native send via invoke_adapter.
	InvokedBy string
	// Adapter names the sidecar that performed a replay; empty for native sends.
	Adapter string
}

// TODO - Consider combining the HistoryStore and ReplayHistoryStore into a single unified storage

// ReplayHistoryStore manages replay entries with thread-safe access.
type ReplayHistoryStore struct {
	storage Storage
	mu      sync.RWMutex
	count   int
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
	if s.persistLocked(entry) {
		s.count++
	}
}

// Complete attaches a response to an already-stored replay entry: the two-phase
// form used for deferred and streaming replays. A non-zero completedAt records the
// elapsed duration; annotations merge over existing keys. Returns false when flowID
// is unknown.
func (s *ReplayHistoryStore) Complete(flowID string, respHeaders, respBody []byte, status int, completedAt time.Time, annotations map[string]any) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.getLocked(flowID)
	if !ok {
		return false
	}
	entry.RespHeaders = respHeaders
	entry.RespBody = respBody
	entry.RespStatus = status
	if !completedAt.IsZero() {
		entry.Duration = completedAt.Sub(entry.CreatedAt)
	}
	if len(annotations) > 0 {
		if entry.Annotations == nil {
			entry.Annotations = make(map[string]any, len(annotations))
		}
		maps.Copy(entry.Annotations, annotations)
	}
	return s.persistLocked(entry)
}

// SetInvokedBy records the originating sidecar on an already-stored replay entry.
// Returns false when flowID is unknown.
func (s *ReplayHistoryStore) SetInvokedBy(flowID, invokedBy string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.getLocked(flowID)
	if !ok {
		return false
	}
	entry.InvokedBy = invokedBy
	return s.persistLocked(entry)
}

// persistLocked writes an entry to storage, returning false on failure.
// Caller must hold mu.
func (s *ReplayHistoryStore) persistLocked(entry *ReplayHistoryEntry) bool {
	meta := ReplayHistoryMeta{
		FlowID:       entry.FlowID,
		Method:       entry.Method,
		Host:         entry.Host,
		Path:         entry.Path,
		Scheme:       entry.Scheme,
		Port:         entry.Port,
		Protocol:     entry.Protocol,
		SourceFlowID: entry.SourceFlowID,
		CreatedAt:    entry.CreatedAt,
		RespStatus:   entry.RespStatus,
		RespLen:      len(entry.RespBody),
		Duration:     entry.Duration,
		Annotations:  entry.Annotations,
		InvokedBy:    entry.InvokedBy,
		Adapter:      entry.Adapter,
	}
	payload := ReplayHistoryPayload{
		RawRequest:      entry.RawRequest,
		ModifiedRequest: entry.ModifiedRequest,
		RespHeaders:     entry.RespHeaders,
		RespBody:        entry.RespBody,
	}

	if metaData, err := Serialize(&meta); err != nil {
		log.Printf("replay history store serialize meta error: %v", err)
		return false
	} else if payloadData, err := Serialize(&payload); err != nil {
		log.Printf("replay history store serialize payload error: %v", err)
		return false
	} else if err := s.storage.Set(entry.FlowID, metaData); err != nil {
		log.Printf("replay history store save meta error: %v", err)
		return false
	} else if err := s.storage.Set(entry.FlowID+replayPayloadSuffix, payloadData); err != nil {
		log.Printf("replay history store save payload error: %v", err)
		_ = s.storage.Delete(entry.FlowID) // rollback meta key
		return false
	}
	return true
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
		if err != nil {
			log.Printf("replay history store get meta %s: %v", flowID, err)
		}
		return nil, false
	}
	var meta ReplayHistoryMeta
	if err := Deserialize(metaData, &meta); err != nil {
		log.Printf("replay history store deserialize meta error: %v", err)
		return nil, false
	}

	payloadData, found, err := s.storage.Get(flowID + replayPayloadSuffix)
	if err != nil || !found {
		if err != nil {
			log.Printf("replay history store get payload %s: %v", flowID, err)
		}
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
		RawRequest:      payload.RawRequest,
		ModifiedRequest: payload.ModifiedRequest,
		Method:          meta.Method,
		Host:            meta.Host,
		Path:            meta.Path,
		Scheme:          meta.Scheme,
		Port:            meta.Port,
		Protocol:        meta.Protocol,
		RespHeaders:     payload.RespHeaders,
		RespBody:        payload.RespBody,
		RespStatus:      meta.RespStatus,
		Duration:        meta.Duration,
		SourceFlowID:    meta.SourceFlowID,
		Annotations:     meta.Annotations,
		InvokedBy:       meta.InvokedBy,
		Adapter:         meta.Adapter,
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

	slices.SortFunc(result, func(a, b *ReplayHistoryEntry) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), cmp.Compare(a.FlowID, b.FlowID))
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
			if err != nil {
				log.Printf("replay history store get meta %s: %v", key, err)
			}
			continue
		}
		var meta ReplayHistoryMeta
		if err := Deserialize(data, &meta); err != nil {
			continue
		}
		result = append(result, meta)
	}

	slices.SortFunc(result, func(a, b ReplayHistoryMeta) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), cmp.Compare(a.FlowID, b.FlowID))
	})
	return result
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

	s.count = 0
	if err := s.storage.DeleteAll(); err != nil {
		log.Printf("replay history store clear error: %v", err)
	}
}

// Delete removes replay entries by flow_id. Idempotent; unknown ids are skipped.
// Returns the number of entries actually removed.
func (s *ReplayHistoryStore) Delete(flowIDs []string) int {
	if len(flowIDs) == 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var deleted int
	for _, fid := range flowIDs {
		if _, found, err := s.storage.Get(fid); err != nil || !found {
			if err != nil {
				log.Printf("replay history store get %s: %v", fid, err)
			}
			continue
		}
		if err := s.storage.Delete(fid); err != nil {
			log.Printf("replay history store delete meta %s: %v", fid, err)
			continue
		}
		if err := s.storage.Delete(fid + replayPayloadSuffix); err != nil {
			log.Printf("replay history store delete payload %s: %v", fid, err)
		}
		s.count--
		deleted++
	}
	return deleted
}

func (s *ReplayHistoryStore) Close(_ context.Context) error {
	return s.storage.Close()
}

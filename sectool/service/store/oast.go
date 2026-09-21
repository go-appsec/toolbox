package store

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	oastSessionKeyPrefix = "sess:"
	oastEventKeyPrefix   = "evt:"
	oastDomainPrefix     = "_osd:"
	oastLabelPrefix      = "_osl:"
)

var (
	// ErrOastNotFound is returned when an OAST session record does not exist.
	ErrOastNotFound = errors.New("oast session not found")
	// ErrOastLabelExists is returned when creating a session with an in-use label.
	ErrOastLabelExists = errors.New("oast label already in use")
)

// OastSessionInfo holds OAST session metadata; the canonical identity shared by
// the backend and the persisted session record.
type OastSessionInfo struct {
	ID             string    `msgpack:"id"`  // short sectool ID
	Domain         string    `msgpack:"dom"` // full interactsh domain
	Label          string    `msgpack:"lbl,omitempty"`
	RedirectTarget string    `msgpack:"rt,omitempty"` // URL to 307 redirect to; empty = none
	CreatedAt      time.Time `msgpack:"ca"`
}

// OastEvent is a captured out-of-band interaction; the canonical event record
// shared by the backend and persisted per sequence key.
type OastEvent struct {
	ID        string                 `msgpack:"id"` // short sectool ID
	Time      time.Time              `msgpack:"t"`
	Type      string                 `msgpack:"ty"` // "dns", "http", "smtp", ...
	SourceIP  string                 `msgpack:"src,omitempty"`
	Subdomain string                 `msgpack:"sub,omitempty"` // full subdomain accessed
	Details   map[string]interface{} `msgpack:"det,omitempty"` // protocol-specific details
}

// OastSessionData is the persisted state for one OAST session. Events live
// under per-event keys; the record tracks the live range so appends never
// rewrite other events.
type OastSessionData struct {
	OastSessionInfo
	Events        []OastEvent `msgpack:"-"` // hydrated view, never serialized
	FirstEventSeq int         `msgpack:"fes"`
	EventCount    int         `msgpack:"ec"`
	DroppedCount  int         `msgpack:"dropped,omitempty"`
	LastPollIdx   int         `msgpack:"lpi,omitempty"` // "since last" poll cursor
}

// OastStore persists OAST sessions and their events through one Storage.
type OastStore struct {
	storage Storage
	mu      sync.RWMutex // serializes session record read-modify-write cycles
}

// NewOastStore creates an OastStore backed by the given storage.
func NewOastStore(storage Storage) *OastStore {
	return &OastStore{storage: storage}
}

// CreateSession persists a new empty session and its reverse indices. Fails if
// the label is already in use by another session.
func (s *OastStore) CreateSession(info OastSessionInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if info.Label != "" {
		if id, ok := s.indexID(oastLabelPrefix + info.Label); ok && id != info.ID {
			return fmt.Errorf("%w: %q already in use by session %s", ErrOastLabelExists, info.Label, id)
		}
	}
	if err := s.persistLocked(&OastSessionData{OastSessionInfo: info}); err != nil {
		return err
	}
	if err := s.storage.Set(oastDomainPrefix+info.Domain, []byte(info.ID)); err != nil {
		return err
	}
	if info.Label == "" {
		return nil
	}
	return s.storage.Set(oastLabelPrefix+info.Label, []byte(info.ID))
}

// Get returns a stored session with its live events by ID.
func (s *OastStore) Get(id string) (*OastSessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.getWithEventsLocked(id)
}

// Resolve finds a session by ID, label, or domain. Events are not hydrated.
func (s *OastStore) Resolve(identifier string) (*OastSessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if rec, ok := s.getLocked(identifier); ok {
		return rec, true
	}
	if id, ok := s.indexID(oastLabelPrefix + identifier); ok {
		if rec, found := s.getLocked(id); found {
			return rec, true
		}
	}
	if id, ok := s.indexID(oastDomainPrefix + identifier); ok {
		if rec, found := s.getLocked(id); found {
			return rec, true
		}
	}
	return nil, false
}

// SessionByLabel returns a stored session whose label matches exactly.
// Events are not hydrated.
func (s *OastStore) SessionByLabel(label string) (*OastSessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.indexID(oastLabelPrefix + label)
	if !ok {
		return nil, false
	}
	return s.getLocked(id)
}

// AppendEvent appends an event under its own key, trimming the oldest when the
// live count exceeds maxEvents. Returns true when a trim occurred so callers
// can shift an ephemeral cursor.
func (s *OastStore) AppendEvent(id string, ev OastEvent, maxEvents int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.getLocked(id)
	if !ok {
		return false, ErrOastNotFound
	}
	if err := s.setEventItem(id, rec.EventCount, ev); err != nil {
		return false, err
	}
	rec.EventCount++

	trimSeq := -1
	if maxEvents > 0 && rec.EventCount-rec.FirstEventSeq > maxEvents {
		trimSeq = rec.FirstEventSeq
		rec.FirstEventSeq++
		rec.DroppedCount++
	}
	// Persist the record before trimming so a persist failure never leaves a
	// hole inside the persisted live range.
	if err := s.persistLocked(rec); err != nil {
		_ = s.storage.Delete(s.eventKey(id, rec.EventCount-1)) // drop the orphaned event body
		return false, err
	}
	if trimSeq < 0 {
		return false, nil
	}
	if err := s.storage.Delete(s.eventKey(id, trimSeq)); err != nil {
		log.Printf("oast store trim event %s/%d: %v", id, trimSeq, err)
	}
	return true, nil
}

// UpdatePollCursor persists a session's "since last" poll cursor.
func (s *OastStore) UpdatePollCursor(id string, idx int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.getLocked(id)
	if !ok {
		return ErrOastNotFound
	}
	rec.LastPollIdx = idx
	return s.persistLocked(rec)
}

// FindEvent locates an event by ID across all sessions. Events are keyed by
// session and sequence, not ID, so this scans stored events; intended for rare
// single-event lookups.
func (s *OastStore) FindEvent(eventID string) (*OastEvent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, key := range s.storage.Keys(oastEventKeyPrefix) {
		data, found, err := s.storage.Get(key)
		if err != nil || !found {
			continue
		}
		var ev OastEvent
		if err := Deserialize(data, &ev); err != nil {
			log.Printf("oast store decode %s: %v", key, err)
			continue
		}
		if ev.ID == eventID {
			return &ev, true
		}
	}
	return nil, false
}

// Delete removes a session record, its live events, and its reverse indices.
func (s *OastStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.getLocked(id)
	if !ok {
		return nil
	}
	for seq := rec.FirstEventSeq; seq < rec.EventCount; seq++ {
		if err := s.storage.Delete(s.eventKey(id, seq)); err != nil {
			log.Printf("oast store delete event %s/%d: %v", id, seq, err)
		}
	}
	_ = s.storage.Delete(oastDomainPrefix + rec.Domain)
	if rec.Label != "" {
		_ = s.storage.Delete(oastLabelPrefix + rec.Label)
	}
	return s.storage.Delete(oastSessionKeyPrefix + id)
}

// List returns every stored session record with events hydrated, in
// unspecified order.
func (s *OastStore) List() []*OastSessionData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []*OastSessionData
	for _, key := range s.storage.Keys(oastSessionKeyPrefix) {
		if rec, ok := s.getWithEventsLocked(strings.TrimPrefix(key, oastSessionKeyPrefix)); ok {
			out = append(out, rec)
		}
	}
	return out
}

// Close closes the underlying storage.
func (s *OastStore) Close() error {
	return s.storage.Close()
}

// getWithEventsLocked loads a session record and hydrates its events.
// Caller must hold mu.
func (s *OastStore) getWithEventsLocked(id string) (*OastSessionData, bool) {
	rec, ok := s.getLocked(id)
	if !ok {
		return nil, false
	}
	rec.Events = s.loadEventsLocked(id, rec)
	return rec, true
}

// loadEventsLocked reads the live event range [FirstEventSeq, EventCount),
// skipping events missing or unreadable in storage. Caller must hold mu.
func (s *OastStore) loadEventsLocked(id string, rec *OastSessionData) []OastEvent {
	events := make([]OastEvent, 0, rec.EventCount-rec.FirstEventSeq)
	for seq := rec.FirstEventSeq; seq < rec.EventCount; seq++ {
		data, found, err := s.storage.Get(s.eventKey(id, seq))
		if err != nil {
			log.Printf("oast store load event %s/%d: %v", id, seq, err)
			continue
		}
		if !found {
			continue
		}
		var ev OastEvent
		if err := Deserialize(data, &ev); err != nil {
			log.Printf("oast store decode event %s/%d: %v", id, seq, err)
			continue
		}
		events = append(events, ev)
	}
	return events
}

// setEventItem persists a single event at the given sequence.
func (s *OastStore) setEventItem(id string, seq int, ev OastEvent) error {
	data, err := Serialize(ev)
	if err != nil {
		return err
	}
	return s.storage.Set(s.eventKey(id, seq), data)
}

func (s *OastStore) eventKey(id string, seq int) string {
	return oastEventKeyPrefix + id + ":" + strconv.Itoa(seq)
}

// persistLocked serializes and writes a session record. Events are excluded
// via msgpack:"-"; caller must hold mu.
func (s *OastStore) persistLocked(rec *OastSessionData) error {
	data, err := Serialize(rec)
	if err != nil {
		return err
	}
	return s.storage.Set(oastSessionKeyPrefix+rec.ID, data)
}

// getLocked loads a session record without hydrating events.
// Caller must hold mu.
func (s *OastStore) getLocked(id string) (*OastSessionData, bool) {
	data, found, err := s.storage.Get(oastSessionKeyPrefix + id)
	if err != nil || !found {
		return nil, false
	}
	var rec OastSessionData
	if err := Deserialize(data, &rec); err != nil {
		return nil, false
	}
	return &rec, true
}

// indexID reads a reverse-index value (a session ID). Caller must hold mu.
func (s *OastStore) indexID(key string) (string, bool) {
	data, found, err := s.storage.Get(key)
	if err != nil || !found {
		return "", false
	}
	return string(data), true
}

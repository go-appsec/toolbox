package store

import (
	"context"
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

const (
	crawlSessionKeyPrefix = "sess:"
	crawlLabelKeyPrefix   = "_cl:"
	crawlFlowKeyPrefix    = "flow:"
)

// CrawlSessionInfo is the identity and lifecycle metadata for a crawl session.
type CrawlSessionInfo struct {
	ID        string    `msgpack:"id"` // short sectool ID
	Label     string    `msgpack:"lb"`
	CreatedAt time.Time `msgpack:"ca"`
	State     string    `msgpack:"st"` // "running", "stopped", "completed", "error"
}

// CrawlSessionData is the persisted metadata and result index for one crawl
// session. Flow bodies live under per-flow keys; this record keeps discovery order.
type CrawlSessionData struct {
	CrawlSessionInfo
	StartedAt       time.Time             `msgpack:"sa"`
	LastActivity    time.Time             `msgpack:"la"`
	FlowIDs         []string              `msgpack:"fids"` // discovery order
	Forms           []protocol.CrawlForm  `msgpack:"fm"`
	Errors          []protocol.CrawlError `msgpack:"er"`
	LastReturnedIdx int                   `msgpack:"lri,omitempty"` // "since last" list cursor
}

// CrawlFlow is a single captured request/response from crawling; the canonical
// crawl flow record shared by the crawler backend and persisted per flow key.
type CrawlFlow struct {
	ID             string        `msgpack:"id"`   // short sectool ID
	SessionID      string        `msgpack:"sid"`  // parent session ID
	URL            string        `msgpack:"url"`  // full URL visited
	Host           string        `msgpack:"host"` // extracted from URL
	Path           string        `msgpack:"path"` // path with query string
	Method         string        `msgpack:"m"`
	FoundOn        string        `msgpack:"fo"` // parent URL where discovered
	Depth          int           `msgpack:"d"`  // crawl depth from seed
	StatusCode     int           `msgpack:"sc"` // HTTP response status
	ContentType    string        `msgpack:"ct"`
	ResponseLength int           `msgpack:"rl"`   // response body length in bytes
	Request        []byte        `msgpack:"req"`  // wire-format bytes
	Response       []byte        `msgpack:"resp"` // wire-format bytes
	Truncated      bool          `msgpack:"tr"`   // response exceeded max_body_bytes
	Duration       time.Duration `msgpack:"dur"`  // request/response round-trip
	DiscoveredAt   time.Time     `msgpack:"da"`
}

// crawlEntry is the hydrated mirror of one session record.
type crawlEntry struct {
	data  *CrawlSessionData
	flows map[string]*CrawlFlow // by flow ID; order follows data.FlowIDs
}

// CrawlStore manages crawl sessions and their discovered results with
// write-through access to a Storage. Reads come from an in-memory mirror that is
// kept authoritative on every mutation.
type CrawlStore struct {
	storage Storage
	mu      sync.RWMutex
	entries map[string]*crawlEntry // by session ID; hydrated lazily from storage
}

// NewCrawlStore creates a new CrawlStore backed by the given storage.
func NewCrawlStore(storage Storage) *CrawlStore {
	return &CrawlStore{storage: storage, entries: make(map[string]*crawlEntry)}
}

// Create persists a new session and its label reverse index. Fails if the ID or
// an equal label is already present. The mirror entry is rolled back if the
// write fails.
func (s *CrawlStore) Create(data *CrawlSessionData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.entries[data.ID]; ok {
		return fmt.Errorf("crawl session %q already exists", data.ID)
	}
	if existing, found := s.labelOwnerLocked(data.Label); found && existing != data.ID {
		return fmt.Errorf("label %q already in use by session %s", data.Label, existing)
	}

	s.entries[data.ID] = &crawlEntry{
		data:  cloneSessionData(data),
		flows: make(map[string]*CrawlFlow),
	}
	if err := s.persistLocked(s.entries[data.ID]); err != nil {
		delete(s.entries, data.ID)
		return err
	}
	return nil
}

// GetSession resolves a session by ID or label and returns its stored metadata.
func (s *CrawlStore) GetSession(identifier string) (*CrawlSessionData, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.lookupLocked(identifier)
	if entry == nil {
		return nil, false
	}
	return cloneSessionData(entry.data), true
}

// UpdateState persists a session's state, rolling back the mirror on failure.
func (s *CrawlStore) UpdateState(sessionID string, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.lookupLocked(sessionID)
	if entry == nil {
		return fmt.Errorf("crawl session %q not found", sessionID)
	}
	prevState, prevActivity := entry.data.State, entry.data.LastActivity
	entry.data.State = state
	entry.data.LastActivity = time.Now()
	if err := s.persistLocked(entry); err != nil {
		entry.data.State = prevState
		entry.data.LastActivity = prevActivity
		return err
	}
	return nil
}

// UpdateCursor persists a session's "since last" list cursor without touching
// LastActivity.
func (s *CrawlStore) UpdateCursor(sessionID string, idx int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.lookupLocked(sessionID)
	if entry == nil {
		return fmt.Errorf("crawl session %q not found", sessionID)
	}
	prevIdx := entry.data.LastReturnedIdx
	entry.data.LastReturnedIdx = idx
	if err := s.persistLocked(entry); err != nil {
		entry.data.LastReturnedIdx = prevIdx
		return err
	}
	return nil
}

// AppendFlow appends a discovered flow to the session in discovery order. The
// flow body is persisted under its own key before the session record updates.
func (s *CrawlStore) AppendFlow(sessionID string, flow *CrawlFlow) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.lookupLocked(sessionID)
	if entry == nil {
		return fmt.Errorf("crawl session %q not found", sessionID)
	}
	flow.SessionID = sessionID
	if err := s.setFlowItem(sessionID, flow); err != nil {
		return err
	}
	entry.data.FlowIDs = append(entry.data.FlowIDs, flow.ID)
	entry.flows[flow.ID] = cloneCrawlFlow(flow)
	s.touchLocked(entry)
	if err := s.persistLocked(entry); err != nil {
		// roll back the mirror; the flow body becomes an unreachable orphan
		entry.data.FlowIDs = entry.data.FlowIDs[:len(entry.data.FlowIDs)-1]
		delete(entry.flows, flow.ID)
		_ = s.storage.Delete(crawlFlowKey(sessionID, flow.ID))
		return err
	}
	return nil
}

// AppendForm appends a discovered form to the session, rolling back the mirror
// on failure.
func (s *CrawlStore) AppendForm(sessionID string, form protocol.CrawlForm) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.lookupLocked(sessionID)
	if entry == nil {
		return fmt.Errorf("crawl session %q not found", sessionID)
	}
	entry.data.Forms = append(entry.data.Forms, form)
	s.touchLocked(entry)
	if err := s.persistLocked(entry); err != nil {
		entry.data.Forms = entry.data.Forms[:len(entry.data.Forms)-1]
		return err
	}
	return nil
}

// AppendError appends a discovered error to the session, rolling back the
// mirror on failure.
func (s *CrawlStore) AppendError(sessionID string, crawlErr protocol.CrawlError) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.lookupLocked(sessionID)
	if entry == nil {
		return fmt.Errorf("crawl session %q not found", sessionID)
	}
	entry.data.Errors = append(entry.data.Errors, crawlErr)
	s.touchLocked(entry)
	if err := s.persistLocked(entry); err != nil {
		entry.data.Errors = entry.data.Errors[:len(entry.data.Errors)-1]
		return err
	}
	return nil
}

// Flows returns the discovered flows for a session in discovery order. The
// returned flows are clones; Request and Response bytes are shared with the
// store and must not be mutated.
func (s *CrawlStore) Flows(sessionID string) ([]*CrawlFlow, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.lookupLocked(sessionID)
	if entry == nil {
		return nil, false
	}
	out := make([]*CrawlFlow, 0, len(entry.data.FlowIDs))
	for _, id := range entry.data.FlowIDs {
		if f, ok := entry.flows[id]; ok {
			out = append(out, cloneCrawlFlow(f))
		}
	}
	return out, true
}

// Forms returns the discovered forms for a session.
func (s *CrawlStore) Forms(sessionID string) ([]protocol.CrawlForm, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.lookupLocked(sessionID)
	if entry == nil {
		return nil, false
	}
	return slices.Clone(entry.data.Forms), true
}

// Errors returns the discovered errors for a session.
func (s *CrawlStore) Errors(sessionID string) ([]protocol.CrawlError, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.lookupLocked(sessionID)
	if entry == nil {
		return nil, false
	}
	return slices.Clone(entry.data.Errors), true
}

// GetFlow returns a flow by its ID across all sessions. Hydrated sessions are
// answered from the mirror; storage is scanned for the rest.
func (s *CrawlStore) GetFlow(flowID string) (*CrawlFlow, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, entry := range s.entries {
		if f, ok := entry.flows[flowID]; ok {
			return cloneCrawlFlow(f), true
		}
	}
	// flow:<sessionID>:<flowID>; IDs contain no colons
	for _, key := range s.storage.Keys(crawlFlowKeyPrefix) {
		if !strings.HasSuffix(key, ":"+flowID) {
			continue
		}
		sessionID := strings.TrimSuffix(strings.TrimPrefix(key, crawlFlowKeyPrefix), ":"+flowID)
		if f, ok := s.getFlowItem(sessionID, flowID); ok {
			return f, true
		}
	}
	return nil, false
}

// Sessions returns all stored sessions in unspecified order.
func (s *CrawlStore) Sessions() []*CrawlSessionData {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []*CrawlSessionData
	for _, key := range s.storage.Keys(crawlSessionKeyPrefix) {
		entry := s.hydrateLocked(strings.TrimPrefix(key, crawlSessionKeyPrefix))
		if entry != nil {
			out = append(out, cloneSessionData(entry.data))
		}
	}
	return out
}

// Delete removes a session and all of its stored results.
func (s *CrawlStore) Delete(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.lookupLocked(sessionID)
	if entry == nil {
		return nil
	}
	for _, key := range s.storage.Keys(crawlFlowKeyPrefix + sessionID + ":") {
		if err := s.storage.Delete(key); err != nil {
			log.Printf("crawl store flow delete %s: %v", key, err)
		}
	}
	s.deleteLabelLocked(entry.data.Label, sessionID)
	delete(s.entries, sessionID)
	return s.storage.Delete(crawlSessionKeyPrefix + sessionID)
}

// Count returns the number of stored sessions.
func (s *CrawlStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.storage.Keys(crawlSessionKeyPrefix))
}

// Close closes the underlying storage.
func (s *CrawlStore) Close(_ context.Context) error {
	return s.storage.Close()
}

// lookupLocked resolves a session entry by ID or label, hydrating from storage on
// first access so reads never assume volatility. Caller must hold mu.
func (s *CrawlStore) lookupLocked(identifier string) *crawlEntry {
	if identifier == "" {
		return nil
	}
	if entry, ok := s.entries[identifier]; ok {
		return entry
	}

	sessionID := s.resolveLabelLocked(identifier)
	if sessionID != "" {
		if entry, ok := s.entries[sessionID]; ok {
			return entry
		}
		return s.hydrateLocked(sessionID)
	}
	return s.hydrateLocked(identifier) // fall back to treating it as a stored ID
}

// hydrateLocked loads a stored session and its flows into the mirror.
func (s *CrawlStore) hydrateLocked(sessionID string) *crawlEntry {
	if _, ok := s.entries[sessionID]; ok {
		return s.entries[sessionID]
	}
	data, found, err := s.storage.Get(crawlSessionKeyPrefix + sessionID)
	if err != nil || !found {
		return nil
	}
	var stored CrawlSessionData
	if err := Deserialize(data, &stored); err != nil {
		log.Printf("crawl store hydrate %s: %v", sessionID, err)
		return nil
	}

	entry := &crawlEntry{data: cloneSessionData(&stored), flows: make(map[string]*CrawlFlow)}
	for _, id := range stored.FlowIDs {
		if f, ok := s.getFlowItem(sessionID, id); ok {
			entry.flows[id] = f
		}
	}
	s.entries[sessionID] = entry
	return entry
}

// resolveLabelLocked returns the session ID owned by a label, or "".
func (s *CrawlStore) resolveLabelLocked(label string) string {
	data, found, err := s.storage.Get(crawlLabelKeyPrefix + label)
	if err != nil || !found {
		return ""
	}
	return string(data)
}

// labelOwnerLocked returns the existing owner of a label, if any.
func (s *CrawlStore) labelOwnerLocked(label string) (string, bool) {
	if label == "" {
		return "", false
	}
	sessionID := s.resolveLabelLocked(label)
	return sessionID, sessionID != ""
}

// touchLocked refreshes LastActivity on a mutation. Caller must hold mu.
func (s *CrawlStore) touchLocked(entry *crawlEntry) {
	entry.data.LastActivity = time.Now()
}

// persistLocked serializes a session record and its label index to storage.
func (s *CrawlStore) persistLocked(entry *crawlEntry) error {
	data, err := Serialize(entry.data)
	if err != nil {
		return fmt.Errorf("crawl store serialize %s: %w", entry.data.ID, err)
	}
	if err := s.storage.Set(crawlSessionKeyPrefix+entry.data.ID, data); err != nil {
		return err
	}

	if entry.data.Label == "" {
		return nil
	}
	return s.storage.Set(crawlLabelKeyPrefix+entry.data.Label, []byte(entry.data.ID))
}

// deleteLabelLocked removes a label reverse index entry for an owner.
func (s *CrawlStore) deleteLabelLocked(label, sessionID string) {
	if label == "" {
		return
	}
	if s.resolveLabelLocked(label) == sessionID {
		_ = s.storage.Delete(crawlLabelKeyPrefix + label)
	}
}

// setFlowItem persists a single flow record.
func (s *CrawlStore) setFlowItem(sessionID string, flow *CrawlFlow) error {
	data, err := Serialize(flow)
	if err != nil {
		return fmt.Errorf("crawl store serialize flow %s: %w", flow.ID, err)
	}
	return s.storage.Set(crawlFlowKey(sessionID, flow.ID), data)
}

// getFlowItem loads a single flow record.
func (s *CrawlStore) getFlowItem(sessionID string, flowID string) (*CrawlFlow, bool) {
	data, found, err := s.storage.Get(crawlFlowKey(sessionID, flowID))
	if err != nil || !found {
		return nil, false
	}
	var f CrawlFlow
	if err := Deserialize(data, &f); err != nil {
		log.Printf("crawl store get flow %s/%s: %v", sessionID, flowID, err)
		return nil, false
	}
	f.SessionID = sessionID
	return cloneCrawlFlow(&f), true
}

func crawlFlowKey(sessionID, flowID string) string {
	return crawlFlowKeyPrefix + sessionID + ":" + flowID
}

func cloneSessionData(d *CrawlSessionData) *CrawlSessionData {
	if d == nil {
		return nil
	}
	cp := *d
	cp.FlowIDs = slices.Clone(d.FlowIDs)
	cp.Forms = slices.Clone(d.Forms)
	cp.Errors = slices.Clone(d.Errors)
	return &cp
}

// cloneCrawlFlow returns a shallow copy of a flow; Request and Response bytes are
// shared with the store and must not be mutated by callers.
func cloneCrawlFlow(f *CrawlFlow) *CrawlFlow {
	if f == nil {
		return nil
	}
	cp := *f
	return &cp
}

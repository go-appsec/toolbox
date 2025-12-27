package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/go-analyze/bulk"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"

	"github.com/jentfoo/llm-security-toolbox/sectool/service/ids"
)

const (
	// pollCheckInterval is how often PollSession checks for new events in the local buffer
	pollCheckInterval = 100 * time.Millisecond
	// interactshPollInterval is how often the interactsh client polls the server
	interactshPollInterval = 2 * time.Second
	// sessionCloseTimeout is how long to wait when closing a session
	sessionCloseTimeout = 2 * time.Second
)

// InteractshBackend implements OastBackend using Interactsh.
type InteractshBackend struct {
	mu       sync.RWMutex
	sessions map[string]*oastSession // by domain (canonical key)
	byID     map[string]string       // short ID -> domain
	byLabel  map[string]string       // label -> domain (only non-empty labels)
	closed   bool
}

// Compile-time check that InteractshBackend implements OastBackend
var _ OastBackend = (*InteractshBackend)(nil)

// oastSession holds the state for a single OAST session.
type oastSession struct {
	info   OastSessionInfo
	client *client.Client

	mu           sync.Mutex
	events       []OastEventInfo
	droppedCount int
	lastPollIdx  int // Index after last poll (for "last" filter)

	stopPolling chan struct{}
	stopped     bool
}

// NewInteractshBackend creates a new Interactsh-backed OastBackend.
func NewInteractshBackend() *InteractshBackend {
	return &InteractshBackend{
		sessions: make(map[string]*oastSession),
		byID:     make(map[string]string),
		byLabel:  make(map[string]string),
	}
}

func (b *InteractshBackend) CreateSession(ctx context.Context, label string) (*OastSessionInfo, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, errors.New("backend is closed")
	}
	// Check label uniqueness before creating interactsh client
	if label != "" {
		if existingDomain, exists := b.byLabel[label]; exists {
			existingSess := b.sessions[existingDomain]
			b.mu.Unlock()
			return nil, fmt.Errorf("label %q already in use by session %s; delete it first with: sectool oast delete %s",
				label, existingSess.info.ID, existingSess.info.ID)
		}
	}
	b.mu.Unlock()

	opts := client.DefaultOptions
	c, err := client.New(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create interactsh client: %w", err)
	}

	sessionID := ids.Generate(ids.DefaultLength)
	domain := c.URL()

	sess := &oastSession{
		info: OastSessionInfo{
			ID:        sessionID,
			Domain:    domain,
			Label:     label,
			CreatedAt: time.Now(),
		},
		client:      c,
		stopPolling: make(chan struct{}),
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		_ = c.Close()
		return nil, errors.New("backend is closed")
	}

	// Re-check label uniqueness in case of race
	if label != "" {
		if existingDomain, exists := b.byLabel[label]; exists {
			existingSess := b.sessions[existingDomain]
			b.mu.Unlock()
			_ = c.Close()
			return nil, fmt.Errorf("label %q already in use by session %s; delete it first with: sectool oast delete %s",
				label, existingSess.info.ID, existingSess.info.ID)
		}
	}

	// Ensure ID uniqueness
	for b.byID[sessionID] != "" {
		sessionID = ids.Generate(ids.DefaultLength)
		sess.info.ID = sessionID
	}

	b.sessions[domain] = sess
	b.byID[sessionID] = domain
	if label != "" {
		b.byLabel[label] = domain
	}
	b.mu.Unlock()

	log.Printf("oast: created session %s with domain %s (label=%q)", sessionID, domain, label)

	// Start background polling
	go b.pollLoop(sess)

	return &sess.info, nil
}

// pollLoop runs background polling for a session.
func (b *InteractshBackend) pollLoop(sess *oastSession) {
	callback := func(interaction *server.Interaction) {
		sess.mu.Lock()
		defer sess.mu.Unlock()

		if sess.stopped {
			return
		}

		eventTime := time.Now()
		if interaction.Timestamp.After(time.Time{}) {
			eventTime = interaction.Timestamp
		}

		details := make(map[string]interface{}, 4)
		if interaction.RawRequest != "" {
			details["raw_request"] = interaction.RawRequest
		}
		if interaction.RawResponse != "" {
			details["raw_response"] = interaction.RawResponse
		}
		if interaction.QType != "" {
			details["query_type"] = interaction.QType
		}
		if interaction.SMTPFrom != "" {
			details["smtp_from"] = interaction.SMTPFrom
		}

		if len(sess.events) >= MaxOastEventsPerSession {
			sess.events = sess.events[1:]
			sess.droppedCount++
			if sess.lastPollIdx > 0 {
				sess.lastPollIdx--
			}
		}
		event := OastEventInfo{
			ID:        ids.Generate(ids.DefaultLength),
			Time:      eventTime,
			Type:      strings.ToLower(interaction.Protocol),
			SourceIP:  interaction.RemoteAddress,
			Subdomain: interaction.FullId,
			Details:   details,
		}
		sess.events = append(sess.events, event)
		log.Printf("oast: session %s received %s event from %s", sess.info.ID, event.Type, event.SourceIP)
	}

	sess.mu.Lock()
	if !sess.stopped {
		if err := sess.client.StartPolling(interactshPollInterval, callback); err != nil {
			log.Printf("oast: polling error for session %s: %v", sess.info.ID, err)
		}
	}
	sess.mu.Unlock()

	<-sess.stopPolling
}

func (b *InteractshBackend) PollSession(ctx context.Context, idOrDomain string, since string, wait time.Duration, limit int) (*OastPollResultInfo, error) {
	sess, err := b.resolveSession(idOrDomain)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(wait)

	for {
		sess.mu.Lock()
		if sess.stopped {
			sess.mu.Unlock()
			return nil, errors.New("session has been deleted")
		}

		events := sess.filterEvents(since)
		if len(events) > 0 || wait == 0 || time.Now().After(deadline) {
			// Apply limit if set
			if limit > 0 && len(events) > limit {
				events = events[:limit]
			}
			// Update lastPollIdx based on the last returned event (for pagination with limit)
			sess.updateLastPollIdx(events)
			result := &OastPollResultInfo{
				Events:       events,
				DroppedCount: sess.droppedCount,
			}
			sess.mu.Unlock()
			return result, nil
		}
		sess.mu.Unlock()

		select {
		case <-ctx.Done():
			sess.mu.Lock()
			events := sess.filterEvents(since)
			// Apply limit if set
			if limit > 0 && len(events) > limit {
				events = events[:limit]
			}
			sess.updateLastPollIdx(events)
			result := &OastPollResultInfo{
				Events:       events,
				DroppedCount: sess.droppedCount,
			}
			sess.mu.Unlock()
			return result, nil
		case <-time.After(pollCheckInterval):
			// Check for new events
		}
	}
}

// filterEvents returns events based on the since filter. Caller must hold s.mu until result slice is discarded.
func (s *oastSession) filterEvents(since string) []OastEventInfo {
	switch since {
	case "":
		return s.events
	case "last":
		if s.lastPollIdx >= len(s.events) {
			return nil
		}
		return s.events[s.lastPollIdx:]
	}

	// Find event by ID and return everything after it
	for i, e := range s.events {
		if e.ID == since {
			if i+1 >= len(s.events) {
				return nil
			}
			return s.events[i+1:]
		}
	}

	// Event ID not found - return all events
	return s.events
}

// updateLastPollIdx updates lastPollIdx based on returned events (for --since last tracking).
// Caller must hold s.mu.
func (s *oastSession) updateLastPollIdx(returnedEvents []OastEventInfo) {
	if len(returnedEvents) == 0 {
		return
	}
	// Find the index of the last returned event in s.events
	lastEventID := returnedEvents[len(returnedEvents)-1].ID
	for i, e := range s.events {
		if e.ID == lastEventID {
			s.lastPollIdx = i + 1
			return
		}
	}
	// Fallback: if not found, use len(events)
	s.lastPollIdx = len(s.events)
}

func (b *InteractshBackend) GetEvent(ctx context.Context, idOrDomain string, eventID string) (*OastEventInfo, error) {
	sess, err := b.resolveSession(idOrDomain)
	if err != nil {
		return nil, err
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.stopped {
		return nil, errors.New("session has been deleted")
	}

	for _, e := range sess.events {
		if e.ID == eventID {
			// Return a copy to avoid holding the lock
			eventCopy := e
			return &eventCopy, nil
		}
	}

	return nil, fmt.Errorf("event not found: %s", eventID)
}

func (b *InteractshBackend) ListSessions(ctx context.Context) ([]OastSessionInfo, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	sessions := make([]OastSessionInfo, 0, len(b.sessions))
	for _, sess := range b.sessions {
		sessions = append(sessions, sess.info)
	}
	return sessions, nil
}

func (b *InteractshBackend) DeleteSession(ctx context.Context, idOrDomain string) error {
	sess, err := b.resolveSession(idOrDomain)
	if err != nil {
		return err
	}

	return b.deleteSession(sess)
}

func (b *InteractshBackend) deleteSession(sess *oastSession) error {
	sess.mu.Lock()
	if sess.stopped {
		sess.mu.Unlock()
		return nil
	}
	sess.stopped = true
	sess.mu.Unlock()

	close(sess.stopPolling)

	if sess.client != nil {
		done := make(chan error, 1)
		go func() {
			done <- sess.client.Close()
		}()

		select {
		case err := <-done:
			if err != nil {
				log.Printf("oast: error closing session %s: %v", sess.info.ID, err)
			}
		case <-time.After(sessionCloseTimeout):
			log.Printf("oast: timeout closing session %s", sess.info.ID)
		}
	}

	b.mu.Lock()
	delete(b.sessions, sess.info.Domain)
	delete(b.byID, sess.info.ID)
	if sess.info.Label != "" {
		delete(b.byLabel, sess.info.Label)
	}
	b.mu.Unlock()

	log.Printf("oast: session %s deleted", sess.info.ID)
	return nil
}

func (b *InteractshBackend) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	sessions := bulk.MapValuesSlice(b.sessions)
	b.mu.Unlock()

	var wg sync.WaitGroup
	for _, sess := range sessions {
		wg.Add(1)
		go func(s *oastSession) {
			defer wg.Done()
			_ = b.deleteSession(s)
		}(sess)
	}
	wg.Wait()

	return nil
}

// resolveSession finds a session by ID, label, or domain.
func (b *InteractshBackend) resolveSession(identifier string) (*oastSession, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Try as ID first
	if domain, ok := b.byID[identifier]; ok {
		if sess, ok := b.sessions[domain]; ok {
			return sess, nil
		}
	}

	// Try as label
	if domain, ok := b.byLabel[identifier]; ok {
		if sess, ok := b.sessions[domain]; ok {
			return sess, nil
		}
	}

	// Try as domain directly
	if sess, ok := b.sessions[identifier]; ok {
		return sess, nil
	}

	return nil, fmt.Errorf("session not found: %s", identifier)
}

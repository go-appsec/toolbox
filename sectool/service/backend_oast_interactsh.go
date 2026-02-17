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
	"github.com/go-appsec/interactsh-lite/oobclient"

	"github.com/go-appsec/toolbox/sectool/service/ids"
)

const (
	// interactshPollInterval is how often the interactsh client polls the server.
	interactshPollInterval = 10 * time.Second
	// sessionCloseTimeout is how long to wait when closing a session.
	sessionCloseTimeout = 10 * time.Second
)

// InteractshBackend implements OastBackend using Interactsh.
type InteractshBackend struct {
	serverURL string // custom server URL, empty = use defaults
	mu        sync.RWMutex
	sessions  map[string]*oastSession // by domain (canonical key)
	byID      map[string]string       // short ID -> domain
	byLabel   map[string]string       // label -> domain (only non-empty labels)
	closed    bool
}

// Compile-time check that InteractshBackend implements OastBackend
var _ OastBackend = (*InteractshBackend)(nil)

// oastSession holds the state for a single OAST session.
type oastSession struct {
	info   OastSessionInfo
	client *oobclient.Client

	mu           sync.Mutex
	notify       chan struct{} // closed when new events arrive, then replaced
	events       []OastEventInfo
	droppedCount int
	lastPollIdx  int // Index after last poll (for "last" filter)

	stopPolling chan struct{}
	stopped     bool
}

// NewInteractshBackend creates a new Interactsh-backed OastBackend.
func NewInteractshBackend(serverURL string) *InteractshBackend {
	return &InteractshBackend{
		serverURL: serverURL,
		sessions:  make(map[string]*oastSession),
		byID:      make(map[string]string),
		byLabel:   make(map[string]string),
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
			return nil, fmt.Errorf("%w: %q already in use by session %s; delete it first with: sectool oast delete %s",
				ErrLabelExists, label, existingSess.info.ID, existingSess.info.ID)
		}
	}
	b.mu.Unlock()

	var opts oobclient.Options
	if b.serverURL != "" {
		opts.ServerURLs = []string{b.serverURL}
	}
	c, err := oobclient.New(ctx, opts)
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
		notify:      make(chan struct{}),
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
			return nil, fmt.Errorf("%w: %q already in use by session %s; delete it first with: sectool oast delete %s",
				ErrLabelExists, label, existingSess.info.ID, existingSess.info.ID)
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

	go b.pollLoop(sess) // Start background polling

	return &sess.info, nil
}

// pollLoop runs background polling for a session.
func (b *InteractshBackend) pollLoop(sess *oastSession) {
	callback := func(interaction *oobclient.Interaction) {
		sess.mu.Lock()
		defer sess.mu.Unlock()

		if sess.stopped {
			return
		}

		var eventTime time.Time
		if !interaction.Timestamp.IsZero() {
			eventTime = interaction.Timestamp
		} else {
			eventTime = time.Now()
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

		// Notify waiters by closing channel, then replace for next notification
		close(sess.notify)
		sess.notify = make(chan struct{})

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

func (b *InteractshBackend) PollSession(ctx context.Context, idOrDomain string, since string, eventType string, wait time.Duration, limit int) (*OastPollResultInfo, error) {
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

		events := sess.filterEvents(since, eventType)
		if len(events) > 0 || wait == 0 || time.Now().After(deadline) || ctx.Err() != nil {
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
		}

		notify := sess.notify // capture before unlocking
		sess.mu.Unlock()

		select {
		case <-notify: // channel closed = new events or session stopped
		case <-ctx.Done():
		case <-time.After(time.Until(deadline)):
		}
	}
}

// filterEvents returns events based on the since and eventType filters.
// Caller must hold s.mu until result slice is discarded.
func (s *oastSession) filterEvents(since, eventType string) []OastEventInfo {
	var events []OastEventInfo
	switch since {
	case "":
		events = s.events
	case sinceLast:
		if s.lastPollIdx >= len(s.events) {
			events = nil
		} else {
			events = s.events[s.lastPollIdx:]
		}
	default:
		// Try parsing as timestamp first
		if sinceTime, ok := parseSinceTimestamp(since); ok {
			events = bulk.SliceFilter(func(e OastEventInfo) bool {
				return e.Time.After(sinceTime)
			}, s.events)
		} else {
			// Find event by ID and return everything after it
			var found bool
			for i, e := range s.events {
				if e.ID == since {
					if i+1 >= len(s.events) {
						events = nil
					} else {
						events = s.events[i+1:]
					}
					found = true
					break
				}
			}
			if !found {
				events = s.events
			}
		}
	}

	if eventType == "" || len(events) == 0 {
		return events
	}

	return bulk.SliceFilter(func(e OastEventInfo) bool {
		return e.Type == eventType
	}, events)
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

	return nil, fmt.Errorf("%w: event %s", ErrNotFound, eventID)
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
	close(sess.notify) // wake any waiters
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

	return nil, fmt.Errorf("%w: %s", ErrNotFound, identifier)
}

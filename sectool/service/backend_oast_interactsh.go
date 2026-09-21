package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-analyze/bulk"
	"github.com/go-appsec/interactsh-lite/oobclient"

	"github.com/go-appsec/toolbox/sectool/service/ids"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

const (
	// interactshPollInterval is how often the interactsh client polls the server.
	interactshPollInterval = 4 * time.Second
	// clientCleanupInterval is how often to check for idle clients with no active sessions.
	clientCleanupInterval = 120 * time.Second
)

// interactLiteHostSuffixes are known interactsh-lite server hosts.
var interactLiteHostSuffixes = [...]string{"oastsrv.net", "oastlab.net"}

// isInteractLiteHost reports whether the server host is a known interactsh-lite host.
func isInteractLiteHost(serverHost string) bool {
	return slices.ContainsFunc(interactLiteHostSuffixes[:], func(suffix string) bool {
		return serverHost == suffix || strings.HasSuffix(serverHost, "."+suffix)
	})
}

// InteractshBackend implements OastBackend using Interactsh.
type InteractshBackend struct {
	serverURL         string       // custom server URL, empty = use defaults
	authToken         string       // optional auth token for protected servers
	redirectSupported bool         // whether the server supports redirect responses
	httpClient        *http.Client // shared HTTP client for all oobclient instances and probes

	// oastStore persists session metadata and events.
	oastStore *store.OastStore

	mu       sync.RWMutex
	sessions map[string]*oastSession // by domain (canonical key)
	closed   bool

	// Clients keyed by redirect target ("" = default/no-redirect), lazily created.
	clients map[string]*oobclient.Client
	initMu  sync.Mutex // guards lazy client creation
}

// Compile-time check that InteractshBackend implements OastBackend
var _ OastBackend = (*InteractshBackend)(nil)

// oastSession holds the state for a single OAST session.
type oastSession struct {
	info store.OastSessionInfo

	mu          sync.Mutex
	notify      chan struct{} // closed when new events arrive, then replaced
	lastPollIdx int           // index after last poll; persisted via OastStore for restart resume
	stopped     bool
}

// NewInteractshBackend creates a new Interactsh-backed OastBackend over the given storage provider.
func NewInteractshBackend(serverURL, authToken string, provider store.Provider) (*InteractshBackend, error) {
	oastStorage, err := provider("oast")
	if err != nil {
		return nil, fmt.Errorf("oast storage: %w", err)
	}
	return &InteractshBackend{
		serverURL: serverURL,
		authToken: authToken,
		httpClient: &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 10 * time.Second,
		},
		oastStore: store.NewOastStore(oastStorage),
		sessions:  make(map[string]*oastSession),
		clients:   make(map[string]*oobclient.Client),
	}, nil
}

// Start probes the server for capabilities and starts background maintenance.
// Must be called before creating sessions. Pair with Close() for cleanup.
func (b *InteractshBackend) Start(ctx context.Context) {
	b.ProbeRedirectSupport(ctx)
	go func() {
		ticker := time.NewTicker(clientCleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			b.mu.Lock()
			if b.closed {
				b.mu.Unlock()
				return
			}
			stale := b.cleanupIdleClients()
			b.mu.Unlock()
			for _, c := range stale {
				if err := c.Close(); err != nil {
					log.Printf("oast: error closing idle client: %v", err)
				}
			}
			if len(stale) > 0 {
				log.Printf("oast: cleaned up %d idle client(s)", len(stale))
			}
		}
	}()
}

// SupportsRedirect reports whether the OAST server supports redirect responses.
func (b *InteractshBackend) SupportsRedirect() bool {
	return b.redirectSupported
}

// ProbeRedirectSupport determines whether the OAST server supports redirect responses.
// Default and known interactsh-lite servers are assumed compatible.
// Custom servers are probed by registering with a 307 ResponseConfig and verifying the response.
func (b *InteractshBackend) ProbeRedirectSupport(ctx context.Context) {
	if b.serverURL == "" || isInteractLiteHost(b.serverURL) {
		b.redirectSupported = true
		return
	}

	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	c, err := oobclient.New(probeCtx, oobclient.Options{
		ServerURLs: []string{b.serverURL},
		Token:      b.authToken,
		HTTPClient: b.httpClient,
		Response: &oobclient.ResponseConfig{
			StatusCode: 307,
			Headers:    []string{"Location: " + b.serverURL},
		},
	})
	if err != nil {
		log.Printf("oast: redirect probe failed (registration): %v", err)
		return
	}
	defer func() { _ = c.Close() }()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "http://"+c.Domain(), nil)
	if err != nil {
		log.Printf("oast: redirect probe failed (build request): %v", err)
		return
	}
	resp, err := b.httpClient.Do(req)
	if err != nil {
		log.Printf("oast: redirect probe failed (request): %v", err)
		return
	}
	_ = resp.Body.Close()

	b.redirectSupported = resp.StatusCode == http.StatusTemporaryRedirect
	log.Printf("oast: redirect probe for %s: supported=%v", b.serverURL, b.redirectSupported)
}

// ensureClientForRedirectTarget lazily creates an oobclient.Client for the given redirect target.
// An empty redirectTarget returns the default (no-redirect) client.
func (b *InteractshBackend) ensureClientForRedirectTarget(ctx context.Context, redirectTarget string) (*oobclient.Client, error) {
	b.mu.RLock()
	if c, ok := b.clients[redirectTarget]; ok {
		b.mu.RUnlock()
		return c, nil
	}
	b.mu.RUnlock()

	b.initMu.Lock()
	defer b.initMu.Unlock()

	b.mu.RLock()
	if c, ok := b.clients[redirectTarget]; ok {
		b.mu.RUnlock()
		return c, nil
	}
	closed := b.closed
	b.mu.RUnlock()
	if closed {
		return nil, errors.New("backend is closed")
	}

	opts := oobclient.Options{HTTPClient: b.httpClient, Token: b.authToken}
	if b.serverURL != "" {
		opts.ServerURLs = []string{b.serverURL}
	}
	if redirectTarget != "" {
		opts.Response = &oobclient.ResponseConfig{
			StatusCode: 307,
			Headers:    []string{"Location: " + redirectTarget},
		}
	}

	c, err := oobclient.New(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create interactsh client: %w", err)
	}

	if err := c.StartPolling(interactshPollInterval, b.makeInteractionHandler(c.CorrelationID())); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("oast failed to start polling: %w", err)
	}

	b.mu.Lock()
	b.clients[redirectTarget] = c
	b.mu.Unlock()

	log.Printf("oast: client created and polling (redirect=%q)", redirectTarget)
	return c, nil
}

// makeInteractionHandler returns a polling callback bound to a specific client's correlationID.
// FullId leaf label is correlationID+sessionID (optionally prefixed with a subdomain).
func (b *InteractshBackend) makeInteractionHandler(correlationID string) func(*oobclient.Interaction) {
	return func(interaction *oobclient.Interaction) {
		leaf := interaction.FullId
		if dotIdx := strings.LastIndexByte(leaf, '.'); dotIdx >= 0 {
			leaf = leaf[dotIdx+1:]
		}
		if !strings.HasPrefix(leaf, correlationID) || len(leaf) <= len(correlationID) {
			return
		}
		sessionID := leaf[len(correlationID):]

		rec, found := b.oastStore.Resolve(sessionID)
		if !found {
			return
		}
		b.mu.RLock()
		sess := b.sessions[rec.Domain]
		b.mu.RUnlock()
		if sess == nil {
			return
		}

		sess.mu.Lock()
		defer sess.mu.Unlock()

		if sess.stopped {
			return
		}

		details := make(map[string]interface{}, 4)
		eventType := strings.ToLower(interaction.Protocol)
		switch eventType {
		case "dns":
			if interaction.QType != "" {
				details["query_type"] = interaction.QType
			}
		case schemeHTTP, schemeHTTPS, "smtp":
			if interaction.SMTPFrom != "" {
				details["smtp_from"] = interaction.SMTPFrom
			}
			if interaction.SMTPTo != "" {
				details["smtp_to"] = interaction.SMTPTo
			}
			if interaction.RawRequest != "" {
				h, b := splitHeadersBody([]byte(interaction.RawRequest))
				details["headers"] = string(bytes.TrimRight(h, "\r\n"))
				if len(b) > 0 {
					details["body"] = string(b)
				}
			}
		default:
			// Uncommon protocols (ftp, ldap, smb, responder): keep raw
			if interaction.RawRequest != "" {
				details["raw_request"] = interaction.RawRequest
			}
		}

		b.persistEventLocked(sess, store.OastEvent{
			ID:        ids.Generate(ids.DefaultLength),
			Time:      interaction.Timestamp,
			Type:      eventType,
			SourceIP:  interaction.RemoteAddress,
			Subdomain: interaction.FullId,
			Details:   details,
		})

		log.Printf("oast: session %s received %s event from %s", sess.info.ID, eventType, interaction.RemoteAddress)
	}
}

// persistEventLocked appends an event to a stored session record, trims beyond
// the cap, adjusts the ephemeral poll cursor, and wakes any waiters.
// Caller must hold sess.mu.
func (b *InteractshBackend) persistEventLocked(sess *oastSession, ev store.OastEvent) {
	if sess.stopped {
		return
	}
	dropped, err := b.oastStore.AppendEvent(sess.info.ID, ev, MaxOastEventsPerSession)
	if errors.Is(err, store.ErrOastNotFound) {
		sess.stopped = true // session deleted concurrently; stop accepting events
		return
	}
	if err != nil {
		log.Printf("oast: session %s append event failed: %v", sess.info.ID, err)
		return
	}
	if dropped && sess.lastPollIdx > 0 {
		sess.lastPollIdx--
		if err := b.oastStore.UpdatePollCursor(sess.info.ID, sess.lastPollIdx); err != nil {
			log.Printf("oast: session %s persist poll cursor: %v", sess.info.ID, err)
		}
	}
	close(sess.notify)
	sess.notify = make(chan struct{})
}

func (b *InteractshBackend) CreateSession(ctx context.Context, label, redirectTarget string) (*store.OastSessionInfo, error) {
	if redirectTarget != "" && !b.redirectSupported {
		return nil, errors.New("OAST server does not support redirect responses")
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, errors.New("backend is closed")
	}
	var existingID string
	if label != "" {
		if rec, ok := b.oastStore.SessionByLabel(label); ok {
			existingID = rec.ID
		}
	}
	b.mu.Unlock()

	if existingID != "" {
		return nil, fmt.Errorf("%w: %q already in use by session %s; delete it first",
			ErrLabelExists, label, existingID)
	}

	c, err := b.ensureClientForRedirectTarget(ctx, redirectTarget)
	if err != nil {
		return nil, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, errors.New("backend is closed")
	}
	// Re-check label uniqueness in case of race
	if label != "" {
		if rec, ok := b.oastStore.SessionByLabel(label); ok {
			return nil, fmt.Errorf("%w: %q already in use by session %s; delete it first",
				ErrLabelExists, label, rec.ID)
		}
	}

	sessionID := strings.ToLower(ids.Generate(ids.EntityLength))
	for {
		if _, found := b.oastStore.Get(sessionID); !found {
			break
		}
		sessionID = strings.ToLower(ids.Generate(ids.EntityLength))
	}
	domain := c.CorrelationID() + sessionID + "." + c.ServerHost()

	info := store.OastSessionInfo{
		ID:             sessionID,
		Domain:         domain,
		Label:          label,
		RedirectTarget: redirectTarget,
		CreatedAt:      time.Now(),
	}
	sess := &oastSession{info: info, notify: make(chan struct{})}

	if err := b.oastStore.CreateSession(info); err != nil {
		if errors.Is(err, store.ErrOastLabelExists) {
			return nil, fmt.Errorf("%w: %q already in use; delete it first", ErrLabelExists, label)
		}
		return nil, fmt.Errorf("persist oast session: %w", err)
	}
	b.sessions[domain] = sess

	return &info, nil
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

		rec, ok := b.oastStore.Get(sess.info.ID)
		if !ok {
			sess.mu.Unlock()
			return nil, fmt.Errorf("%w: %s", ErrNotFound, sess.info.ID)
		}

		events := filterEvents(rec.Events, since, sess.lastPollIdx, eventType)
		if len(events) > 0 || wait == 0 || time.Now().After(deadline) || ctx.Err() != nil {
			if limit > 0 && len(events) > limit {
				events = events[:limit]
			}
			if len(events) > 0 {
				sess.lastPollIdx = advanceLastPollIdx(events, rec.Events)
				if err := b.oastStore.UpdatePollCursor(sess.info.ID, sess.lastPollIdx); err != nil {
					log.Printf("oast: session %s persist poll cursor: %v", sess.info.ID, err)
				}
			}
			result := &OastPollResultInfo{
				Events:       events,
				DroppedCount: rec.DroppedCount,
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
func filterEvents(full []store.OastEvent, since string, lastPollIdx int, eventType string) []store.OastEvent {
	var events []store.OastEvent
	switch since {
	case "":
		events = full
	case sinceLast:
		if lastPollIdx >= len(full) {
			events = nil
		} else {
			events = full[lastPollIdx:]
		}
	default:
		// Try parsing as timestamp first
		if sinceTime, ok := parseSinceTimestamp(since); ok {
			events = bulk.SliceFilter(func(e store.OastEvent) bool {
				return e.Time.After(sinceTime)
			}, full)
		} else {
			// Find event by ID and return everything after it
			var found bool
			for i, e := range full {
				if e.ID == since {
					if i+1 >= len(full) {
						events = nil
					} else {
						events = full[i+1:]
					}
					found = true
					break
				}
			}
			if !found {
				events = full
			}
		}
	}

	if eventType == "" || len(events) == 0 {
		return events
	}

	return bulk.SliceFilter(func(e store.OastEvent) bool {
		return matchesEventType(e.Type, eventType)
	}, events)
}

// advanceLastPollIdx returns the new cursor after returning returnedEvents.
func advanceLastPollIdx(returned []store.OastEvent, full []store.OastEvent) int {
	lastID := returned[len(returned)-1].ID
	for i, e := range full {
		if e.ID == lastID {
			return i + 1
		}
	}
	return len(full)
}

// matchesEventType reports whether an event type matches the filter.
// "http" and "https" are treated as equivalent since agents typically want both.
func matchesEventType(eventType, filter string) bool {
	if eventType == filter {
		return true
	}
	return (eventType == "http" || eventType == "https") && (filter == "http" || filter == "https")
}

func (b *InteractshBackend) GetEvent(_ context.Context, eventID string) (*store.OastEvent, error) {
	ev, ok := b.oastStore.FindEvent(eventID)
	if !ok {
		return nil, fmt.Errorf("%w: event %s", ErrNotFound, eventID)
	}
	return ev, nil
}

func (b *InteractshBackend) ListSessions(ctx context.Context) ([]store.OastSessionInfo, error) {
	recs := b.oastStore.List()
	sessions := make([]store.OastSessionInfo, 0, len(recs))
	for _, rec := range recs {
		sessions = append(sessions, rec.OastSessionInfo)
	}
	return sessions, nil
}

func (b *InteractshBackend) DeleteSession(ctx context.Context, idOrDomain string) error {
	rec, ok := b.oastStore.Resolve(idOrDomain)
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, idOrDomain)
	}

	return b.deleteSession(rec.ID, rec.Domain)
}

func (b *InteractshBackend) deleteSession(id, domain string) error {
	b.mu.Lock()
	sess := b.sessions[domain]
	delete(b.sessions, domain)
	b.mu.Unlock()

	if sess != nil {
		sess.mu.Lock()
		if !sess.stopped {
			sess.stopped = true
			close(sess.notify) // wake any waiters
		}
		sess.mu.Unlock()
	}

	return b.oastStore.Delete(id)
}

func (b *InteractshBackend) Close(ctx context.Context) error {
	// deadline-less ctx gets a backstop so the client-close wait always unblocks
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, shutdownBackstop)
		defer cancel()
	}

	b.initMu.Lock()
	defer b.initMu.Unlock()

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true

	// Stop all sessions under the lock.
	// Safe: sess.mu is a leaf lock, never held while acquiring b.mu.
	for _, sess := range b.sessions {
		sess.mu.Lock()
		if !sess.stopped {
			sess.stopped = true
			close(sess.notify)
		}
		sess.mu.Unlock()
	}

	// Close all clients in parallel (deregistration makes HTTP calls)
	var wg sync.WaitGroup
	for _, c := range b.clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Close(); err != nil {
				log.Printf("oast: error closing client: %v", err)
			}
		}()
	}

	b.sessions = nil
	b.clients = nil
	b.mu.Unlock()

	// ctx bounds the wait; a lingering c.Close() finishes on the shared http client timeout
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		log.Printf("oast: timeout closing clients")
	}

	return b.oastStore.Close()
}

// cleanupIdleClients removes clients with no active sessions from the map.
// Caller must hold b.mu. Returns removed clients for closing outside the lock.
func (b *InteractshBackend) cleanupIdleClients() []*oobclient.Client {
	activeTargets := make(map[string]bool, len(b.sessions))
	for _, sess := range b.sessions {
		activeTargets[sess.info.RedirectTarget] = true
	}

	var stale []*oobclient.Client
	for target, c := range b.clients {
		if target == "" {
			continue // never clean up the default (no-redirect) client
		}
		if !activeTargets[target] {
			stale = append(stale, c)
			delete(b.clients, target)
		}
	}
	return stale
}

// resolveSession finds the live runtime session for an ID, label, or domain.
// Persisted sessions without a live handle report not running; live collection
// cannot resume for them.
func (b *InteractshBackend) resolveSession(identifier string) (*oastSession, error) {
	rec, ok := b.oastStore.Resolve(identifier)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, identifier)
	}

	b.mu.RLock()
	sess := b.sessions[rec.Domain]
	b.mu.RUnlock()

	if sess == nil {
		return nil, fmt.Errorf("%w: session %s (not running in this process)", ErrNotFound, rec.ID)
	}
	return sess, nil
}

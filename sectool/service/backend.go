package service

import (
	"context"
	"errors"
	"time"
)

// ErrLabelExists is returned when label conflicts with an existing entry (rule or OAST).
var ErrLabelExists = errors.New("label already exists")

// ErrNotFound is returned when a requested resource (rule, session, etc.) doesn't exist.
var ErrNotFound = errors.New("not found")

// Rule type constants for match/replace rules.
const (
	RuleTypeRequestHeader  = "request_header"
	RuleTypeRequestBody    = "request_body"
	RuleTypeResponseHeader = "response_header"
	RuleTypeResponseBody   = "response_body"
)

// HttpBackend defines the interface for proxy history and request sending.
// This abstraction allows switching between Burp MCP and future built-in proxies.
type HttpBackend interface {
	// Close shuts down the HttpBackend.
	Close() error

	// GetProxyHistory retrieves proxy HTTP history entries.
	// Returns up to count entries starting from offset.
	GetProxyHistory(ctx context.Context, count int, offset uint32) ([]ProxyEntry, error)

	// SendRequest sends an HTTP request and returns the response.
	// The request is raw HTTP bytes. Response is returned as headers and body.
	SendRequest(ctx context.Context, name string, req SendRequestInput) (*SendRequestResult, error)

	// ListRules returns all enabled match/replace rules managed by sectool.
	// websocket=true returns WebSocket rules, false returns HTTP rules.
	ListRules(ctx context.Context, websocket bool) ([]RuleEntry, error)

	// AddRule creates a new match/replace rule.
	// Returns the created rule with assigned ID.
	AddRule(ctx context.Context, websocket bool, rule ProxyRuleInput) (*RuleEntry, error)

	// UpdateRule modifies an existing rule by ID or label.
	// Searches both HTTP and WebSocket rules automatically.
	UpdateRule(ctx context.Context, idOrLabel string, rule ProxyRuleInput) (*RuleEntry, error)

	// DeleteRule removes a rule by ID or label.
	// Searches both HTTP and WebSocket rules automatically.
	DeleteRule(ctx context.Context, idOrLabel string) error
}

// ProxyRuleInput contains parameters for creating/updating a rule.
type ProxyRuleInput struct {
	Label   string // Optional label for easier reference
	Type    string // Required: rule type
	IsRegex bool
	Match   string
	Replace string
}

// ProxyEntry represents a single proxy history entry in HttpBackend-agnostic form.
type ProxyEntry struct {
	Request  string // Raw HTTP request
	Response string // Raw HTTP response
	Notes    string // User annotations
}

// Target specifies the destination for a request.
type Target struct {
	Hostname  string
	Port      int
	UsesHTTPS bool
}

// SendRequestInput contains all parameters for sending a request.
type SendRequestInput struct {
	RawRequest      []byte
	Target          Target
	FollowRedirects bool
	Timeout         time.Duration
}

// SendRequestResult contains the response from a sent request.
type SendRequestResult struct {
	Headers  []byte
	Body     []byte
	Duration time.Duration
}

// MaxOastEventsPerSession is the maximum number of events stored per session.
// Oldest events are dropped when this limit is exceeded.
const MaxOastEventsPerSession = 2000

// OastBackend defines the interface for OAST (Out-of-band Application Security Testing).
type OastBackend interface {
	// CreateSession registers with the OAST provider and starts background polling.
	// Returns session with short ID and domain.
	// If label is non-empty, it must be unique across all sessions.
	CreateSession(ctx context.Context, label string) (*OastSessionInfo, error)

	// PollSession returns events for a session.
	// idOrDomain accepts either the short ID or the full domain.
	// since filters events: empty returns all, "last" returns since last poll, or an event ID.
	// wait specifies how long to block waiting for events (0 = return immediately).
	// limit caps the number of events returned (0 = no limit). When used with "since last",
	// the last position is updated to the last returned event (for pagination).
	PollSession(ctx context.Context, idOrDomain string, since string, wait time.Duration, limit int) (*OastPollResultInfo, error)

	// GetEvent retrieves a single event by ID from a session.
	// Returns the full event details without truncation.
	GetEvent(ctx context.Context, idOrDomain string, eventID string) (*OastEventInfo, error)

	// ListSessions returns all active sessions.
	ListSessions(ctx context.Context) ([]OastSessionInfo, error)

	// DeleteSession stops polling and deregisters from the OAST provider.
	// idOrDomain accepts either the short ID or the full domain.
	DeleteSession(ctx context.Context, idOrDomain string) error

	// Close cleans up all sessions (called on service shutdown).
	// Should attempt deregistration with a short timeout.
	Close() error
}

// OastSessionInfo represents an active OAST session (internal domain type).
type OastSessionInfo struct {
	ID        string    // Short sectool ID (e.g., "a1b2c3")
	Domain    string    // Full Interactsh domain (e.g., "xyz123.oast.fun")
	Label     string    // Optional user-provided label for easier reference
	CreatedAt time.Time // When the session was created
}

// OastEventInfo represents a captured out-of-band interaction (internal domain type).
type OastEventInfo struct {
	ID        string                 // Short sectool ID
	Time      time.Time              // When the interaction occurred
	Type      string                 // "dns", "http", "smtp"
	SourceIP  string                 // Remote address of the interaction
	Subdomain string                 // Full subdomain that was accessed
	Details   map[string]interface{} // Protocol-specific details
}

// OastPollResultInfo contains the result of polling for events.
type OastPollResultInfo struct {
	Events       []OastEventInfo // Events matching the filter
	DroppedCount int             // Number of events dropped due to buffer limit
}

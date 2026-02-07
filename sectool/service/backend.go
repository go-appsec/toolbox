package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/go-appsec/llm-security-toolbox/sectool/protocol"
	"github.com/go-appsec/llm-security-toolbox/sectool/service/proxy"
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

	RuleTypeWSToServer = "ws:to-server"
	RuleTypeWSToClient = "ws:to-client"
	RuleTypeWSBoth     = "ws:both"
)

const sinceLast = "last"

// isWSType returns true if the type is a WebSocket type (ws: prefix).
func isWSType(t string) bool {
	return strings.HasPrefix(t, "ws:")
}

// HttpBackend defines the interface for proxy history and request sending.
// This abstraction allows switching between Burp MCP and future built-in proxies.
type HttpBackend interface {
	// Close shuts down the HttpBackend.
	Close() error

	// GetProxyHistory retrieves proxy HTTP history entries.
	// Returns up to count entries starting from offset.
	GetProxyHistory(ctx context.Context, count int, offset uint32) ([]ProxyEntry, error)

	// GetProxyHistoryMeta retrieves lightweight metadata for proxy history entries.
	// Returns up to count entries starting from offset.
	GetProxyHistoryMeta(ctx context.Context, count int, offset uint32) ([]ProxyEntryMeta, error)

	// SendRequest sends an HTTP request and returns the response.
	// The request is raw HTTP bytes. Response is returned as headers and body.
	SendRequest(ctx context.Context, name string, req SendRequestInput) (*SendRequestResult, error)

	// ListRules returns all enabled match/replace rules managed by sectool.
	// websocket=true returns WebSocket rules, false returns HTTP rules.
	ListRules(ctx context.Context, websocket bool) ([]protocol.RuleEntry, error)

	// AddRule creates a new match/replace rule.
	// WebSocket vs HTTP is inferred from rule.Type (ws:* types are WebSocket).
	// Returns the created rule with assigned ID.
	AddRule(ctx context.Context, rule ProxyRuleInput) (*protocol.RuleEntry, error)

	// UpdateRule modifies an existing rule by ID or label.
	// Searches both HTTP and WebSocket rules automatically.
	UpdateRule(ctx context.Context, idOrLabel string, rule ProxyRuleInput) (*protocol.RuleEntry, error)

	// DeleteRule removes a rule by ID or label.
	// Searches both HTTP and WebSocket rules automatically.
	DeleteRule(ctx context.Context, idOrLabel string) error
}

// ProxyEntryMeta holds lightweight metadata for a proxy history entry.
// Used by summary/list paths to avoid deserializing full request/response bodies.
type ProxyEntryMeta struct {
	Method      string
	Host        string
	Path        string // includes query string
	Status      int
	RespLen     int
	Protocol    string
	ContentType string
}

// ProxyRuleInput contains parameters for creating/updating a rule.
type ProxyRuleInput struct {
	Label   string // Optional label for easier reference
	Type    string // Required: rule type
	IsRegex *bool  // nil = preserve existing, non-nil = set to value
	Match   string
	Replace string
}

// ProxyEntry represents a single proxy history entry in HttpBackend-agnostic form.
type ProxyEntry struct {
	Request  string `json:"request"`  // Raw HTTP request
	Response string `json:"response"` // Raw HTTP response
	Notes    string `json:"notes"`    // User annotations
	Protocol string `json:"protocol"` // "http/1.1" or "h2" (empty defaults to http/1.1)
}

// Target specifies the destination for a request.
// Type alias for proxy.Target to enable unified target handling across packages.
type Target = proxy.Target

// SendRequestInput contains all parameters for sending a request.
type SendRequestInput struct {
	RawRequest      []byte
	Target          Target
	FollowRedirects bool
	Timeout         time.Duration
	Force           bool // Skip validation for protocol-level tests

	// Protocol from the original history entry ("http/1.1" or "h2")
	// Empty defaults to HTTP/1.1
	Protocol string
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
	// eventType filters by protocol: empty returns all, otherwise one of dns, http, smtp, ftp, ldap, smb, responder.
	// wait specifies how long to block waiting for events (0 = return immediately).
	// limit caps the number of events returned (0 = no limit). When used with "since last",
	// the last position is updated to the last returned event (for pagination).
	PollSession(ctx context.Context, idOrDomain string, since string, eventType string, wait time.Duration, limit int) (*OastPollResultInfo, error)

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

// CrawlerBackend defines the interface for web crawling operations.
type CrawlerBackend interface {
	// CreateSession starts a new crawl session. Returns immediately; crawling is async.
	// Returns error if max concurrent sessions reached or no valid seeds/domains.
	CreateSession(ctx context.Context, opts CrawlOptions) (*CrawlSessionInfo, error)

	// AddSeeds adds URLs to an existing session (can be called while running).
	// sessionID can be the ID or label. Returns error if session is not running.
	AddSeeds(ctx context.Context, sessionID string, seeds []CrawlSeed) error

	// GetStatus returns session progress metrics.
	// sessionID can be the ID or label. Returns ErrNotFound if session doesn't exist.
	GetStatus(ctx context.Context, sessionID string) (*CrawlStatus, error)

	// ListFlows returns flows matching filters.
	// sessionID can be the ID or label.
	ListFlows(ctx context.Context, sessionID string, opts CrawlListOptions) ([]CrawlFlow, error)

	// ListForms returns forms discovered in a session.
	// sessionID can be the ID or label.
	ListForms(ctx context.Context, sessionID string, limit int) ([]DiscoveredForm, error)

	// ListErrors returns errors encountered in a session.
	// sessionID can be the ID or label.
	ListErrors(ctx context.Context, sessionID string, limit int) ([]CrawlError, error)

	// GetFlow returns a flow by ID. Returns ErrNotFound if flow doesn't exist.
	GetFlow(ctx context.Context, flowID string) (*CrawlFlow, error)

	// StopSession immediately stops a running crawl. In-flight requests are abandoned.
	// sessionID can be the ID or label.
	StopSession(ctx context.Context, sessionID string) error

	// ListSessions returns all sessions (active and completed), most recent first.
	// limit=0 means no limit.
	ListSessions(ctx context.Context, limit int) ([]CrawlSessionInfo, error)

	// Close cleans up all sessions (called on service shutdown).
	Close() error
}

// CrawlOptions contains parameters for creating a crawl session.
type CrawlOptions struct {
	Label             string            // Optional unique label for the session
	Seeds             []CrawlSeed       // Initial seeds (URLs and/or flow IDs)
	ExplicitDomains   []string          // User-specified via --domain
	AllowedPaths      []string          // Glob patterns (default: all)
	DisallowedPaths   []string          // Glob patterns (default from config)
	IncludeSubdomains bool              // Default: true
	MaxDepth          int               // 0 = unlimited
	MaxRequests       int               // 0 = unlimited
	Delay             time.Duration     // Default: 200ms
	RandomDelay       time.Duration     // Additional random jitter
	Parallelism       int               // Default: 2
	IgnoreRobotsTxt   bool              // Default: false
	SubmitForms       bool              // Default: false
	ExtractForms      *bool             // Default: true (from config)
	Headers           map[string]string // Custom headers
}

// CrawlSeed represents a seed for starting a crawl.
type CrawlSeed struct {
	URL    string // Direct URL seed
	FlowID string // Or proxy flow ID - extracts URL and ALL headers
}

// CrawlListOptions contains filters for listing crawl flows.
// Mirrors ProxyListRequest filters for consistency.
type CrawlListOptions struct {
	Host         string            // Glob pattern for host
	PathPattern  string            // Glob pattern for path
	StatusCodes  *StatusCodeFilter // Filter by status codes (supports ranges like 2XX)
	Methods      []string          // Filter by HTTP methods
	Contains     string            // Search URL and headers
	ContainsBody string            // Search request/response body
	ExcludeHost  string            // Exclude hosts matching glob
	ExcludePath  string            // Exclude paths matching glob
	Since        string            // Only flows after this flow_id, or "last" for new flows
	Limit        int               // Max results (0 = no limit)
	Offset       int               // Skip first N results
}

// CrawlSessionInfo represents metadata about a crawl session.
type CrawlSessionInfo struct {
	ID        string    // Short sectool ID
	Label     string    // Optional user-provided label
	CreatedAt time.Time // When the session was created
	State     string    // "running", "stopped", "completed", "error"
}

// CrawlStatus contains progress metrics for a crawl session.
type CrawlStatus struct {
	State           string        // "running", "stopped", "completed", "error"
	URLsQueued      int           // URLs waiting to be visited
	URLsVisited     int           // URLs successfully visited
	URLsErrored     int           // URLs that resulted in errors
	FormsDiscovered int           // Forms found during crawl
	Duration        time.Duration // Time since session started
	LastActivity    time.Time     // When last request was made
	ErrorMessage    string        // Error details if State is "error"
}

// CrawlFlow represents a single captured request/response from crawling.
type CrawlFlow struct {
	ID             string        // Short sectool ID
	SessionID      string        // Parent session ID
	URL            string        // Full URL visited
	Host           string        // Hostname (extracted from URL)
	Path           string        // Path with query string (extracted from URL)
	Method         string        // HTTP method
	FoundOn        string        // Parent URL where discovered
	Depth          int           // Crawl depth from seed
	StatusCode     int           // HTTP response status
	ContentType    string        // Response content type
	ResponseLength int           // Response body length in bytes
	Request        []byte        // Wire-format bytes from httputil.DumpRequestOut
	Response       []byte        // Wire-format bytes from httputil.DumpResponse
	Truncated      bool          // True if response exceeded max_response_body_bytes
	Duration       time.Duration // Request/response round-trip time
	DiscoveredAt   time.Time     // When this flow was captured
}

// DiscoveredForm represents a form found during crawling.
type DiscoveredForm struct {
	ID        string      // Short sectool ID
	SessionID string      // Parent session ID
	URL       string      // Page containing the form
	Action    string      // Form action URL (resolved to absolute)
	Method    string      // GET/POST
	Inputs    []FormInput // Form fields
	HasCSRF   bool        // Detected CSRF token field
}

// FormInput represents a single form field.
type FormInput struct {
	Name     string // Field name attribute
	Type     string // text, password, hidden, select, textarea, etc.
	Value    string // Default/current value
	Required bool   // Has required attribute
}

// CrawlError represents an error encountered during crawling.
type CrawlError struct {
	FlowID string // May be empty if request never sent
	URL    string // URL that caused the error
	Error  string // Error message
	Status int    // HTTP status if available
}

// ExportResult contains information about an exported flow bundle.
// BundleID equals FlowID for simpler mental model - one ID per request.
// Re-exporting the same flow overwrites the bundle, restoring original state.
type ExportResult struct {
	BundleID   string   // Bundle identifier (equals flow_id)
	BundlePath string   // Full path to bundle directory
	Files      []string // List of created files
}

// parseSinceTimestamp attempts to parse a string as a timestamp in multiple formats.
// Returns the parsed time and true if successful, or zero time and false if not a timestamp.
func parseSinceTimestamp(s string) (time.Time, bool) {
	now := time.Now()
	loc := now.Location()
	// Try formats with timezones
	for _, format := range []string{time.RFC3339} {
		if t, err := time.Parse(format, s); err == nil {
			return t, true
		}
	}
	// Try RFC3339 without timezone (assume local)
	if t, err := time.ParseInLocation("2006-01-02T15:04:05", s, loc); err == nil {
		return t, true
	}
	// Try other formats without timezone
	for _, format := range []string{time.DateTime, time.Stamp} {
		if t, err := time.ParseInLocation(format, s, loc); err == nil {
			return t, true
		}
	}
	// Time only - assume today's date
	if t, err := time.ParseInLocation(time.TimeOnly, s, loc); err == nil {
		return time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), t.Second(), 0, loc), true
	}
	return time.Time{}, false
}

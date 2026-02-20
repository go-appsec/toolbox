package protocol

import (
	"encoding/json"

	"github.com/go-appsec/toolbox/sectool/jwt"
)

// =============================================================================
// Proxy Types
// =============================================================================

// SummaryEntry represents grouped traffic by (host, path, method, status).
type SummaryEntry struct {
	Host   string `json:"host"`
	Path   string `json:"path"`
	Method string `json:"method"`
	Status int    `json:"status"`
	Count  int    `json:"count"`
}

// FlowEntry represents a single proxy history entry in list view.
type FlowEntry struct {
	FlowID         string `json:"flow_id"`
	Method         string `json:"method"`
	Scheme         string `json:"scheme"`
	Host           string `json:"host"`
	Port           int    `json:"port,omitempty"`
	Path           string `json:"path"`
	Status         int    `json:"status"`
	ResponseLength int    `json:"response_length"`
	Source         string `json:"source,omitempty"` // "proxy" or "replay"
}

// RequestLine contains path and version from the HTTP request line.
type RequestLine struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// ProxyPollResponse is the unified response for proxy_poll.
type ProxyPollResponse struct {
	Aggregates []SummaryEntry `json:"aggregates,omitempty"` // summary mode
	Flows      []FlowEntry    `json:"flows,omitempty"`      // list mode
	Note       string         `json:"note,omitempty"`
}

// MarshalJSON preserves non-nil empty slices (as []) while omitting nil ones.
// This ensures the active mode key is always present even with zero results.
func (r ProxyPollResponse) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	if r.Aggregates != nil {
		m["aggregates"] = r.Aggregates
	}
	if r.Flows != nil {
		m["flows"] = r.Flows
	}
	if r.Note != "" {
		m["note"] = r.Note
	}
	return json.Marshal(m)
}

// FlowGetResponse is the response for flow_get.
type FlowGetResponse struct {
	FlowID            string              `json:"flow_id"`
	Source            string              `json:"source"`
	Method            string              `json:"method"`
	URL               string              `json:"url"`
	ReqHeaders        string              `json:"request_headers"`
	ReqHeadersParsed  map[string][]string `json:"request_headers_parsed,omitempty"`
	ReqLine           *RequestLine        `json:"request_line,omitempty"`
	ReqBody           string              `json:"request_body"`
	ReqSize           int                 `json:"request_size"`
	Status            int                 `json:"status"`
	StatusLine        string              `json:"status_line"`
	RespHeaders       string              `json:"response_headers"`
	RespHeadersParsed map[string][]string `json:"response_headers_parsed,omitempty"`
	RespBody          string              `json:"response_body"`
	RespSize          int                 `json:"response_size"`
	Duration          string              `json:"duration,omitempty"`
	FoundOn           string              `json:"found_on,omitempty"`
	Depth             int                 `json:"depth,omitempty"`
	Truncated         bool                `json:"truncated,omitempty"`
	Note              string              `json:"note,omitempty"`
}

// =============================================================================
// Response Types
// =============================================================================

// ResponseDetails contains HTTP response summary fields.
type ResponseDetails struct {
	Status      int    `json:"status"`
	StatusLine  string `json:"status_line"`
	RespHeaders string `json:"response_headers"`
	RespPreview string `json:"response_preview,omitempty"`
	RespSize    int    `json:"response_size"`
}

// =============================================================================
// Replay Types
// =============================================================================

// ReplaySendResponse is the response for replay_send.
type ReplaySendResponse struct {
	FlowID   string `json:"flow_id"`
	Duration string `json:"duration"`
	ResponseDetails
}

// =============================================================================
// OAST Types
// =============================================================================

// OastCreateResponse is the response for oast_create.
type OastCreateResponse struct {
	OastID string `json:"oast_id"`
	Domain string `json:"domain"`
	Label  string `json:"label,omitempty"`
}

// OastSummaryEntry represents aggregated OAST events by (subdomain, source_ip, type).
type OastSummaryEntry struct {
	Subdomain string `json:"subdomain"`
	SourceIP  string `json:"source_ip"`
	Type      string `json:"type"`
	Count     int    `json:"count"`
}

// OastPollResponse is the response for oast_poll.
type OastPollResponse struct {
	Aggregates   []OastSummaryEntry `json:"aggregates,omitempty"` // summary mode
	Events       []OastEvent        `json:"events,omitempty"`     // list mode
	DroppedCount int                `json:"dropped_count,omitempty"`
}

// MarshalJSON preserves non-nil empty slices (as []) while omitting nil ones.
func (r OastPollResponse) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	if r.Aggregates != nil {
		m["aggregates"] = r.Aggregates
	}
	if r.Events != nil {
		m["events"] = r.Events
	}
	if r.DroppedCount > 0 {
		m["dropped_count"] = r.DroppedCount
	}
	return json.Marshal(m)
}

// OastEvent represents a single OAST interaction event.
type OastEvent struct {
	EventID   string                 `json:"event_id"`
	Time      string                 `json:"time"`
	Type      string                 `json:"type"`
	SourceIP  string                 `json:"source_ip"`
	Subdomain string                 `json:"subdomain,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// OastListResponse is the response for oast_list.
type OastListResponse struct {
	Sessions []OastSession `json:"sessions"`
}

// OastSession represents an active OAST session.
type OastSession struct {
	OastID    string `json:"oast_id"`
	Domain    string `json:"domain"`
	Label     string `json:"label,omitempty"`
	CreatedAt string `json:"created_at"`
}

// OastGetResponse is the response for oast_get.
type OastGetResponse struct {
	EventID   string                 `json:"event_id"`
	Time      string                 `json:"time"`
	Type      string                 `json:"type"`
	SourceIP  string                 `json:"source_ip"`
	Subdomain string                 `json:"subdomain,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// =============================================================================
// Rule Types
// =============================================================================

// RuleListResponse is the response for proxy_rule_list.
type RuleListResponse struct {
	Rules []RuleEntry `json:"rules"`
}

// RuleEntry represents a match/replace rule.
type RuleEntry struct {
	RuleID  string `json:"rule_id"`
	Type    string `json:"type"`
	Label   string `json:"label,omitempty"`
	IsRegex bool   `json:"is_regex,omitempty"`
	Match   string `json:"match,omitempty"`
	Replace string `json:"replace,omitempty"`
}

// =============================================================================
// Crawler Types
// =============================================================================

// CrawlCreateResponse is the response for crawl_create.
type CrawlCreateResponse struct {
	SessionID string `json:"session_id"`
	Label     string `json:"label,omitempty"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
}

// CrawlSeedResponse is the response for crawl_seed.
type CrawlSeedResponse struct {
	AddedCount int `json:"added_count"`
}

// CrawlStatusResponse is the response for crawl_status.
type CrawlStatusResponse struct {
	State           string `json:"state"`
	URLsQueued      int    `json:"urls_queued"`
	URLsVisited     int    `json:"urls_visited"`
	URLsErrored     int    `json:"urls_errored"`
	FormsDiscovered int    `json:"forms_discovered"`
	Duration        string `json:"duration"`
	LastActivity    string `json:"last_activity"`
	ErrorMessage    string `json:"error_message,omitempty"`
}

// CrawlPollResponse is the unified response for crawl_poll.
type CrawlPollResponse struct {
	SessionID  string         `json:"session_id"`
	State      string         `json:"state,omitempty"`
	Duration   string         `json:"duration,omitempty"` // summary only
	Aggregates []SummaryEntry `json:"aggregates,omitempty"`
	Flows      []CrawlFlow    `json:"flows,omitempty"`
	Forms      []CrawlForm    `json:"forms,omitempty"`
	Errors     []CrawlError   `json:"errors,omitempty"`
	Note       string         `json:"note,omitempty"`
}

// MarshalJSON preserves non-nil empty slices (as []) while omitting nil ones.
func (r CrawlPollResponse) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"session_id": r.SessionID,
	}
	if r.State != "" {
		m["state"] = r.State
	}
	if r.Duration != "" {
		m["duration"] = r.Duration
	}
	if r.Aggregates != nil {
		m["aggregates"] = r.Aggregates
	}
	if r.Flows != nil {
		m["flows"] = r.Flows
	}
	if r.Forms != nil {
		m["forms"] = r.Forms
	}
	if r.Errors != nil {
		m["errors"] = r.Errors
	}
	if r.Note != "" {
		m["note"] = r.Note
	}
	return json.Marshal(m)
}

// CrawlFlow is a crawled request/response summary.
type CrawlFlow struct {
	FlowID         string `json:"flow_id"`
	Method         string `json:"method"`
	Host           string `json:"host"`
	Path           string `json:"path"`
	Status         int    `json:"status"`
	ResponseLength int    `json:"response_length"`
	Duration       string `json:"duration"`
	FoundOn        string `json:"found_on,omitempty"`
}

// CrawlForm is a discovered form.
type CrawlForm struct {
	FormID  string      `json:"form_id"`
	URL     string      `json:"url"`
	Action  string      `json:"action"`
	Method  string      `json:"method"`
	HasCSRF bool        `json:"has_csrf"`
	Inputs  []FormInput `json:"inputs"`
}

// FormInput is a form input field.
type FormInput struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value,omitempty"`
	Required bool   `json:"required,omitempty"`
}

// CrawlError is a crawl error.
type CrawlError struct {
	URL    string `json:"url"`
	Status int    `json:"status,omitempty"`
	Error  string `json:"error"`
}

// CrawlSessionsResponse is the response for crawl_sessions.
type CrawlSessionsResponse struct {
	Sessions []CrawlSession `json:"sessions"`
}

// CrawlSession is a crawl session entry.
type CrawlSession struct {
	SessionID string `json:"session_id"`
	Label     string `json:"label,omitempty"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
}

// =============================================================================
// Cookie Types
// =============================================================================

// CookieJarResponse is the response for cookie_jar.
type CookieJarResponse struct {
	Cookies []CookieEntry `json:"cookies"`
}

// CookieEntry represents a cookie observed in proxy/replay traffic.
type CookieEntry struct {
	Name     string      `json:"name"`
	Domain   string      `json:"domain"`
	Path     string      `json:"path"`
	Secure   bool        `json:"secure"`
	HttpOnly bool        `json:"httponly"`
	SameSite string      `json:"samesite,omitempty"`
	Expires  string      `json:"expires"`
	Value    string      `json:"value,omitempty"`
	Decoded  *jwt.Result `json:"decoded,omitempty"`
	FlowID   string      `json:"flow_id"`
}

// =============================================================================
// Diff Types
// =============================================================================

// DiffFlowResponse is the response for diff_flow.
type DiffFlowResponse struct {
	Same     bool          `json:"same,omitempty"`
	Request  *RequestDiff  `json:"request,omitempty"`
	Response *ResponseDiff `json:"response,omitempty"`
}

// RequestDiff contains differences in the request.
type RequestDiff struct {
	Method  *ABPair     `json:"method,omitempty"`
	Path    *ABPair     `json:"path,omitempty"`
	Query   *ParamsDiff `json:"query,omitempty"`
	Headers *ParamsDiff `json:"headers,omitempty"`
	Body    *BodyDiff   `json:"body,omitempty"`
}

// ResponseDiff contains differences in the response.
type ResponseDiff struct {
	Status  *ABIntPair  `json:"status,omitempty"`
	Headers *ParamsDiff `json:"headers,omitempty"`
	Body    *BodyDiff   `json:"body,omitempty"`
}

// ABPair represents a string value that differs between flow A and B.
type ABPair struct {
	A string `json:"a"`
	B string `json:"b"`
}

// ABIntPair represents an integer value that differs between flow A and B.
type ABIntPair struct {
	A int `json:"a"`
	B int `json:"b"`
}

// ParamsDiff shows structured add/remove/change for headers or query params.
type ParamsDiff struct {
	Added          []NameValue    `json:"added,omitempty"`
	Removed        []NameValue    `json:"removed,omitempty"`
	Changed        []NameABChange `json:"changed,omitempty"`
	UnchangedCount int            `json:"unchanged_count"`
}

// NameValue is a name-value pair for added/removed headers or params.
type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// NameABChange shows a header or param that changed between A and B.
type NameABChange struct {
	Name string `json:"name"`
	A    string `json:"a"`
	B    string `json:"b"`
}

// BodyDiff shows body differences, format-aware.
type BodyDiff struct {
	Format string `json:"format"` // "json", "text", "binary"

	// JSON diff fields
	Added          []PathValue    `json:"added,omitempty"`
	Removed        []PathEntry    `json:"removed,omitempty"`
	Changed        []PathABChange `json:"changed,omitempty"`
	UnchangedCount int            `json:"unchanged_count,omitempty"`

	// Text diff fields
	Diff    string `json:"diff,omitempty"`
	Summary string `json:"summary,omitempty"`

	// Size fields (text and binary)
	ASize int `json:"a_size,omitempty"`
	BSize int `json:"b_size,omitempty"`

	// Binary diff fields
	Same *bool `json:"same,omitempty"`

	Truncated bool `json:"truncated,omitempty"`
}

// PathValue is a JSON path with its value (for added paths).
type PathValue struct {
	Path  string      `json:"path"`
	Value interface{} `json:"value"`
}

// PathEntry is a JSON path (for removed paths).
type PathEntry struct {
	Path string `json:"path"`
}

// PathABChange shows a JSON path whose value changed.
type PathABChange struct {
	Path string      `json:"path"`
	A    interface{} `json:"a"`
	B    interface{} `json:"b"`
}

// =============================================================================
// Reflection Types
// =============================================================================

// FindReflectedResponse is the response for find_reflected.
type FindReflectedResponse struct {
	Reflections []Reflection `json:"reflections"`
}

// Reflection represents a request parameter value found in the response.
type Reflection struct {
	Name         string   `json:"name"`
	Source       string   `json:"source"`
	Value        string   `json:"value"`
	Locations    []string `json:"locations"`
	RawReflected bool     `json:"raw_reflected,omitempty"` // value has special chars and appears unencoded
}

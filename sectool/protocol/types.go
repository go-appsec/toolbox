package protocol

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
}

// ProxyGetResponse is the response for proxy_get.
type ProxyGetResponse struct {
	FlowID            string              `json:"flow_id"`
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
	ReplayID string `json:"replay_id"`
	Duration string `json:"duration"`
	ResponseDetails
}

// ReplayGetResponse is the response for replay_get.
type ReplayGetResponse struct {
	ReplayID          string              `json:"replay_id"`
	Duration          string              `json:"duration"`
	Status            int                 `json:"status"`
	StatusLine        string              `json:"status_line"`
	RespHeaders       string              `json:"response_headers"`
	RespHeadersParsed map[string][]string `json:"response_headers_parsed,omitempty"`
	RespBody          string              `json:"response_body"`
	RespSize          int                 `json:"response_size"`
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

// CrawlGetResponse is the response for crawl_get.
type CrawlGetResponse struct {
	FlowID            string              `json:"flow_id"`
	Method            string              `json:"method"`
	URL               string              `json:"url"`
	FoundOn           string              `json:"found_on,omitempty"`
	Depth             int                 `json:"depth"`
	ReqHeaders        string              `json:"request_headers"`
	ReqHeadersParsed  map[string][]string `json:"request_headers_parsed,omitempty"`
	ReqBody           string              `json:"request_body"`
	ReqSize           int                 `json:"request_size"`
	Status            int                 `json:"status"`
	StatusLine        string              `json:"status_line"`
	RespHeaders       string              `json:"response_headers"`
	RespHeadersParsed map[string][]string `json:"response_headers_parsed,omitempty"`
	RespBody          string              `json:"response_body"`
	RespSize          int                 `json:"response_size"`
	Truncated         bool                `json:"truncated,omitempty"`
	Duration          string              `json:"duration"`
}

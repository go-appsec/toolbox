package mcpclient

// =============================================================================
// Proxy Options
// =============================================================================

// ProxyPollOpts are options for ProxyPoll.
type ProxyPollOpts struct {
	OutputMode   string // "summary" or "flows"
	Host         string
	Path         string
	Method       string
	Status       string
	Contains     string
	ContainsBody string
	Since        string // list mode
	ExcludeHost  string
	ExcludePath  string
	Limit        int // list mode
	Offset       int // list mode
}

// RuleAddOpts are options for ProxyRuleAdd.
type RuleAddOpts struct {
	Type    string
	Match   string
	Replace string
	Label   string
	IsRegex bool
}

// RuleUpdateOpts are options for ProxyRuleUpdate.
type RuleUpdateOpts struct {
	Type    string
	Match   string
	Replace string
	Label   string
	IsRegex *bool // nil = preserve existing, non-nil = set to value
}

// =============================================================================
// Replay Options
// =============================================================================

// ReplaySendOpts are options for ReplaySend.
type ReplaySendOpts struct {
	FlowID          string
	Body            string
	Target          string
	AddHeaders      []string
	RemoveHeaders   []string
	Path            string
	Query           string
	SetQuery        []string
	RemoveQuery     []string
	SetJSON         map[string]interface{}
	RemoveJSON      []string
	FollowRedirects bool
	Timeout         string
	Force           bool
}

// RequestSendOpts are options for RequestSend.
type RequestSendOpts struct {
	URL             string
	Method          string
	Headers         map[string]string
	Body            string
	FollowRedirects bool
	Timeout         string
}

// =============================================================================
// Crawl Options
// =============================================================================

// CrawlCreateOpts are options for CrawlCreate.
type CrawlCreateOpts struct {
	Label             string
	SeedURLs          string
	SeedFlows         string
	Domains           string
	Headers           map[string]string
	MaxDepth          int
	MaxRequests       int
	Delay             string
	Parallelism       int
	IncludeSubdomains *bool
	SubmitForms       bool
	IgnoreRobots      bool
}

// CrawlPollOpts are options for CrawlPoll.
type CrawlPollOpts struct {
	OutputMode   string // "summary", "flows", "forms", "errors"
	Host         string
	Path         string
	Method       string
	Status       string
	Contains     string
	ContainsBody string
	ExcludeHost  string
	ExcludePath  string
	Since        string // flows mode
	Limit        int
	Offset       int
}

// OastPollOpts are options for OastPoll.
type OastPollOpts struct {
	OutputMode string // "summary" or "events"
	Since      string
	EventType  string
	Wait       string
	Limit      int
}

package mcpclient

// =============================================================================
// Proxy Options
// =============================================================================

// ProxyPollOpts are options for ProxyPoll.
type ProxyPollOpts struct {
	OutputMode   string // "summary" or "flows"
	Source       string // "proxy", "replay", or empty for both
	Host         string
	Path         string
	Method       string
	Status       string
	SearchHeader string
	SearchBody   string
	Since        string // list mode
	ExcludeHost  string
	ExcludePath  string
	Limit        int // list mode
	Offset       int // list mode
}

// ProxyGetOpts are options for ProxyGet.
type ProxyGetOpts struct {
	Scope    string
	Pattern  string
	FullBody bool // base64-encoded for exact export
}

// RuleAddOpts are options for ProxyRuleAdd.
type RuleAddOpts struct {
	Type    string
	Match   string
	Replace string
	Label   string
	IsRegex bool
}

// =============================================================================
// Replay Options
// =============================================================================

// ReplaySendOpts are options for ReplaySend.
type ReplaySendOpts struct {
	FlowID          string
	Method          string
	Body            string
	Target          string
	SetHeaders      []string
	RemoveHeaders   []string
	Path            string
	Query           string
	SetQuery        []string
	RemoveQuery     []string
	SetJSON         map[string]interface{}
	RemoveJSON      []string
	FollowRedirects bool
	Force           bool
}

// RequestSendOpts are options for RequestSend.
type RequestSendOpts struct {
	URL             string
	Method          string
	Headers         []string
	Body            string
	FollowRedirects bool
	Force           bool
}

// =============================================================================
// Crawl Options
// =============================================================================

// CrawlCreateOpts are options for CrawlCreate.
type CrawlCreateOpts struct {
	Label        string
	SeedURLs     string
	SeedFlows    string
	Domains      string
	Headers      map[string]string
	MaxDepth     int
	MaxRequests  int
	Delay        string
	Parallelism  int
	SubmitForms  bool
	IgnoreRobots bool
}

// CrawlPollOpts are options for CrawlPoll.
type CrawlPollOpts struct {
	OutputMode   string // "summary", "flows", "forms", "errors"
	Host         string
	Path         string
	Method       string
	Status       string
	SearchHeader string
	SearchBody   string
	ExcludeHost  string
	ExcludePath  string
	Since        string // flows mode
	Limit        int
	Offset       int
}

// CrawlGetOpts are options for CrawlGet.
type CrawlGetOpts struct {
	Scope    string
	Pattern  string
	FullBody bool // base64-encoded
}

// CookieJarOpts are options for CookieJar.
type CookieJarOpts struct {
	Name   string
	Domain string
}

// DiffFlowOpts are options for DiffFlow.
type DiffFlowOpts struct {
	FlowA        string
	FlowB        string
	Scope        string
	MaxDiffLines int
}

// OastPollOpts are options for OastPoll.
type OastPollOpts struct {
	OutputMode string // "summary" or "events"
	Since      string
	EventType  string
	Wait       string
	Limit      int
}

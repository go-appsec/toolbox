package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-analyze/bulk"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/go-harden/llm-security-toolbox/sectool/config"
	"github.com/go-harden/llm-security-toolbox/sectool/service/ids"
	"github.com/go-harden/llm-security-toolbox/sectool/service/store"
)

// mcpServer wraps the MCP server and its dependencies.
type mcpServer struct {
	server           *server.MCPServer
	sseServer        *server.SSEServer
	streamableServer *server.StreamableHTTPServer
	httpServer       *http.Server
	listener         net.Listener
	service          *Server

	// workflowMode controls workflow behavior:
	// ""            - workflow tool required before other tools work
	// "none"        - no workflow, all tools available immediately
	// "explore"     - explore instructions in server description, all tools
	// "test-report" - test-report instructions, no crawl tools
	workflowMode        string
	workflowInitialized atomic.Bool
}

// newMCPServer creates a new MCP server instance.
func newMCPServer(svc *Server, workflowMode string) *mcpServer {
	opts := []server.ServerOption{
		server.WithToolCapabilities(false),
		server.WithLogging(),
	}

	// Add instructions based on workflow mode
	switch workflowMode {
	case WorkflowModeExplore:
		opts = append(opts, server.WithInstructions(workflowExploreContent))
	case WorkflowModeTestReport:
		opts = append(opts, server.WithInstructions(workflowTestReportContent))
	}

	mcpSrv := server.NewMCPServer("sectool", config.Version, opts...)

	m := &mcpServer{
		server:       mcpSrv,
		service:      svc,
		workflowMode: workflowMode,
	}

	m.registerTools()

	return m
}

func (m *mcpServer) Start(port int) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	m.listener = listener

	// SSE server for legacy clients
	m.sseServer = server.NewSSEServer(m.server,
		server.WithBaseURL("http://"+addr),
	)

	// Streamable HTTP server for modern clients
	m.streamableServer = server.NewStreamableHTTPServer(m.server,
		server.WithStateLess(true),
	)

	mux := http.NewServeMux()
	mux.Handle("/mcp", m.streamableServer)
	mux.Handle("/sse", m.sseServer)
	mux.Handle("/sse/", m.sseServer)

	m.httpServer = &http.Server{Handler: mux}

	go func() {
		if err := m.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("MCP server error: %v", err)
		}
	}()

	return nil
}

func (m *mcpServer) Addr() string {
	if m.listener != nil {
		return m.listener.Addr().String()
	}
	return ""
}

// Close stops the MCP server.
func (m *mcpServer) Close(ctx context.Context) error {
	var errs []error
	if m.httpServer != nil {
		if err := m.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if m.sseServer != nil {
		if err := m.sseServer.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if m.streamableServer != nil {
		if err := m.streamableServer.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// registerTools registers MCP tools based on workflow mode.
func (m *mcpServer) registerTools() {
	switch m.workflowMode {
	case WorkflowModeNone, WorkflowModeExplore, WorkflowModeCLI: // workflow requirements disabled or pre-set, all tools available
		m.addProxyTools()
		m.addReplayTools()
		m.addOastTools()
		m.addEncodeTools()
		m.addCrawlTools()
	case WorkflowModeTestReport:
		m.addProxyTools()
		m.addReplayTools()
		m.addOastTools()
		m.addEncodeTools()
		// crawl tools excluded
	default: // Empty (default) workflowMode: require workflow tool call first, all tools registered
		m.server.AddTool(m.workflowTool(), m.handleWorkflow)
		m.addProxyTools()
		m.addReplayTools()
		m.addOastTools()
		m.addEncodeTools()
		m.addCrawlTools()
	}
}

func (m *mcpServer) addProxyTools() {
	m.server.AddTool(m.proxySummaryTool(), m.handleProxySummary)
	m.server.AddTool(m.proxyListTool(), m.handleProxyList)
	m.server.AddTool(m.proxyGetTool(), m.handleProxyGet)
	m.server.AddTool(m.proxyRuleListTool(), m.handleProxyRuleList)
	m.server.AddTool(m.proxyRuleAddTool(), m.handleProxyRuleAdd)
	m.server.AddTool(m.proxyRuleUpdateTool(), m.handleProxyRuleUpdate)
	m.server.AddTool(m.proxyRuleDeleteTool(), m.handleProxyRuleDelete)
}

func (m *mcpServer) addReplayTools() {
	m.server.AddTool(m.replaySendTool(), m.handleReplaySend)
	m.server.AddTool(m.replayGetTool(), m.handleReplayGet)
	m.server.AddTool(m.requestSendTool(), m.handleRequestSend)
}

func (m *mcpServer) addOastTools() {
	m.server.AddTool(m.oastCreateTool(), m.handleOastCreate)
	m.server.AddTool(m.oastPollTool(), m.handleOastPoll)
	m.server.AddTool(m.oastGetTool(), m.handleOastGet)
	m.server.AddTool(m.oastListTool(), m.handleOastList)
	m.server.AddTool(m.oastDeleteTool(), m.handleOastDelete)
}

func (m *mcpServer) addEncodeTools() {
	m.server.AddTool(m.encodeURLTool(), m.handleEncodeURL)
	m.server.AddTool(m.encodeBase64Tool(), m.handleEncodeBase64)
	m.server.AddTool(m.encodeHTMLTool(), m.handleEncodeHTML)
}

func (m *mcpServer) addCrawlTools() {
	m.server.AddTool(m.crawlCreateTool(), m.handleCrawlCreate)
	m.server.AddTool(m.crawlSeedTool(), m.handleCrawlSeed)
	m.server.AddTool(m.crawlStatusTool(), m.handleCrawlStatus)
	m.server.AddTool(m.crawlSummaryTool(), m.handleCrawlSummary)
	m.server.AddTool(m.crawlListTool(), m.handleCrawlList)
	m.server.AddTool(m.crawlSessionsTool(), m.handleCrawlSessions)
	m.server.AddTool(m.crawlStopTool(), m.handleCrawlStop)
	m.server.AddTool(m.crawlGetTool(), m.handleCrawlGet)
}

const workflowNotInitializedError = "call workflow first with the relevant task, use 'explore' if there is no better fit"

// requireWorkflow returns an error result if workflow is required but not initialized, nil otherwise.
// Only enforced when workflowMode is empty (default behavior).
func (m *mcpServer) requireWorkflow() *mcp.CallToolResult {
	if m.workflowMode == "" && !m.workflowInitialized.Load() {
		return errorResult(workflowNotInitializedError)
	}
	return nil
}

func (m *mcpServer) workflowTool() mcp.Tool {
	return mcp.NewTool("workflow",
		mcp.WithDescription(`Initialize sectool workflow - MUST be called before using other tools.

Select the task that best matches your objective:
- test-report: Validating a specific vulnerability report
- explore: Security testing and vulnerability discovery (default if unsure)

Returns necessary instructions on tool use and user interaction  strategies.`),
		mcp.WithString("task", mcp.Required(), mcp.Description("Workflow type: 'test-report' for validating vulnerability reports, 'explore' for security testing/discovery")),
	)
}

func (m *mcpServer) handleWorkflow(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	task := req.GetString("task", WorkflowModeExplore)

	var content string
	switch task {
	case WorkflowModeExplore:
		content = workflowExploreContent
	case WorkflowModeTestReport:
		content = workflowTestReportContent
	case WorkflowModeCLI:
		m.workflowInitialized.Store(true)
		return mcp.NewToolResultText("Tools enabled for CLI usage"), nil
	default:
		return errorResult("invalid task: use 'explore' or 'test-report'"), nil
	}

	m.workflowInitialized.Store(true)
	log.Printf("mcp/workflow: initialized with task=%s", task)

	return mcp.NewToolResultText(content), nil
}

var workflowExploreContent = `# Security Testing Workflow

Collaborate with the user to probe and discover security vulnerabilities.

## Collaboration Model

**Your role:** Analyze traffic, identify vulnerabilities, craft/replay requests, monitor OAST interactions, suggest attack strategies.

**User's role:** Browser navigation, authentication, trigger UI actions, provide application context, answer questions to help.

**Key principle:** Work collaboratively - don't assume, ask when uncertain about scope, behavior.

## Common Workflow

1. User provides testing context/scope - ask for clarification if needed
2. User generates traffic via browser; you monitor with proxy_summary then proxy_list
3. Identify interesting endpoints and potential vulnerabilities
4. Test hypotheses using sectool (often replay_send with modifications)
5. Report findings, discuss next steps, explore multiple angles in parallel

## Optional: Expanding Coverage with Crawling

Crawling can discover hidden endpoints, forms, and linked resources beyond manual exploration. Confirm with the user before starting a crawl.

When approved:
- crawl_create with seed_flows from proxy_list to inherit authentication
- crawl_status to monitor progress; crawl_summary for aggregated results
- crawl_list with type="forms" to find input vectors for testing
- Crawler flows work with replay_send and crawl_get just like proxy flows with proxy_get
`

var workflowTestReportContent = `# Vulnerability Validation Workflow

Collaborate with the user to validate a reported security vulnerability.

## Collaboration Model

**Your role:** Be helpful in verifying the claimed behavior by analyzing the proxy traffic, craft and replay requests, monitor OAST interactions, and suggest additional attack strategies to verify impact.

**User's role:** Browser navigation, authentication, trigger UI actions, provide application context, answer questions to help.

**Key principle:** Work collaboratively - don't assume, ask when uncertain about scope, reproduction steps, behavior.

## Common Workflow

1. User provides vulnerability report - understand claimed issue and impact
2. Build verification plan together: prerequisites, step-by-step actions, expected behavior
3. User performs browser actions; you analyze captured traffic
4. Utilize sectool commands including replaying and modifying requests to assist in verifying the issue
5. Assess: Is it exploitable as described? Mitigating controls? Related variants?
6. Discuss results and additional testing permutations that should be considered
`

func (m *mcpServer) proxySummaryTool() mcp.Tool {
	return mcp.NewTool("proxy_summary",
		mcp.WithDescription(`Get aggregated summary of proxy history.

Returns traffic grouped by (host, path, method, status), sorted by count descending.
Use this first to understand available traffic before using proxy_list with specific filters.

Filters narrow the summary scope: host/path/exclude_host/exclude_path use glob (*, ?).
method/status are comma-separated. contains searches URL+headers; contains_body searches bodies.`),
		mcp.WithString("host", mcp.Description("Filter by host (glob pattern, e.g., '*.example.com')")),
		mcp.WithString("path", mcp.Description("Filter by path (glob pattern, e.g., '/api/*')")),
		mcp.WithString("method", mcp.Description("Filter by HTTP method(s), comma-separated (e.g., 'GET,POST')")),
		mcp.WithString("status", mcp.Description("Filter by status code(s) or ranges (e.g., '200,302' or '2XX,4XX')")),
		mcp.WithString("contains", mcp.Description("Filter by text in URL or headers (does not search body)")),
		mcp.WithString("contains_body", mcp.Description("Filter by text in request or response body")),
		mcp.WithString("exclude_host", mcp.Description("Exclude hosts matching glob pattern")),
		mcp.WithString("exclude_path", mcp.Description("Exclude paths matching glob pattern")),
	)
}

func (m *mcpServer) proxyListTool() mcp.Tool {
	return mcp.NewTool("proxy_list",
		mcp.WithDescription(`Query proxy history for individual flows.

Returns individual flows with flow_id for use with proxy_get or replay_send.
At least one filter or limit is REQUIRED. Use proxy_summary first to understand available traffic.

Filters: host/path/exclude_host/exclude_path use glob (*, ?). method/status are comma-separated (status supports ranges like 2XX).
Search: contains searches URL+headers; contains_body searches bodies.
Incremental: since=flow_id or "last" for new entries only.
Pagination: use limit and offset after filtering.`),
		mcp.WithString("host", mcp.Description("Filter by host (glob pattern, e.g., '*.example.com')")),
		mcp.WithString("path", mcp.Description("Filter by path (glob pattern, e.g., '/api/*')")),
		mcp.WithString("method", mcp.Description("Filter by HTTP method(s), comma-separated (e.g., 'GET,POST')")),
		mcp.WithString("status", mcp.Description("Filter by status code(s) or ranges (e.g., '200,302' or '2XX,4XX')")),
		mcp.WithString("contains", mcp.Description("Filter by text in URL or headers (does not search body)")),
		mcp.WithString("contains_body", mcp.Description("Filter by text in request or response body")),
		mcp.WithString("since", mcp.Description("Only entries after this flow_id (exclusive), or 'last' to get entries added since your last proxy_list call (per-session cursor)")),
		mcp.WithString("exclude_host", mcp.Description("Exclude hosts matching glob pattern")),
		mcp.WithString("exclude_path", mcp.Description("Exclude paths matching glob pattern")),
		mcp.WithNumber("limit", mcp.Description("Max results to return")),
		mcp.WithNumber("offset", mcp.Description("Skip first N results (applied after filtering)")),
	)
}

func (m *mcpServer) proxyGetTool() mcp.Tool {
	return mcp.NewTool("proxy_get",
		mcp.WithDescription(`Get full request and response data for a proxy history entry.

Returns headers and body for both request and response. Binary bodies are returned as "<BINARY:N Bytes>" placeholder.
Use flow_id from proxy_list to identify the entry.`),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow ID from proxy_list")),
	)
}

func (m *mcpServer) proxyRuleListTool() mcp.Tool {
	return mcp.NewTool("proxy_rule_list",
		mcp.WithDescription("List proxy match/replace rules. Use type_filter to control which rules are returned."),
		mcp.WithString("type_filter", mcp.Description("Filter by rule type: 'http', 'websocket', or 'all' (default: 'all')")),
		mcp.WithNumber("limit", mcp.Description("Maximum number of rules to return")),
	)
}

func (m *mcpServer) proxyRuleAddTool() mcp.Tool {
	return mcp.NewTool("proxy_rule_add",
		mcp.WithDescription(`Add proxy match/replace rule. Persists across all traffic (vs replay_send for one-off edits).

Types:
  HTTP:      request_header (default), request_body, response_header, response_body
  WebSocket: ws:to-server, ws:to-client, ws:both

Regex: is_regex=true (Java regex). Labels must be unique.`),
		mcp.WithString("type", mcp.Required(), mcp.Description("Rule type: request_header, request_body, response_header, response_body, ws:to-server, ws:to-client, ws:both")),
		mcp.WithString("match", mcp.Description("Pattern to find")),
		mcp.WithString("replace", mcp.Description("Replacement text")),
		mcp.WithString("label", mcp.Description("Optional unique label (usable as rule_id)")),
		mcp.WithBoolean("is_regex", mcp.Description("Treat match as regex pattern (Java regex syntax)")),
	)
}

func (m *mcpServer) proxyRuleUpdateTool() mcp.Tool {
	return mcp.NewTool("proxy_rule_update",
		mcp.WithDescription(`Update a proxy match/replace rule by rule_id or label (searches HTTP+WS).

Requires at least match or replace. To rename label only, resend existing values with new label.`),
		mcp.WithString("rule_id", mcp.Required(), mcp.Description("Rule ID or label to update")),
		mcp.WithString("type", mcp.Required(), mcp.Description("Rule type: HTTP uses request_header/request_body/response_header/response_body; WebSocket uses ws:to-server/ws:to-client/ws:both")),
		mcp.WithString("match", mcp.Description("Pattern to match")),
		mcp.WithString("replace", mcp.Description("Replacement text")),
		mcp.WithString("label", mcp.Description("Optional new label (unique); omit to keep existing")),
		mcp.WithBoolean("is_regex", mcp.Description("Treat match as regex pattern (Java regex syntax)")),
	)
}

func (m *mcpServer) proxyRuleDeleteTool() mcp.Tool {
	return mcp.NewTool("proxy_rule_delete",
		mcp.WithDescription("Delete a proxy match/replace rule by rule_id or label (searches HTTP+WS)."),
		mcp.WithString("rule_id", mcp.Required(), mcp.Description("Rule ID or label to delete")),
	)
}

func (m *mcpServer) replaySendTool() mcp.Tool {
	return mcp.NewTool("replay_send",
		mcp.WithDescription(`Replay a proxied request (flow_id from proxy_list) with edits.

Returns: replay_id, status, headers, response_preview. Full body via replay_get.

Edits:
- target: scheme+host[:port] (e.g., 'https://staging.example.com')
- path/query: override path or entire query string
- set_query/remove_query: selective query param edits
- add_headers/remove_headers: header edits
- body: replace entire body
- set_json/remove_json: selective JSON edits; requires body to be valid JSON

JSON paths: dot notation (user.email, items[0].id).
set_json is an object: {"user.email": "x", "items[0].id": 5}
Types auto-parsed: null/true/false/numbers/{}/[], else string.
Processing: remove_* then set_*. Content-Length/Host auto-updated.
Validation: fix issues or use force=true for protocol testing.`),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow ID from proxy_list to use as base request")),
		mcp.WithString("body", mcp.Description("Request body content (replaces existing body)")),
		mcp.WithString("target", mcp.Description("Override destination (scheme+host[:port]); keeps original path/query")),
		mcp.WithArray("add_headers", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Headers to add/replace (format: 'Name: Value')")),
		mcp.WithArray("remove_headers", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Header names to remove")),
		mcp.WithString("path", mcp.Description("Override request path (include leading '/')")),
		mcp.WithString("query", mcp.Description("Override entire query string (no leading '?')")),
		mcp.WithArray("set_query", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Query params to set (format: 'name=value')")),
		mcp.WithArray("remove_query", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Query param names to remove")),
		mcp.WithObject("set_json", mcp.Description("JSON fields to set as object: {\"path\": value} (e.g., {\"user.email\": \"x\", \"items[0].id\": 5})")),
		mcp.WithArray("remove_json", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("JSON fields to remove (dot path: 'user.temp', 'items[2]')")),
		mcp.WithBoolean("follow_redirects", mcp.Description("Follow HTTP redirects (default: false)")),
		mcp.WithString("timeout", mcp.Description("Request timeout (e.g., '30s', '1m')")),
		mcp.WithBoolean("force", mcp.Description("Skip validation for protocol-level tests (smuggling, CRLF injection)")),
	)
}

func (m *mcpServer) replayGetTool() mcp.Tool {
	return mcp.NewTool("replay_get",
		mcp.WithDescription(`Retrieve full response from a previous replay_send.

Returns headers and body. Binary bodies are returned as "<BINARY:N Bytes>" placeholder.
Results are ephemeral and cleared on service restart.`),
		mcp.WithString("replay_id", mcp.Required(), mcp.Description("Replay ID from replay_send response")),
	)
}

func (m *mcpServer) requestSendTool() mcp.Tool {
	return mcp.NewTool("request_send",
		mcp.WithDescription(`Send a request from scratch (no captured flow required).

Use this when you need to send a request to a URL without first capturing it via proxy.
Returns: replay_id, status, headers, response_preview. Full body via replay_get.`),
		mcp.WithString("url", mcp.Required(), mcp.Description("Target URL (e.g., 'https://api.example.com/users')")),
		mcp.WithString("method", mcp.Description("HTTP method (default: GET)")),
		mcp.WithObject("headers", mcp.Description("Headers as object: {\"Name\": \"Value\"}")),
		mcp.WithString("body", mcp.Description("Request body content")),
		mcp.WithBoolean("follow_redirects", mcp.Description("Follow HTTP redirects (default: false)")),
		mcp.WithString("timeout", mcp.Description("Request timeout (e.g., '30s', '1m')")),
	)
}

func (m *mcpServer) oastCreateTool() mcp.Tool {
	return mcp.NewTool("oast_create",
		mcp.WithDescription(`Create OAST (Out-of-Band Application Security Testing) session.

Returns {oast_id, domain} for blind out-of-band detection (DNS/HTTP/SMTP).
Workflow: create -> inject domain in payload -> trigger target -> oast_poll -> oast_get for details.
Use cases: blind SSRF, blind XXE, DNS exfiltration, email verification bypass.`),
		mcp.WithString("label", mcp.Description("Optional unique label for this session")),
	)
}

func (m *mcpServer) oastPollTool() mcp.Tool {
	return mcp.NewTool("oast_poll",
		mcp.WithDescription(`Poll for OAST interaction events (DNS/HTTP/SMTP).

Options:
- Immediate: omit wait
- Long-poll: set wait (e.g., '30s', max 120s)
- Incremental: since=event_id or "last" for only new events

Response includes events (event_id) and optional dropped_count; use oast_get for full event details.`),
		mcp.WithString("oast_id", mcp.Required(), mcp.Description("OAST session ID, label, or domain")),
		mcp.WithString("since", mcp.Description("Return events after this event_id, or 'last' to get events received since your last oast_poll call (per-session cursor)")),
		mcp.WithString("wait", mcp.Description("Long-poll duration (e.g., '30s', max 120s)")),
		mcp.WithNumber("limit", mcp.Description("Maximum number of events to return")),
	)
}

func (m *mcpServer) oastGetTool() mcp.Tool {
	return mcp.NewTool("oast_get",
		mcp.WithDescription("Get full OAST event data: HTTP request/response, DNS query type/answer, SMTP headers/body."),
		mcp.WithString("oast_id", mcp.Required(), mcp.Description("OAST session ID, label, or domain")),
		mcp.WithString("event_id", mcp.Required(), mcp.Description("Event ID from oast_poll")),
	)
}

func (m *mcpServer) oastListTool() mcp.Tool {
	return mcp.NewTool("oast_list",
		mcp.WithDescription("List active OAST sessions."),
		mcp.WithNumber("limit", mcp.Description("Maximum number of sessions to return")),
	)
}

func (m *mcpServer) oastDeleteTool() mcp.Tool {
	return mcp.NewTool("oast_delete",
		mcp.WithDescription("Delete an OAST session and stop monitoring its domain."),
		mcp.WithString("oast_id", mcp.Required(), mcp.Description("OAST session ID, label, or domain")),
	)
}

func (m *mcpServer) encodeURLTool() mcp.Tool {
	return mcp.NewTool("encode_url",
		mcp.WithDescription("URL encode or decode a string."),
		mcp.WithString("input", mcp.Required(), mcp.Description("String to encode or decode")),
		mcp.WithBoolean("decode", mcp.Description("Decode instead of encode")),
	)
}

func (m *mcpServer) encodeBase64Tool() mcp.Tool {
	return mcp.NewTool("encode_base64",
		mcp.WithDescription("Base64 encode or decode a string."),
		mcp.WithString("input", mcp.Required(), mcp.Description("String to encode or decode")),
		mcp.WithBoolean("decode", mcp.Description("Decode instead of encode")),
	)
}

func (m *mcpServer) encodeHTMLTool() mcp.Tool {
	return mcp.NewTool("encode_html",
		mcp.WithDescription("HTML entity encode or decode a string."),
		mcp.WithString("input", mcp.Required(), mcp.Description("String to encode or decode")),
		mcp.WithBoolean("decode", mcp.Description("Decode instead of encode")),
	)
}

func (m *mcpServer) handleProxySummary(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	log.Printf("proxy/summary: fetching aggregated summary")

	listReq := &ProxyListRequest{
		Host:         req.GetString("host", ""),
		Path:         req.GetString("path", ""),
		Method:       req.GetString("method", ""),
		Status:       req.GetString("status", ""),
		Contains:     req.GetString("contains", ""),
		ContainsBody: req.GetString("contains_body", ""),
		ExcludeHost:  req.GetString("exclude_host", ""),
		ExcludePath:  req.GetString("exclude_path", ""),
	}

	allEntries, err := m.service.fetchAllProxyEntries(ctx)
	if err != nil {
		return errorResult("failed to fetch proxy summary: " + err.Error()), nil
	}

	filtered := applyProxyFilters(allEntries, listReq, m.service.flowStore, m.service.proxyLastOffset.Load())

	agg := aggregateByTuple(filtered, func(e flowEntry) (string, string, string, int) {
		return e.host, e.path, e.method, e.status
	})
	log.Printf("proxy/summary: returning %d aggregates from %d entries", len(agg), len(filtered))

	return jsonResult(&ProxySummaryResponse{Aggregates: agg})
}

func (m *mcpServer) handleProxyList(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	listReq := &ProxyListRequest{
		Host:         req.GetString("host", ""),
		Path:         req.GetString("path", ""),
		Method:       req.GetString("method", ""),
		Status:       req.GetString("status", ""),
		Contains:     req.GetString("contains", ""),
		ContainsBody: req.GetString("contains_body", ""),
		Since:        req.GetString("since", ""),
		ExcludeHost:  req.GetString("exclude_host", ""),
		ExcludePath:  req.GetString("exclude_path", ""),
		Limit:        req.GetInt("limit", 0),
		Offset:       req.GetInt("offset", 0),
	}

	if !listReq.HasFilters() {
		return errorResult("at least one filter or limit is required; use proxy_summary first to see available traffic"), nil
	}

	log.Printf("proxy/list: fetching with filters (host=%q path=%q method=%q status=%q since=%q offset=%d)",
		listReq.Host, listReq.Path, listReq.Method, listReq.Status, listReq.Since, listReq.Offset)

	allEntries, err := m.service.fetchAllProxyEntries(ctx)
	if err != nil {
		return errorResult("failed to fetch proxy history: " + err.Error()), nil
	}

	lastOffset := m.service.proxyLastOffset.Load()
	filtered := applyProxyFilters(allEntries, listReq, m.service.flowStore, lastOffset)

	// Apply offset after filtering
	if listReq.Offset > 0 && listReq.Offset < len(filtered) {
		filtered = filtered[listReq.Offset:]
	} else if listReq.Offset >= len(filtered) {
		filtered = nil
	}

	// Apply limit after offset
	if listReq.Limit > 0 && len(filtered) > listReq.Limit {
		filtered = filtered[:listReq.Limit]
	}

	var maxOffset uint32
	for _, e := range filtered {
		if e.offset > maxOffset {
			maxOffset = e.offset
		}
	}

	flows := make([]FlowSummary, 0, len(filtered))
	for _, entry := range filtered {
		headerLines := extractHeaderLines(entry.request)
		_, reqBody := splitHeadersBody([]byte(entry.request))
		hash := store.ComputeFlowHashSimple(entry.method, entry.host, entry.path, headerLines, reqBody)
		flowID := m.service.flowStore.Register(entry.offset, hash)

		scheme, port, _ := inferSchemeAndPort(entry.host)

		flows = append(flows, FlowSummary{
			FlowID:         flowID,
			Method:         entry.method,
			Scheme:         scheme,
			Host:           entry.host,
			Port:           port,
			Path:           truncateString(entry.path, maxPathLength),
			Status:         entry.status,
			ResponseLength: entry.respLen,
		})
	}
	log.Printf("proxy/list: returning %d flows (fetched %d, filtered %d)", len(flows), len(allEntries), len(allEntries)-len(filtered))

	if maxOffset > lastOffset {
		m.service.proxyLastOffset.Store(maxOffset)
	}

	return jsonResult(&ProxyListResponse{Flows: flows})
}

func (m *mcpServer) handleProxyGet(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	flowID := req.GetString("flow_id", "")
	if flowID == "" {
		return errorResult("flow_id is required"), nil
	}

	// Hidden parameter for CLI: returns full base64-encoded bodies instead of previews
	fullBody := req.GetBool("full_body", false)

	entry, ok := m.service.flowStore.Lookup(flowID)
	if !ok {
		return errorResult("flow_id not found: run proxy_list to see available flows"), nil
	}

	proxyEntries, err := m.service.httpBackend.GetProxyHistory(ctx, 1, entry.Offset)
	if err != nil {
		return errorResult("failed to fetch flow: " + err.Error()), nil
	}
	if len(proxyEntries) == 0 {
		return errorResult("flow not found in proxy history"), nil
	}

	rawReq := []byte(proxyEntries[0].Request)
	rawResp := []byte(proxyEntries[0].Response)

	method, host, path := extractRequestMeta(proxyEntries[0].Request)
	reqHeaders, reqBody := splitHeadersBody(rawReq)
	respHeaders, respBody := splitHeadersBody(rawResp)
	respCode, respStatusLine := parseResponseStatus(respHeaders)

	// Extract version from request line
	var version string
	if idx := strings.Index(proxyEntries[0].Request, "\r\n"); idx > 0 {
		if parts := strings.SplitN(proxyEntries[0].Request[:idx], " ", 3); len(parts) >= 3 {
			version = parts[2]
		}
	}

	scheme, _, _ := inferSchemeAndPort(host)
	fullURL := scheme + "://" + host + path

	log.Printf("mcp/proxy_get: flow=%s method=%s url=%s", flowID, method, fullURL)

	// Format bodies based on full_body flag
	var reqBodyStr, respBodyStr string
	if fullBody {
		reqBodyStr = base64.StdEncoding.EncodeToString(reqBody)
		respBodyStr = base64.StdEncoding.EncodeToString(respBody)
	} else {
		reqBodyStr = previewBody(reqBody, fullBodyMaxSize)
		respBodyStr = previewBody(respBody, fullBodyMaxSize)
	}

	return jsonResult(ProxyGetResponse{
		FlowID:            flowID,
		Method:            method,
		URL:               fullURL,
		ReqHeaders:        string(reqHeaders),
		ReqHeadersParsed:  parseHeadersToMap(string(reqHeaders)),
		ReqLine:           &RequestLine{Path: path, Version: version},
		ReqBody:           reqBodyStr,
		ReqSize:           len(reqBody),
		Status:            respCode,
		StatusLine:        respStatusLine,
		RespHeaders:       string(respHeaders),
		RespHeadersParsed: parseHeadersToMap(string(respHeaders)),
		RespBody:          respBodyStr,
		RespSize:          len(respBody),
	})
}

func (m *mcpServer) handleProxyRuleList(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	typeFilter := req.GetString("type_filter", "all")
	limit := req.GetInt("limit", 0)

	var rules []RuleEntry
	switch typeFilter {
	case "http":
		httpRules, err := m.service.httpBackend.ListRules(ctx, false)
		if err != nil {
			return errorResult("failed to list HTTP rules: " + err.Error()), nil
		}
		rules = httpRules
	case "websocket":
		wsRules, err := m.service.httpBackend.ListRules(ctx, true)
		if err != nil {
			return errorResult("failed to list WebSocket rules: " + err.Error()), nil
		}
		rules = wsRules
	case "all", "":
		httpRules, err := m.service.httpBackend.ListRules(ctx, false)
		if err != nil {
			return errorResult("failed to list HTTP rules: " + err.Error()), nil
		}
		wsRules, err := m.service.httpBackend.ListRules(ctx, true)
		if err != nil {
			return errorResult("failed to list WebSocket rules: " + err.Error()), nil
		}
		rules = append(httpRules, wsRules...)
	default:
		return errorResult("invalid type_filter: must be 'http', 'websocket', or 'all'"), nil
	}

	if limit > 0 && len(rules) > limit {
		rules = rules[:limit]
	}

	log.Printf("mcp/proxy_rule_list: returning %d rules (filter=%s)", len(rules), typeFilter)
	return jsonResult(RuleListResponse{Rules: rules})
}

func (m *mcpServer) handleProxyRuleAdd(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	ruleType := req.GetString("type", "")
	if ruleType == "" {
		return errorResult("type is required"), nil
	}
	if err := validateRuleTypeAny(ruleType); err != nil {
		return errorResult(err.Error()), nil
	}

	match := req.GetString("match", "")
	replace := req.GetString("replace", "")
	if match == "" && replace == "" {
		return errorResult("match or replace is required"), nil
	}
	label := req.GetString("label", "")

	log.Printf("mcp/proxy_rule_add: type=%s label=%q", ruleType, label)

	isRegex := req.GetBool("is_regex", false)
	rule, err := m.service.httpBackend.AddRule(ctx, ProxyRuleInput{
		Label:   label,
		Type:    ruleType,
		IsRegex: &isRegex,
		Match:   match,
		Replace: replace,
	})
	if err != nil {
		if errors.Is(err, ErrLabelExists) {
			return errorResult("label already exists: " + err.Error()), nil
		}
		return errorResult("failed to add rule: " + err.Error()), nil
	}

	log.Printf("mcp/proxy_rule_add: created rule %s", rule.RuleID)
	return jsonResult(rule)
}

func (m *mcpServer) handleProxyRuleUpdate(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	ruleID := req.GetString("rule_id", "")
	if ruleID == "" {
		return errorResult("rule_id is required"), nil
	}

	ruleType := req.GetString("type", "")
	if ruleType == "" {
		return errorResult("type is required"), nil
	}
	if err := validateRuleTypeAny(ruleType); err != nil {
		return errorResult(err.Error()), nil
	}

	match := req.GetString("match", "")
	replace := req.GetString("replace", "")
	if match == "" && replace == "" {
		return errorResult("match or replace is required"), nil
	}

	// Only set IsRegex if explicitly provided in request
	var isRegex *bool
	if args := req.GetArguments(); args != nil {
		if _, ok := args["is_regex"]; ok {
			v := req.GetBool("is_regex", false)
			isRegex = &v
		}
	}

	rule, err := m.service.httpBackend.UpdateRule(ctx, ruleID, ProxyRuleInput{
		Label:   req.GetString("label", ""),
		Type:    ruleType,
		IsRegex: isRegex,
		Match:   match,
		Replace: replace,
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("rule not found"), nil
		}
		if errors.Is(err, ErrLabelExists) {
			return errorResult("label already exists: " + err.Error()), nil
		}
		return errorResult("failed to update rule: " + err.Error()), nil
	}

	log.Printf("mcp/proxy_rule_update: updated rule %s", rule.RuleID)
	return jsonResult(rule)
}

func (m *mcpServer) handleProxyRuleDelete(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	ruleID := req.GetString("rule_id", "")
	if ruleID == "" {
		return errorResult("rule_id is required"), nil
	}

	if err := m.service.httpBackend.DeleteRule(ctx, ruleID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("rule not found"), nil
		}
		return errorResult("failed to delete rule: " + err.Error()), nil
	}

	log.Printf("mcp/proxy_rule_delete: deleted rule %s", ruleID)
	return jsonResult(RuleDeleteResponse{})
}

func (m *mcpServer) handleReplaySend(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	flowID := req.GetString("flow_id", "")
	if flowID == "" {
		return errorResult("flow_id is required"), nil
	}

	// Try proxy flowStore first, then crawler backend
	var rawRequest []byte
	if entry, ok := m.service.flowStore.Lookup(flowID); ok {
		proxyEntries, err := m.service.httpBackend.GetProxyHistory(ctx, 1, entry.Offset)
		if err != nil {
			return errorResult("failed to fetch flow: " + err.Error()), nil
		}
		if len(proxyEntries) == 0 {
			return errorResult("flow not found in proxy history"), nil
		}
		rawRequest = []byte(proxyEntries[0].Request)
	} else if flow, err := m.service.crawlerBackend.GetFlow(ctx, flowID); err == nil && flow != nil {
		rawRequest = flow.Request
	} else {
		return errorResult("flow_id not found: run proxy_list or crawl_list to see available flows"), nil
	}

	rawRequest = modifyRequestLine(rawRequest, &PathQueryOpts{
		Path:        req.GetString("path", ""),
		Query:       req.GetString("query", ""),
		SetQuery:    req.GetStringSlice("set_query", nil),
		RemoveQuery: req.GetStringSlice("remove_query", nil),
	})

	headers, reqBody := splitHeadersBody(rawRequest)

	sendReq := &ReplaySendRequest{
		AddHeaders:    req.GetStringSlice("add_headers", nil),
		RemoveHeaders: req.GetStringSlice("remove_headers", nil),
		Target:        req.GetString("target", ""),
	}
	headers = applyHeaderModifications(headers, sendReq)
	headers = setHeaderIfMissing(headers, "User-Agent", config.UserAgent())

	if body := req.GetString("body", ""); body != "" {
		reqBody = []byte(body)
	}

	// Get set_json as a map (MCP format: {"path": value})
	var setJSON map[string]interface{}
	if args := req.GetArguments(); args != nil {
		if setJSONRaw, ok := args["set_json"]; ok && setJSONRaw != nil {
			if setJSONMap, ok := setJSONRaw.(map[string]interface{}); ok {
				setJSON = setJSONMap
			}
		}
	}
	removeJSON := req.GetStringSlice("remove_json", nil)
	if len(setJSON) > 0 || len(removeJSON) > 0 {
		modifiedBody, err := modifyJSONBodyMap(reqBody, setJSON, removeJSON)
		if err != nil {
			return errorResult("JSON body modification failed: " + err.Error()), nil
		}
		reqBody = modifiedBody
	}

	headers = updateContentLength(headers, len(reqBody))
	rawRequest = append(headers, reqBody...)

	if !req.GetBool("force", false) {
		issues := validateRequest(rawRequest)
		if slices.ContainsFunc(issues, func(i validationIssue) bool { return i.Severity == severityError }) {
			return errorResult("validation failed:\n" + formatIssues(issues)), nil
		}
	}

	host, port, usesHTTPS := parseTarget(rawRequest, req.GetString("target", ""))

	replayID := ids.Generate(ids.DefaultLength)

	scheme := schemeHTTP
	if usesHTTPS {
		scheme = schemeHTTPS
	}
	log.Printf("mcp/replay_send: %s sending to %s://%s:%d (flow=%s)", replayID, scheme, host, port, flowID)

	var timeout time.Duration
	if timeoutStr := req.GetString("timeout", ""); timeoutStr != "" {
		parsed, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return errorResult("invalid timeout duration: " + err.Error()), nil
		}
		timeout = parsed
	}

	sendInput := SendRequestInput{
		RawRequest: rawRequest,
		Target: Target{
			Hostname:  host,
			Port:      port,
			UsesHTTPS: usesHTTPS,
		},
		FollowRedirects: req.GetBool("follow_redirects", false),
		Timeout:         timeout,
	}

	result, err := m.service.httpBackend.SendRequest(ctx, "sectool-"+replayID, sendInput)
	if err != nil {
		return errorResult("request failed: " + err.Error()), nil
	}

	respHeaders := result.Headers
	respBody := result.Body
	respCode, respStatusLine := parseResponseStatus(respHeaders)
	log.Printf("mcp/replay_send: %s completed in %v (status=%d, size=%d)", replayID, result.Duration, respCode, len(respBody))

	m.service.requestStore.Store(replayID, &store.RequestEntry{
		Headers:  respHeaders,
		Body:     respBody,
		Duration: result.Duration,
	})

	return jsonResult(ReplaySendResponse{
		ReplayID: replayID,
		Duration: result.Duration.String(),
		ResponseDetails: ResponseDetails{
			Status:      respCode,
			StatusLine:  respStatusLine,
			RespHeaders: string(respHeaders),
			RespSize:    len(respBody),
			RespPreview: previewBody(respBody, responsePreviewSize),
		},
	})
}

func (m *mcpServer) handleReplayGet(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	replayID := req.GetString("replay_id", "")
	if replayID == "" {
		return errorResult("replay_id is required"), nil
	}

	// Hidden parameter for CLI: returns full base64-encoded body instead of preview
	fullBody := req.GetBool("full_body", false)

	log.Printf("mcp/replay_get: retrieving %s", replayID)
	result, ok := m.service.requestStore.Get(replayID)
	if !ok {
		return errorResult("replay not found: replay results are ephemeral and cleared on service restart"), nil
	}

	respCode, respStatusLine := parseResponseStatus(result.Headers)

	// Format body based on full_body flag
	var respBodyStr string
	if fullBody {
		respBodyStr = base64.StdEncoding.EncodeToString(result.Body)
	} else {
		respBodyStr = previewBody(result.Body, fullBodyMaxSize)
	}

	return jsonResult(ReplayGetResponse{
		ReplayID:          replayID,
		Duration:          result.Duration.String(),
		Status:            respCode,
		StatusLine:        respStatusLine,
		RespHeaders:       string(result.Headers),
		RespHeadersParsed: parseHeadersToMap(string(result.Headers)),
		RespBody:          respBodyStr,
		RespSize:          len(result.Body),
	})
}

func (m *mcpServer) handleRequestSend(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	urlStr := req.GetString("url", "")
	if urlStr == "" {
		return errorResult("url is required"), nil
	}

	method := req.GetString("method", "GET")

	// Parse headers from object
	var headers map[string]string
	if args := req.GetArguments(); args != nil {
		if headersRaw, ok := args["headers"]; ok && headersRaw != nil {
			if headersMap, ok := headersRaw.(map[string]interface{}); ok {
				headers = make(map[string]string)
				for k, v := range headersMap {
					if vs, ok := v.(string); ok {
						headers[k] = vs
					}
				}
			}
		}
	}

	body := []byte(req.GetString("body", ""))

	parsedURL, err := parseURLWithDefaultHTTPS(urlStr)
	if err != nil {
		return errorResult("invalid URL: " + err.Error()), nil
	}

	rawRequest := buildRawRequest(method, parsedURL, headers, body)
	if rawRequest == nil {
		return errorResult("failed to build request: invalid method or URL"), nil
	}
	target := targetFromURL(parsedURL)
	replayID := ids.Generate(ids.DefaultLength)

	log.Printf("mcp/request_send: %s sending to %s", replayID, parsedURL)

	var timeout time.Duration
	if timeoutStr := req.GetString("timeout", ""); timeoutStr != "" {
		parsed, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return errorResult("invalid timeout duration: " + err.Error()), nil
		}
		timeout = parsed
	}

	sendInput := SendRequestInput{
		RawRequest:      rawRequest,
		Target:          target,
		FollowRedirects: req.GetBool("follow_redirects", false),
		Timeout:         timeout,
	}

	result, err := m.service.httpBackend.SendRequest(ctx, "sectool-"+replayID, sendInput)
	if err != nil {
		return errorResult("request failed: " + err.Error()), nil
	}

	respCode, respStatusLine := parseResponseStatus(result.Headers)
	log.Printf("mcp/request_send: %s completed in %v (status=%d, size=%d)", replayID, result.Duration, respCode, len(result.Body))

	m.service.requestStore.Store(replayID, &store.RequestEntry{
		Headers:  result.Headers,
		Body:     result.Body,
		Duration: result.Duration,
	})

	return jsonResult(ReplaySendResponse{
		ReplayID: replayID,
		Duration: result.Duration.String(),
		ResponseDetails: ResponseDetails{
			Status:      respCode,
			StatusLine:  respStatusLine,
			RespHeaders: string(result.Headers),
			RespSize:    len(result.Body),
			RespPreview: previewBody(result.Body, responsePreviewSize),
		},
	})
}

func (m *mcpServer) handleOastCreate(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	label := req.GetString("label", "")

	sess, err := m.service.oastBackend.CreateSession(ctx, label)
	if err != nil {
		return errorResult("failed to create OAST session: " + err.Error()), nil
	}

	log.Printf("mcp/oast_create: created session %s with domain %s (label=%q)", sess.ID, sess.Domain, sess.Label)
	return jsonResult(OastCreateResponse{
		OastID: sess.ID,
		Domain: sess.Domain,
		Label:  sess.Label,
	})
}

func (m *mcpServer) handleOastPoll(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	oastID := req.GetString("oast_id", "")
	if oastID == "" {
		return errorResult("oast_id is required"), nil
	}

	var wait time.Duration
	if waitStr := req.GetString("wait", ""); waitStr != "" {
		parsed, err := time.ParseDuration(waitStr)
		if err != nil {
			return errorResult("invalid wait duration: " + err.Error()), nil
		}
		if parsed > 120*time.Second {
			parsed = 120 * time.Second
		}
		wait = parsed
	}

	since := req.GetString("since", "")
	limit := req.GetInt("limit", 0)

	log.Printf("mcp/oast_poll: polling session %s (wait=%v since=%q limit=%d)", oastID, wait, since, limit)

	result, err := m.service.oastBackend.PollSession(ctx, oastID, since, wait, limit)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("session not found"), nil
		}
		return errorResult("failed to poll session: " + err.Error()), nil
	}

	events := make([]OastEvent, len(result.Events))
	for i, e := range result.Events {
		events[i] = OastEvent{
			EventID:   e.ID,
			Time:      e.Time.UTC().Format(time.RFC3339),
			Type:      e.Type,
			SourceIP:  e.SourceIP,
			Subdomain: e.Subdomain,
			Details:   e.Details,
		}
	}

	log.Printf("mcp/oast_poll: session %s returned %d events", oastID, len(events))
	return jsonResult(OastPollResponse{
		Events:       events,
		DroppedCount: result.DroppedCount,
	})
}

func (m *mcpServer) handleOastGet(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	oastID := req.GetString("oast_id", "")
	if oastID == "" {
		return errorResult("oast_id is required"), nil
	}
	eventID := req.GetString("event_id", "")
	if eventID == "" {
		return errorResult("event_id is required"), nil
	}

	log.Printf("mcp/oast_get: getting event %s from session %s", eventID, oastID)

	event, err := m.service.oastBackend.GetEvent(ctx, oastID, eventID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("session or event not found"), nil
		}
		return errorResult("failed to get event: " + err.Error()), nil
	}

	return jsonResult(OastGetResponse{
		EventID:   event.ID,
		Time:      event.Time.UTC().Format(time.RFC3339),
		Type:      event.Type,
		SourceIP:  event.SourceIP,
		Subdomain: event.Subdomain,
		Details:   event.Details,
	})
}

func (m *mcpServer) handleOastList(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	limit := req.GetInt("limit", 0)

	sessions, err := m.service.oastBackend.ListSessions(ctx)
	if err != nil {
		return errorResult("failed to list OAST sessions: " + err.Error()), nil
	}

	// Sort by creation time descending (most recent first)
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].CreatedAt.After(sessions[j].CreatedAt)
	})

	if limit > 0 && len(sessions) > limit {
		sessions = sessions[:limit]
	}

	apiSessions := make([]OastSession, len(sessions))
	for i, sess := range sessions {
		apiSessions[i] = OastSession{
			OastID:    sess.ID,
			Domain:    sess.Domain,
			Label:     sess.Label,
			CreatedAt: sess.CreatedAt.UTC().Format(time.RFC3339),
		}
	}

	log.Printf("oast/list: returning %d active sessions", len(apiSessions))
	return jsonResult(&OastListResponse{Sessions: apiSessions})
}

func (m *mcpServer) handleOastDelete(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	oastID := req.GetString("oast_id", "")
	if oastID == "" {
		return errorResult("oast_id is required"), nil
	}

	log.Printf("mcp/oast_delete: deleting session %s", oastID)

	if err := m.service.oastBackend.DeleteSession(ctx, oastID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("session not found"), nil
		}
		return errorResult("failed to delete session: " + err.Error()), nil
	}

	return jsonResult(OastDeleteResponse{})
}

func (m *mcpServer) handleEncodeURL(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := req.GetString("input", "")
	if input == "" {
		return errorResult("input is required"), nil
	}

	decode := req.GetBool("decode", false)

	var result string
	if decode {
		decoded, err := url.QueryUnescape(input)
		if err != nil {
			return errorResult("URL decode error: " + err.Error()), nil
		}
		result = decoded
	} else {
		result = url.QueryEscape(input)
	}

	return mcp.NewToolResultText(result), nil
}

func (m *mcpServer) handleEncodeBase64(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := req.GetString("input", "")
	if input == "" {
		return errorResult("input is required"), nil
	}

	decode := req.GetBool("decode", false)

	var result string
	if decode {
		decoded, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			return errorResult("base64 decode error: " + err.Error()), nil
		}
		result = string(decoded)
	} else {
		result = base64.StdEncoding.EncodeToString([]byte(input))
	}

	return mcp.NewToolResultText(result), nil
}

func (m *mcpServer) handleEncodeHTML(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := req.GetString("input", "")
	if input == "" {
		return errorResult("input is required"), nil
	}

	decode := req.GetBool("decode", false)

	var result string
	if decode {
		result = html.UnescapeString(input)
	} else {
		result = html.EscapeString(input)
	}

	return mcp.NewToolResultText(result), nil
}

func jsonResult(data interface{}) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return errorResult("failed to marshal response: " + err.Error()), nil
	}
	return mcp.NewToolResultText(string(b)), nil
}

func errorResult(message string) *mcp.CallToolResult {
	return mcp.NewToolResultError(message)
}

func (m *mcpServer) crawlCreateTool() mcp.Tool {
	return mcp.NewTool("crawl_create",
		mcp.WithDescription(`Start a new web crawl session.

Discovers URLs, forms, and content by following links from seed URLs.
Session runs asynchronously; use crawl_status to monitor progress.

Seeds can be:
- Direct URLs (seed_urls)
- Proxy flow IDs (seed_flows) - inherits headers from the captured request

The crawler automatically:
- Respects robots.txt (unless ignore_robots=true)
- Extracts forms for security testing
- Captures request/response pairs
- Groups similar paths in summary`),
		mcp.WithString("label", mcp.Description("Optional unique label for easy reference")),
		mcp.WithString("seed_urls", mcp.Description("Comma-separated list of URLs to start crawling from")),
		mcp.WithString("seed_flows", mcp.Description("Comma-separated list of proxy flow_ids to use as seeds")),
		mcp.WithString("domains", mcp.Description("Comma-separated list of additional domains to allow")),
		mcp.WithObject("headers", mcp.Description("Custom headers as object: {\"Name\": \"Value\"}")),
		mcp.WithNumber("max_depth", mcp.Description("Maximum crawl depth (0 = unlimited)")),
		mcp.WithNumber("max_requests", mcp.Description("Maximum total requests (0 = unlimited)")),
		mcp.WithString("delay", mcp.Description("Delay between requests (e.g., '200ms', '1s')")),
		mcp.WithNumber("parallelism", mcp.Description("Number of concurrent requests (default: 2)")),
		mcp.WithBoolean("include_subdomains", mcp.Description("Include subdomains of seed hosts (default: true)")),
		mcp.WithBoolean("submit_forms", mcp.Description("Automatically submit discovered forms (default: false)")),
		mcp.WithBoolean("ignore_robots", mcp.Description("Ignore robots.txt restrictions (default: false)")),
	)
}

func (m *mcpServer) handleCrawlCreate(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	// Parse seed URLs and flows
	var seeds []CrawlSeed
	if seedURLs := req.GetString("seed_urls", ""); seedURLs != "" {
		for _, u := range parseCommaSeparated(seedURLs) {
			seeds = append(seeds, CrawlSeed{URL: u})
		}
	}
	if seedFlows := req.GetString("seed_flows", ""); seedFlows != "" {
		for _, f := range parseCommaSeparated(seedFlows) {
			seeds = append(seeds, CrawlSeed{FlowID: f})
		}
	}

	// Parse domains
	var domains []string
	if domainsStr := req.GetString("domains", ""); domainsStr != "" {
		domains = parseCommaSeparated(domainsStr)
	}

	// Parse delay
	var delay time.Duration
	if delayStr := req.GetString("delay", ""); delayStr != "" {
		parsed, err := time.ParseDuration(delayStr)
		if err != nil {
			return errorResult("invalid delay: " + err.Error()), nil
		}
		delay = parsed
	}

	includeSubdomains := true
	if args := req.GetArguments(); args != nil {
		if v, ok := args["include_subdomains"]; ok {
			if b, ok := v.(bool); ok {
				includeSubdomains = b
			}
		}
	}

	opts := CrawlOptions{
		Label:             req.GetString("label", ""),
		Seeds:             seeds,
		ExplicitDomains:   domains,
		IncludeSubdomains: includeSubdomains,
		MaxDepth:          req.GetInt("max_depth", 0),
		MaxRequests:       req.GetInt("max_requests", 0),
		Delay:             delay,
		Parallelism:       req.GetInt("parallelism", 0),
		IgnoreRobotsTxt:   req.GetBool("ignore_robots", false),
		SubmitForms:       req.GetBool("submit_forms", false),
		// ExtractForms left nil to use config default
	}

	log.Printf("mcp/crawl_create: creating session (label=%q, seeds=%d, domains=%d)",
		opts.Label, len(seeds), len(domains))

	sess, err := m.service.crawlerBackend.CreateSession(ctx, opts)
	if err != nil {
		if errors.Is(err, ErrLabelExists) {
			return errorResult("label already exists: " + err.Error()), nil
		}
		return errorResult("failed to create crawl session: " + err.Error()), nil
	}

	return jsonResult(CrawlCreateResponse{
		SessionID: sess.ID,
		Label:     sess.Label,
		State:     sess.State,
		CreatedAt: sess.CreatedAt.UTC().Format(time.RFC3339),
	})
}

func (m *mcpServer) crawlSeedTool() mcp.Tool {
	return mcp.NewTool("crawl_seed",
		mcp.WithDescription(`Add seeds to an existing running crawl session.

Can only add seeds while session is running.`),
		mcp.WithString("session_id", mcp.Required(), mcp.Description("Session ID or label")),
		mcp.WithString("seed_urls", mcp.Description("Comma-separated list of URLs to add")),
		mcp.WithString("seed_flows", mcp.Description("Comma-separated list of proxy flow_ids to add")),
	)
}

func (m *mcpServer) handleCrawlSeed(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	sessionID := req.GetString("session_id", "")
	if sessionID == "" {
		return errorResult("session_id is required"), nil
	}

	var seeds []CrawlSeed
	if seedURLs := req.GetString("seed_urls", ""); seedURLs != "" {
		for _, u := range parseCommaSeparated(seedURLs) {
			seeds = append(seeds, CrawlSeed{URL: u})
		}
	}
	if seedFlows := req.GetString("seed_flows", ""); seedFlows != "" {
		for _, f := range parseCommaSeparated(seedFlows) {
			seeds = append(seeds, CrawlSeed{FlowID: f})
		}
	}

	if len(seeds) == 0 {
		return errorResult("at least one seed_url or seed_flow is required"), nil
	}

	log.Printf("mcp/crawl_seed: adding %d seeds to session %s", len(seeds), sessionID)

	if err := m.service.crawlerBackend.AddSeeds(ctx, sessionID, seeds); err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("session not found"), nil
		}
		return errorResult("failed to add seeds: " + err.Error()), nil
	}

	return jsonResult(CrawlSeedResponse{AddedCount: len(seeds)})
}

func (m *mcpServer) crawlStatusTool() mcp.Tool {
	return mcp.NewTool("crawl_status",
		mcp.WithDescription(`Get status of a crawl session.

Returns progress metrics including URLs visited, queued, errors, and forms discovered.`),
		mcp.WithString("session_id", mcp.Required(), mcp.Description("Session ID or label")),
	)
}

func (m *mcpServer) handleCrawlStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	sessionID := req.GetString("session_id", "")
	if sessionID == "" {
		return errorResult("session_id is required"), nil
	}

	log.Printf("mcp/crawl_status: getting status for session %s", sessionID)

	status, err := m.service.crawlerBackend.GetStatus(ctx, sessionID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("session not found"), nil
		}
		return errorResult("failed to get status: " + err.Error()), nil
	}

	return jsonResult(CrawlStatusResponse{
		State:           status.State,
		URLsQueued:      status.URLsQueued,
		URLsVisited:     status.URLsVisited,
		URLsErrored:     status.URLsErrored,
		FormsDiscovered: status.FormsDiscovered,
		Duration:        status.Duration.Round(time.Millisecond).String(),
		LastActivity:    status.LastActivity.UTC().Format(time.RFC3339),
		ErrorMessage:    status.ErrorMessage,
	})
}

func (m *mcpServer) crawlSummaryTool() mcp.Tool {
	return mcp.NewTool("crawl_summary",
		mcp.WithDescription(`Get aggregated summary of a crawl session.

Returns traffic grouped by (host, path, method, status) - same format as proxy_summary.
Path patterns replace numeric IDs and UUIDs with * for grouping.`),
		mcp.WithString("session_id", mcp.Required(), mcp.Description("Session ID or label")),
	)
}

func (m *mcpServer) handleCrawlSummary(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	sessionID := req.GetString("session_id", "")
	if sessionID == "" {
		return errorResult("session_id is required"), nil
	}

	log.Printf("mcp/crawl_summary: getting summary for session %s", sessionID)

	summary, err := m.service.crawlerBackend.GetSummary(ctx, sessionID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("session not found"), nil
		}
		return errorResult("failed to get summary: " + err.Error()), nil
	}

	return jsonResult(CrawlSummaryResponse{
		SessionID:  summary.SessionID,
		State:      summary.State,
		Duration:   summary.Duration.Round(time.Millisecond).String(),
		Aggregates: summary.Aggregates,
	})
}

func (m *mcpServer) crawlListTool() mcp.Tool {
	return mcp.NewTool("crawl_list",
		mcp.WithDescription(`List flows, forms, or errors from a crawl session.

Set type to control what is returned:
- "urls" (default): Returns crawled flows with flow_id for use with crawl_get
- "forms": Returns discovered forms with field information
- "errors": Returns errors encountered during crawling

Incremental: since=flow_id, timestamp (RFC3339 or date), or "last" for new entries only.`),
		mcp.WithString("session_id", mcp.Required(), mcp.Description("Session ID or label")),
		mcp.WithString("type", mcp.Description("What to list: 'urls' (default), 'forms', or 'errors'")),
		mcp.WithString("host", mcp.Description("Filter by host glob pattern (e.g., '*.example.com')")),
		mcp.WithString("path", mcp.Description("Filter by path glob pattern (e.g., '/api/*')")),
		mcp.WithString("method", mcp.Description("Filter by HTTP method (comma-separated)")),
		mcp.WithString("status", mcp.Description("Filter by status codes or ranges (e.g., '200,404' or '2XX,4XX')")),
		mcp.WithString("contains", mcp.Description("Search in URL and headers")),
		mcp.WithString("contains_body", mcp.Description("Search in request/response body")),
		mcp.WithString("exclude_host", mcp.Description("Exclude hosts matching glob pattern")),
		mcp.WithString("exclude_path", mcp.Description("Exclude paths matching glob pattern")),
		mcp.WithString("since", mcp.Description("Only entries after: flow_id, timestamp (2006-01-02T15:04:05Z or 2006-01-02), or 'last'")),
		mcp.WithNumber("limit", mcp.Description("Maximum number of results (default: 100)")),
		mcp.WithNumber("offset", mcp.Description("Skip first N results for pagination")),
	)
}

func (m *mcpServer) handleCrawlList(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	sessionID := req.GetString("session_id", "")
	if sessionID == "" {
		return errorResult("session_id is required"), nil
	}

	listType := req.GetString("type", "urls")
	limit := req.GetInt("limit", 100)

	log.Printf("mcp/crawl_list: listing %s for session %s (limit=%d)", listType, sessionID, limit)

	switch listType {
	case "forms":
		forms, err := m.service.crawlerBackend.ListForms(ctx, sessionID, limit)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return errorResult("session not found"), nil
			}
			return errorResult("failed to list forms: " + err.Error()), nil
		}

		return jsonResult(CrawlListResponse{Forms: formsToAPI(forms)})

	case "errors":
		errs, err := m.service.crawlerBackend.ListErrors(ctx, sessionID, limit)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return errorResult("session not found"), nil
			}
			return errorResult("failed to list errors: " + err.Error()), nil
		}

		var apiErrors []CrawlErrorAPI
		for _, e := range errs {
			apiErrors = append(apiErrors, CrawlErrorAPI{
				URL:    e.URL,
				Status: e.Status,
				Error:  e.Error,
			})
		}
		return jsonResult(CrawlListResponse{Errors: apiErrors})

	default: // "urls"
		opts := CrawlListOptions{
			Host:         req.GetString("host", ""),
			PathPattern:  req.GetString("path", ""),
			StatusCodes:  parseStatusFilter(req.GetString("status", "")),
			Methods:      parseCommaSeparated(req.GetString("method", "")),
			Contains:     req.GetString("contains", ""),
			ContainsBody: req.GetString("contains_body", ""),
			ExcludeHost:  req.GetString("exclude_host", ""),
			ExcludePath:  req.GetString("exclude_path", ""),
			Since:        req.GetString("since", ""),
			Limit:        limit,
			Offset:       req.GetInt("offset", 0),
		}

		flows, err := m.service.crawlerBackend.ListFlows(ctx, sessionID, opts)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return errorResult("session not found"), nil
			}
			return errorResult("failed to list flows: " + err.Error()), nil
		}

		var apiFlows []CrawlFlowAPI
		for _, f := range flows {
			apiFlows = append(apiFlows, CrawlFlowAPI{
				FlowID:         f.ID,
				Method:         f.Method,
				Host:           f.Host,
				Path:           f.Path,
				Status:         f.StatusCode,
				ResponseLength: f.ResponseLength,
				Duration:       f.Duration.Round(time.Millisecond).String(),
				FoundOn:        f.FoundOn,
			})
		}
		return jsonResult(CrawlListResponse{Flows: apiFlows})
	}
}

func (m *mcpServer) crawlSessionsTool() mcp.Tool {
	return mcp.NewTool("crawl_sessions",
		mcp.WithDescription(`List all crawl sessions.

Returns sessions ordered by creation time (most recent first).`),
		mcp.WithNumber("limit", mcp.Description("Maximum number of sessions to return (0 = all)")),
	)
}

func (m *mcpServer) handleCrawlSessions(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	limit := req.GetInt("limit", 0)

	log.Printf("mcp/crawl_sessions: listing sessions (limit=%d)", limit)

	sessions, err := m.service.crawlerBackend.ListSessions(ctx, limit)
	if err != nil {
		return errorResult("failed to list sessions: " + err.Error()), nil
	}

	apiSessions := make([]CrawlSessionAPI, 0, len(sessions))
	for _, sess := range sessions {
		apiSessions = append(apiSessions, CrawlSessionAPI{
			SessionID: sess.ID,
			Label:     sess.Label,
			State:     sess.State,
			CreatedAt: sess.CreatedAt.UTC().Format(time.RFC3339),
		})
	}

	return jsonResult(CrawlSessionsResponse{Sessions: apiSessions})
}

func (m *mcpServer) crawlStopTool() mcp.Tool {
	return mcp.NewTool("crawl_stop",
		mcp.WithDescription(`Stop a running crawl session.

In-flight requests are abandoned immediately.`),
		mcp.WithString("session_id", mcp.Required(), mcp.Description("Session ID or label")),
	)
}

func (m *mcpServer) handleCrawlStop(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	sessionID := req.GetString("session_id", "")
	if sessionID == "" {
		return errorResult("session_id is required"), nil
	}

	log.Printf("mcp/crawl_stop: stopping session %s", sessionID)

	if err := m.service.crawlerBackend.StopSession(ctx, sessionID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("session not found"), nil
		}
		return errorResult("failed to stop session: " + err.Error()), nil
	}

	return jsonResult(CrawlStopResponse{Stopped: true})
}

func (m *mcpServer) crawlGetTool() mcp.Tool {
	return mcp.NewTool("crawl_get",
		mcp.WithDescription(`Get full details of a crawl flow.

Returns the complete request and response for a flow captured during crawling.`),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("The flow_id from crawl_list")),
	)
}

func (m *mcpServer) handleCrawlGet(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	flowID := req.GetString("flow_id", "")
	if flowID == "" {
		return errorResult("flow_id is required"), nil
	}

	// Hidden parameter for CLI: returns full base64-encoded bodies instead of previews
	fullBody := req.GetBool("full_body", false)

	log.Printf("mcp/crawl_get: getting flow %s", flowID)

	flow, err := m.service.crawlerBackend.GetFlow(ctx, flowID)
	if err != nil {
		return errorResult("failed to get flow: " + err.Error()), nil
	}

	if flow == nil {
		return errorResult("flow not found: run crawl_list to see available flows"), nil
	}

	reqHeaders, reqBody := splitHeadersBody(flow.Request)
	respHeaders, respBody := splitHeadersBody(flow.Response)
	statusCode, statusLine := parseResponseStatus(respHeaders)

	// Format bodies based on full_body flag
	var reqBodyStr, respBodyStr string
	if fullBody {
		reqBodyStr = base64.StdEncoding.EncodeToString(reqBody)
		respBodyStr = base64.StdEncoding.EncodeToString(respBody)
	} else {
		reqBodyStr = previewBody(reqBody, fullBodyMaxSize)
		respBodyStr = previewBody(respBody, fullBodyMaxSize)
	}

	return jsonResult(CrawlGetResponse{
		FlowID:            flow.ID,
		Method:            flow.Method,
		URL:               flow.URL,
		FoundOn:           flow.FoundOn,
		Depth:             flow.Depth,
		ReqHeaders:        string(reqHeaders),
		ReqHeadersParsed:  parseHeadersToMap(string(reqHeaders)),
		ReqBody:           reqBodyStr,
		ReqSize:           len(reqBody),
		Status:            statusCode,
		StatusLine:        statusLine,
		RespHeaders:       string(respHeaders),
		RespHeadersParsed: parseHeadersToMap(string(respHeaders)),
		RespBody:          respBodyStr,
		RespSize:          len(respBody),
		Truncated:         flow.Truncated,
		Duration:          flow.Duration.Round(time.Millisecond).String(),
	})
}

// CrawlGetResponse is the response for MCP crawl_get.
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

// flowEntry holds parsed metadata for a proxy history entry.
type flowEntry struct {
	offset   uint32
	method   string
	host     string
	path     string
	status   int
	respLen  int
	request  string
	response string
}

// fetchAllProxyEntries retrieves all proxy history entries from the backend.
func (s *Server) fetchAllProxyEntries(ctx context.Context) ([]flowEntry, error) {
	var allEntries []flowEntry
	var offset uint32
	for {
		proxyEntries, err := s.httpBackend.GetProxyHistory(ctx, fetchBatchSize, offset)
		if err != nil {
			return nil, err
		}
		if len(proxyEntries) == 0 {
			break
		}

		for i, entry := range proxyEntries {
			method, host, path := extractRequestMeta(entry.Request)
			status := readResponseStatusCode([]byte(entry.Response))
			_, respBody := splitHeadersBody([]byte(entry.Response))

			allEntries = append(allEntries, flowEntry{
				offset:   offset + uint32(i),
				method:   method,
				host:     host,
				path:     path,
				status:   status,
				respLen:  len(respBody),
				request:  entry.Request,
				response: entry.Response,
			})
		}

		offset += uint32(len(proxyEntries))
		if len(proxyEntries) < fetchBatchSize {
			break
		}
	}
	return allEntries, nil
}

// applyProxyFilters applies filters that can't be expressed in Burp regex.
func applyProxyFilters(entries []flowEntry, req *ProxyListRequest, flowStore *store.FlowStore, lastOffset uint32) []flowEntry {
	if !req.HasFilters() {
		return entries
	}

	methods := parseCommaSeparated(req.Method)
	statuses := parseStatusFilter(req.Status)

	var sinceOffset uint32
	var hasSince bool
	if req.Since != "" {
		if req.Since == "last" {
			sinceOffset = lastOffset
			hasSince = true
		} else if entry, ok := flowStore.Lookup(req.Since); ok {
			sinceOffset = entry.Offset
			hasSince = true
		}
	}

	return bulk.SliceFilter(func(e flowEntry) bool {
		if hasSince && e.offset <= sinceOffset {
			return false // Since filter (exclusive - only entries after)
		} else if len(methods) > 0 && !slices.Contains(methods, e.method) {
			return false // Method filter
		} else if !statuses.Empty() && !statuses.Matches(e.status) {
			return false // Status filter
		} else if req.Host != "" && !matchesGlob(e.host, req.Host) {
			return false // Host filter (if using client-side filtering)
		} else if req.Path != "" && !matchesGlob(e.path, req.Path) && !matchesGlob(pathWithoutQuery(e.path), req.Path) {
			return false
		} else if req.ExcludeHost != "" && matchesGlob(e.host, req.ExcludeHost) {
			return false // Exclude host
		} else if req.ExcludePath != "" && matchesGlob(e.path, req.ExcludePath) {
			return false // Exclude path
		}
		if req.Contains != "" {
			// Search URL and headers only (not body)
			reqHeaders, _ := splitHeadersBody([]byte(e.request))
			respHeaders, _ := splitHeadersBody([]byte(e.response))
			combined := string(reqHeaders) + string(respHeaders)
			if !strings.Contains(combined, req.Contains) {
				return false
			}
		}
		if req.ContainsBody != "" {
			_, reqBody := splitHeadersBody([]byte(e.request))
			_, respBody := splitHeadersBody([]byte(e.response))
			combined := string(reqBody) + string(respBody)
			if !strings.Contains(combined, req.ContainsBody) {
				return false // Contains body filter
			}
		}

		return true
	}, entries)
}

var validRuleTypes = map[string]bool{
	// HTTP types
	RuleTypeRequestHeader:  true,
	RuleTypeRequestBody:    true,
	RuleTypeResponseHeader: true,
	RuleTypeResponseBody:   true,
	// WebSocket types
	"ws:to-server": true,
	"ws:to-client": true,
	"ws:both":      true,
}

func validateRuleTypeAny(t string) error {
	if !validRuleTypes[t] {
		return fmt.Errorf("invalid rule type %q", t)
	}
	return nil
}

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/go-appsec/toolbox/sectool/config"
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

	// Close HTTP server - use short timeout then force close.
	// Streaming connections (SSE, MCP) never become idle, so Shutdown blocks.
	if m.httpServer != nil {
		shortCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		err := m.httpServer.Shutdown(shortCtx)
		cancel()
		if errors.Is(err, context.DeadlineExceeded) {
			// Force close - active connections won't drain gracefully
			if closeErr := m.httpServer.Close(); closeErr != nil {
				errs = append(errs, closeErr)
			}
		} else if err != nil {
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
		m.addEncodingTools()
		m.addHashTools()
		m.addJWTTools()
		m.addCrawlTools()
		m.addDiffTools()
		m.addReflectionTools()
	case WorkflowModeTestReport:
		m.addProxyTools()
		m.addReplayTools()
		m.addOastTools()
		m.addEncodingTools()
		m.addHashTools()
		m.addJWTTools()
		m.addDiffTools()
		m.addReflectionTools()
		// crawl tools excluded
	default: // Empty (default) workflowMode: require workflow tool call first, all tools registered
		m.server.AddTool(m.workflowTool(), m.handleWorkflow)
		m.addProxyTools()
		m.addReplayTools()
		m.addOastTools()
		m.addEncodingTools()
		m.addHashTools()
		m.addJWTTools()
		m.addCrawlTools()
		m.addDiffTools()
		m.addReflectionTools()
	}
}

func (m *mcpServer) addProxyTools() {
	m.server.AddTool(m.proxyPollTool(), m.handleProxyPoll)
	m.server.AddTool(m.flowGetTool(), m.handleFlowGet)
	m.server.AddTool(m.cookieJarTool(), m.handleCookieJar)
	m.server.AddTool(m.proxyRuleListTool(), m.handleProxyRuleList)
	m.server.AddTool(m.proxyRuleAddTool(), m.handleProxyRuleAdd)
	m.server.AddTool(m.proxyRuleDeleteTool(), m.handleProxyRuleDelete)
}

func (m *mcpServer) addReplayTools() {
	m.server.AddTool(m.replaySendTool(), m.handleReplaySend)
	m.server.AddTool(m.requestSendTool(), m.handleRequestSend)
}

func (m *mcpServer) addOastTools() {
	m.server.AddTool(m.oastCreateTool(), m.handleOastCreate)
	m.server.AddTool(m.oastPollTool(), m.handleOastPoll)
	m.server.AddTool(m.oastGetTool(), m.handleOastGet)
	m.server.AddTool(m.oastListTool(), m.handleOastList)
	m.server.AddTool(m.oastDeleteTool(), m.handleOastDelete)
}

func (m *mcpServer) addEncodingTools() {
	m.server.AddTool(m.encodeTool(), m.handleEncode)
	m.server.AddTool(m.decodeTool(), m.handleDecode)
}

func (m *mcpServer) addHashTools() {
	m.server.AddTool(m.hashTool(), m.handleHash)
}

func (m *mcpServer) addJWTTools() {
	m.server.AddTool(m.jwtDecodeTool(), m.handleJWTDecode)
}

func (m *mcpServer) addCrawlTools() {
	m.server.AddTool(m.crawlCreateTool(), m.handleCrawlCreate)
	m.server.AddTool(m.crawlSeedTool(), m.handleCrawlSeed)
	m.server.AddTool(m.crawlStatusTool(), m.handleCrawlStatus)
	m.server.AddTool(m.crawlPollTool(), m.handleCrawlPoll)
	m.server.AddTool(m.crawlSessionsTool(), m.handleCrawlSessions)
	m.server.AddTool(m.crawlStopTool(), m.handleCrawlStop)
}

func (m *mcpServer) addDiffTools() {
	m.server.AddTool(m.diffFlowTool(), m.handleDiffFlow)
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
	log.Printf("workflow: initialized task=%s", task)

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
2. User generates traffic via browser; you monitor with proxy_poll
3. Identify interesting endpoints and potential vulnerabilities
4. Test hypotheses using sectool (often replay_send with modifications)
5. Report findings, discuss next steps, explore multiple angles in parallel

## Optional: Expanding Coverage with Crawling

Crawling can discover hidden endpoints, forms, and linked resources beyond manual exploration. Confirm with the user before starting a crawl.

When approved:
- crawl_create with seed_flows from proxy_poll to inherit authentication
- crawl_status to monitor progress; crawl_poll for aggregated results
- crawl_poll with output_mode="forms" to find input vectors for testing
- Crawler flows work with replay_send and flow_get just like proxy flows
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

// errorResultFromErr creates an error result with user-friendly timeout messages.
func errorResultFromErr(prefix string, err error) *mcp.CallToolResult {
	return mcp.NewToolResultError(prefix + translateTimeoutError(err))
}

// translateTimeoutError converts context errors to user-friendly messages.
func translateTimeoutError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "request timed out"
	}
	if errors.Is(err, context.Canceled) {
		return "request canceled"
	}
	return err.Error()
}

// resolvedFlow holds the raw request and response bytes for a resolved flow.
type resolvedFlow struct {
	RawRequest  []byte
	RawResponse []byte
	Source      string        // "proxy", "replay", "crawl"
	Protocol    string        // "http/1.1", "h2", or empty (defaults to http/1.1)
	Duration    time.Duration // replay, crawl (zero = not available)
	FoundOn     string        // crawl only
	Depth       int           // crawl only
	Truncated   bool          // crawl only
}

// resolveFlow looks up a flow by ID across replay, proxy, and crawler backends.
// Returns nil and an error result if the flow is not found.
func (m *mcpServer) resolveFlow(ctx context.Context, flowID string) (*resolvedFlow, *mcp.CallToolResult) {
	if entry, ok := m.service.replayHistoryStore.Get(flowID); ok {
		return &resolvedFlow{
			RawRequest:  entry.RawRequest,
			RawResponse: slices.Concat(entry.RespHeaders, entry.RespBody),
			Source:      SourceReplay,
			Protocol:    entry.Protocol,
			Duration:    entry.Duration,
		}, nil
	}
	if offset, ok := m.service.proxyIndex.Offset(flowID); ok {
		entries, err := m.service.httpBackend.GetProxyHistory(ctx, 1, offset)
		if err != nil {
			return nil, errorResultFromErr("failed to fetch flow: ", err)
		}
		if len(entries) == 0 {
			return nil, errorResult("flow not found in proxy history")
		}
		return &resolvedFlow{
			RawRequest:  []byte(entries[0].Request),
			RawResponse: []byte(entries[0].Response),
			Source:      SourceProxy,
			Protocol:    entries[0].Protocol,
		}, nil
	}
	if flow, err := m.service.crawlerBackend.GetFlow(ctx, flowID); err == nil && flow != nil {
		return &resolvedFlow{
			RawRequest:  flow.Request,
			RawResponse: flow.Response,
			Source:      SourceCrawl,
			Duration:    flow.Duration,
			FoundOn:     flow.FoundOn,
			Depth:       flow.Depth,
			Truncated:   flow.Truncated,
		}, nil
	}
	return nil, errorResult("flow_id not found: run proxy_poll or crawl_poll to see available flows")
}

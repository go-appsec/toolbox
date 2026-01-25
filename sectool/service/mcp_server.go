package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/go-harden/llm-security-toolbox/sectool/config"
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
	m.server.AddTool(m.proxyPollTool(), m.handleProxyPoll)
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
	m.server.AddTool(m.crawlPollTool(), m.handleCrawlPoll)
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

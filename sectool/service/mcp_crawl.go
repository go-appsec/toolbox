package service

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/llm-security-toolbox/sectool/protocol"
)

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
		// SubmitForms and ExtractForms left unset to use config defaults
	}

	log.Printf("mcp/crawl_create: creating session (label=%q, seeds=%d, domains=%d)",
		opts.Label, len(seeds), len(domains))

	sess, err := m.service.crawlerBackend.CreateSession(ctx, opts)
	if err != nil {
		if errors.Is(err, ErrLabelExists) {
			return errorResult("label already exists: " + err.Error()), nil
		}
		return errorResultFromErr("failed to create crawl session: ", err), nil
	}

	return jsonResult(protocol.CrawlCreateResponse{
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
		return errorResultFromErr("failed to add seeds: ", err), nil
	}

	return jsonResult(protocol.CrawlSeedResponse{AddedCount: len(seeds)})
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
		return errorResultFromErr("failed to get status: ", err), nil
	}

	return jsonResult(protocol.CrawlStatusResponse{
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

func (m *mcpServer) crawlPollTool() mcp.Tool {
	return mcp.NewTool("crawl_poll",
		mcp.WithDescription(`Query crawl session results: summary (default), flows, forms, or errors.

Output modes:
- "summary" (default): Returns traffic grouped by (host, path, method, status). Path patterns replace numeric IDs and UUIDs with * for grouping.
- "flows": Returns crawled flows with flow_id for use with crawl_get.
- "forms": Returns discovered forms with field information.
- "errors": Returns errors encountered during crawling.

Filters apply to summary and flows modes: host/path/exclude_host/exclude_path use glob (*, ?). method/status are comma-separated (status supports ranges like 2XX).
Incremental (summary/flows): since accepts flow_id, timestamp, or "last". Flows mode only: pagination with limit/offset.`),
		mcp.WithString("session_id", mcp.Required(), mcp.Description("Session ID or label")),
		mcp.WithString("output_mode", mcp.Description("Output mode: 'summary' (default), 'flows', 'forms', or 'errors'")),
		mcp.WithString("host", mcp.Description("Filter by host glob pattern (e.g., '*.example.com')")),
		mcp.WithString("path", mcp.Description("Filter by path glob pattern (e.g., '/api/*')")),
		mcp.WithString("method", mcp.Description("Filter by HTTP method (comma-separated)")),
		mcp.WithString("status", mcp.Description("Filter by status codes or ranges (e.g., '200,404' or '2XX,4XX')")),
		mcp.WithString("contains", mcp.Description("Search in URL and headers")),
		mcp.WithString("contains_body", mcp.Description("Search in request/response body")),
		mcp.WithString("exclude_host", mcp.Description("Exclude hosts matching glob pattern")),
		mcp.WithString("exclude_path", mcp.Description("Exclude paths matching glob pattern")),
		mcp.WithString("since", mcp.Description("flow_id, timestamp (RFC3339, '2006-01-02 15:04:05', '15:04:05'), or 'last' (cursor)")),
		mcp.WithNumber("limit", mcp.Description("Maximum number of results (default: 100 for flows/forms/errors)")),
		mcp.WithNumber("offset", mcp.Description("Skip first N results for pagination (flows mode)")),
	)
}

func (m *mcpServer) handleCrawlPoll(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	sessionID := req.GetString("session_id", "")
	if sessionID == "" {
		return errorResult("session_id is required"), nil
	}

	outputMode := req.GetString("output_mode", "summary")
	limit := req.GetInt("limit", 100)

	log.Printf("mcp/crawl_poll: mode=%s session=%s (limit=%d)", outputMode, sessionID, limit)

	switch outputMode {
	case "forms":
		forms, err := m.service.crawlerBackend.ListForms(ctx, sessionID, limit)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return errorResult("session not found"), nil
			}
			return errorResultFromErr("failed to list forms: ", err), nil
		}

		return jsonResult(protocol.CrawlPollResponse{SessionID: sessionID, Forms: formsToAPI(forms)})

	case "errors":
		errs, err := m.service.crawlerBackend.ListErrors(ctx, sessionID, limit)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return errorResult("session not found"), nil
			}
			return errorResultFromErr("failed to list errors: ", err), nil
		}

		var apiErrors []protocol.CrawlError
		for _, e := range errs {
			apiErrors = append(apiErrors, protocol.CrawlError{
				URL:    e.URL,
				Status: e.Status,
				Error:  e.Error,
			})
		}
		return jsonResult(protocol.CrawlPollResponse{SessionID: sessionID, Errors: apiErrors})

	case "flows":
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
			return errorResultFromErr("failed to list flows: ", err), nil
		}

		var apiFlows []protocol.CrawlFlow
		for _, f := range flows {
			apiFlows = append(apiFlows, protocol.CrawlFlow{
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
		return jsonResult(protocol.CrawlPollResponse{SessionID: sessionID, Flows: apiFlows})

	default: // summary
		// Get status for state and duration
		status, err := m.service.crawlerBackend.GetStatus(ctx, sessionID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return errorResult("session not found"), nil
			}
			return errorResultFromErr("failed to get status: ", err), nil
		}

		// Use ListFlows with filters (no limit) to get filtered flows, then aggregate
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
			Limit:        0, // no limit for summary
		}

		flows, err := m.service.crawlerBackend.ListFlows(ctx, sessionID, opts)
		if err != nil {
			return errorResultFromErr("failed to get flows: ", err), nil
		}

		aggregates := aggregateByTuple(flows, func(f CrawlFlow) (string, string, string, int) {
			return f.Host, f.Path, f.Method, f.StatusCode
		})

		return jsonResult(protocol.CrawlPollResponse{
			SessionID:  sessionID,
			State:      status.State,
			Duration:   status.Duration.Round(time.Millisecond).String(),
			Aggregates: aggregates,
		})
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
		return errorResultFromErr("failed to list sessions: ", err), nil
	}

	apiSessions := make([]protocol.CrawlSession, 0, len(sessions))
	for _, sess := range sessions {
		apiSessions = append(apiSessions, protocol.CrawlSession{
			SessionID: sess.ID,
			Label:     sess.Label,
			State:     sess.State,
			CreatedAt: sess.CreatedAt.UTC().Format(time.RFC3339),
		})
	}

	return jsonResult(protocol.CrawlSessionsResponse{Sessions: apiSessions})
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
		return errorResultFromErr("failed to stop session: ", err), nil
	}

	return jsonResult(CrawlStopResponse{Stopped: true})
}

func (m *mcpServer) crawlGetTool() mcp.Tool {
	return mcp.NewTool("crawl_get",
		mcp.WithDescription(`Get full details of a crawl flow.

Returns the complete request and response for a flow captured during crawling.`),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("The flow_id from crawl_poll (output_mode=flows)")),
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
		return errorResultFromErr("failed to get flow: ", err), nil
	}

	if flow == nil {
		return errorResult("flow not found: run crawl_poll to see available flows"), nil
	}

	reqHeaders, reqBody := splitHeadersBody(flow.Request)
	respHeaders, respBody := splitHeadersBody(flow.Response)
	statusCode, statusLine := parseResponseStatus(respHeaders)

	// Decompress bodies for display (gzip/deflate) - applies to both modes
	displayReqBody, _ := decompressForDisplay(reqBody, string(reqHeaders))
	displayRespBody, _ := decompressForDisplay(respBody, string(respHeaders))

	// Format bodies based on full_body flag
	var reqBodyStr, respBodyStr string
	if fullBody {
		// Full body mode: base64-encode the decompressed content
		reqBodyStr = base64.StdEncoding.EncodeToString(displayReqBody)
		respBodyStr = base64.StdEncoding.EncodeToString(displayRespBody)
	} else {
		// Preview mode: truncated text preview
		reqBodyStr = previewBody(displayReqBody, fullBodyMaxSize)
		respBodyStr = previewBody(displayRespBody, fullBodyMaxSize)
	}

	return jsonResult(protocol.CrawlGetResponse{
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

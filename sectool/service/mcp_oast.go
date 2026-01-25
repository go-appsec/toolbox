package service

import (
	"context"
	"errors"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-harden/llm-security-toolbox/sectool/protocol"
)

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
		mcp.WithDescription(`Poll for OAST interaction events: summary (default) or events mode.

Output modes:
- "summary" (default): Returns events aggregated by (subdomain, source_ip, type), sorted by count descending.
- "events": Returns individual events with event_id for use with oast_get.

Options:
- Immediate: omit wait
- Long-poll: set wait (e.g., '30s', max 120s)
- Incremental: use since parameter, accepts event_id, timestamp, or "last"
- Filter by type: dns, http, smtp, ftp, ldap, smb, responder

Response includes events/aggregates and optional dropped_count; use oast_get for full event details.`),
		mcp.WithString("oast_id", mcp.Required(), mcp.Description("OAST session ID, label, or domain")),
		mcp.WithString("output_mode", mcp.Description("Output mode: 'summary' (default) or 'events'")),
		mcp.WithString("since", mcp.Description("event_id, timestamp (e.g., RFC3339, '2006-01-02 15:04:05', '15:04:05'), or 'last' (per-session cursor)")),
		mcp.WithString("type", mcp.Description("Filter by event type: dns, http, smtp, ftp, ldap, smb, responder")),
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
	return jsonResult(protocol.OastCreateResponse{
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

	outputMode := req.GetString("output_mode", "summary")

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
	eventType := strings.ToLower(req.GetString("type", ""))
	limit := req.GetInt("limit", 0)

	log.Printf("mcp/oast_poll: mode=%s session=%s (wait=%v since=%q type=%q limit=%d)", outputMode, oastID, wait, since, eventType, limit)

	result, err := m.service.oastBackend.PollSession(ctx, oastID, since, eventType, wait, limit)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("session not found"), nil
		}
		return errorResult("failed to poll session: " + err.Error()), nil
	}

	switch outputMode {
	case "events":
		events := make([]protocol.OastEvent, len(result.Events))
		for i, e := range result.Events {
			events[i] = protocol.OastEvent{
				EventID:   e.ID,
				Time:      e.Time.UTC().Format(time.RFC3339),
				Type:      e.Type,
				SourceIP:  e.SourceIP,
				Subdomain: e.Subdomain,
				Details:   e.Details,
			}
		}

		log.Printf("mcp/oast_poll: session %s returned %d events", oastID, len(events))
		return jsonResult(protocol.OastPollResponse{
			Events:       events,
			DroppedCount: result.DroppedCount,
		})

	default: // summary
		agg := aggregateOastEvents(result.Events)
		log.Printf("mcp/oast_poll: session %s returned %d aggregates from %d events", oastID, len(agg), len(result.Events))
		return jsonResult(protocol.OastPollResponse{
			Aggregates:   agg,
			DroppedCount: result.DroppedCount,
		})
	}
}

// aggregateOastEvents aggregates OAST events by (subdomain, source_ip, type).
func aggregateOastEvents(events []OastEventInfo) []protocol.OastSummaryEntry {
	type key struct {
		subdomain string
		sourceIP  string
		eventType string
	}
	counts := make(map[key]int)

	for _, e := range events {
		k := key{subdomain: e.Subdomain, sourceIP: e.SourceIP, eventType: e.Type}
		counts[k]++
	}

	result := make([]protocol.OastSummaryEntry, 0, len(counts))
	for k, count := range counts {
		result = append(result, protocol.OastSummaryEntry{
			Subdomain: k.subdomain,
			SourceIP:  k.sourceIP,
			Type:      k.eventType,
			Count:     count,
		})
	}

	// Sort by count descending
	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	return result
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

	return jsonResult(protocol.OastGetResponse{
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

	apiSessions := make([]protocol.OastSession, len(sessions))
	for i, sess := range sessions {
		apiSessions[i] = protocol.OastSession{
			OastID:    sess.ID,
			Domain:    sess.Domain,
			Label:     sess.Label,
			CreatedAt: sess.CreatedAt.UTC().Format(time.RFC3339),
		}
	}

	log.Printf("oast/list: returning %d active sessions", len(apiSessions))
	return jsonResult(&protocol.OastListResponse{Sessions: apiSessions})
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

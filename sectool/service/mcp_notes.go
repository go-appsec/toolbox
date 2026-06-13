package service

import (
	"context"
	"log"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/dedupe"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sectool/util"
)

func (m *mcpServer) addNotesTools() {
	m.server.AddTool(m.notesSaveTool(), m.handleNotesSave)
	m.server.AddTool(m.notesListTool(), m.handleNotesList)
}

func (m *mcpServer) notesSaveTool() mcp.Tool {
	return mcp.NewTool("notes_save",
		mcp.WithDescription(`Create, update, or delete a note/finding linked to captured flows.

Create: omit note_id, provide type + content + flow_ids (optional).
Update: provide note_id + fields to change (only provided fields to update).
Delete: provide note_id only, all other fields must be empty.`),
		mcp.WithString("note_id", mcp.Description("Provide note_id to update or delete")),
		mcp.WithString("type", mcp.Description("Note type (free-form): finding, note, result, observation, etc.")),
		mcp.WithString("flow_ids", mcp.Description("Flow IDs (from proxy, replay, crawl) to associate as JSON array")),
		mcp.WithString("content", mcp.Description("Description and details for note")),
	)
}

func (m *mcpServer) notesListTool() mcp.Tool {
	return mcp.NewTool("notes_list",
		mcp.WithDescription(`List saved notes with optional filters.

Returns notes sorted by creation time. Use filters to narrow results.`),
		mcp.WithString("type", mcp.Description("Filter by note type")),
		mcp.WithString("flow_ids", mcp.Description("Filter to notes referencing flow IDs as JSON array")),
		mcp.WithString("contains", mcp.Description("Case-insensitive substring search on content")),
		mcp.WithString("after_id", mcp.Description("Paging cursor: return the identified note and any created after")),
		mcp.WithNumber("limit", mcp.Description("Maximum number of notes to return (1 with after_id to lookup single note)")),
	)
}

func (m *mcpServer) handleNotesSave(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	noteID := req.GetString("note_id", "")
	noteType := req.GetString("type", "")
	flowIDsStr := req.GetString("flow_ids", "")
	content := req.GetString("content", "")

	ns := m.service.noteStore

	// Delete: note_id provided with all other fields empty
	if noteID != "" && noteType == "" && flowIDsStr == "" && content == "" {
		existing, ok := ns.Get(noteID)
		if !ok {
			return errorResult("note not found: " + noteID), nil
		} else if err := ns.Delete(noteID); err != nil {
			return errorResult("failed to delete note: " + err.Error()), nil
		}
		log.Printf("notes/save: deleted note %s (type=%s)", noteID, existing.Type)
		return jsonResult(protocol.NoteDeleteResponse{})
	}

	// Update: note_id provided with some fields
	if noteID != "" {
		existing, ok := ns.Get(noteID)
		if !ok {
			return errorResult("note not found: " + noteID), nil
		}

		// Merge provided fields
		if noteType != "" {
			existing.Type = noteType
		}
		if flowIDsStr != "" {
			flowIDs := dedupe.Slice(parseStringList(flowIDsStr))
			if errResult := m.validateFlowIDs(ctx, flowIDs); errResult != nil {
				return errResult, nil
			}
			existing.FlowIDs = flowIDs
		}
		if content != "" {
			existing.Content = content
		}

		if err := ns.Save(existing); err != nil {
			return errorResult("failed to update note: " + err.Error()), nil
		}

		log.Printf("notes/save: updated note %s (type=%s, flows=%d)", noteID, existing.Type, len(existing.FlowIDs))
		return jsonResult(noteToEntry(existing))
	}

	// Create: no note_id
	if noteType == "" {
		return errorResult("type is required when creating a note"), nil
	} else if content == "" {
		return errorResult("content is required when creating a note"), nil
	}

	flowIDs := dedupe.Slice(parseStringList(flowIDsStr))
	if errResult := m.validateFlowIDs(ctx, flowIDs); errResult != nil {
		return errResult, nil
	}

	note := &store.NoteMeta{
		Type:    noteType,
		FlowIDs: flowIDs,
		Content: content,
	}

	if err := ns.Create(note); err != nil {
		return errorResult("failed to save note: " + err.Error()), nil
	}

	log.Printf("notes/save: created note %s (type=%s, flows=%d)", note.NoteID, note.Type, len(note.FlowIDs))
	return jsonResult(noteToEntry(note))
}

func (m *mcpServer) handleNotesList(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	ns := m.service.noteStore

	flowIDStr := req.GetString("flow_ids", "")
	var flowIDs []string
	if flowIDStr != "" {
		flowIDs = parseStringList(flowIDStr)
	}

	opts := store.NoteListOptions{
		Type:     req.GetString("type", ""),
		FlowIDs:  flowIDs,
		Contains: req.GetString("contains", ""),
		AfterID:  req.GetString("after_id", ""),
		Limit:    req.GetInt("limit", 0),
	}

	notes := ns.List(opts)

	entries := make([]protocol.NoteEntry, len(notes))
	for i, n := range notes {
		entries[i] = noteToEntry(n)
	}

	log.Printf("notes/list: %d notes (type=%q flow_ids=%v contains=%q)", len(entries), opts.Type, opts.FlowIDs, opts.Contains)
	return jsonResult(protocol.NotesListResponse{Notes: entries})
}

// validateFlowIDs checks that all flow IDs exist across proxy, replay, and crawl.
func (m *mcpServer) validateFlowIDs(ctx context.Context, flowIDs []string) *mcp.CallToolResult {
	for _, fid := range flowIDs {
		if !m.flowExists(ctx, fid) {
			return errorResult("flow_id not found: " + fid)
		}
	}
	return nil
}

// flowExists checks if a flow ID exists in any backend without full deserialization.
func (m *mcpServer) flowExists(ctx context.Context, flowID string) bool {
	if _, ok := m.service.replayHistoryStore.Get(flowID); ok {
		return true
	} else if entry, err := m.service.httpBackend.GetProxyEntry(ctx, flowID); err == nil && entry != nil {
		return true
	} else if flow, err := m.service.crawlerBackend.GetFlow(ctx, flowID); err == nil && flow != nil {
		return true
	}
	return false
}

// attachFlowNotes attaches note info to proxy/replay flow entries.
// No-op when no notes exist.
func (m *mcpServer) attachFlowNotes(flows []protocol.FlowEntry) {
	if m.service.noteStore.Count() == 0 || len(flows) == 0 {
		return
	}

	flowIDs := make([]string, len(flows))
	for i, f := range flows {
		flowIDs[i] = f.FlowID
	}

	noteMap := m.service.noteStore.ForFlowIDs(flowIDs)
	if len(noteMap) == 0 {
		return
	}

	for i, f := range flows {
		if notes, ok := noteMap[f.FlowID]; ok {
			flows[i].Notes = notesToFlowInfo(notes)
		}
	}
}

// attachCrawlFlowNotes attaches note info to crawl flow entries.
// No-op when no notes exist.
func (m *mcpServer) attachCrawlFlowNotes(flows []protocol.CrawlFlow) {
	if m.service.noteStore.Count() == 0 || len(flows) == 0 {
		return
	}

	flowIDs := make([]string, len(flows))
	for i, f := range flows {
		flowIDs[i] = f.FlowID
	}

	noteMap := m.service.noteStore.ForFlowIDs(flowIDs)
	if len(noteMap) == 0 {
		return
	}

	for i, f := range flows {
		if notes, ok := noteMap[f.FlowID]; ok {
			flows[i].Notes = notesToFlowInfo(notes)
		}
	}
}

const maxFlowNoteContentLen = 1000

func notesToFlowInfo(notes []*store.NoteMeta) []protocol.FlowNoteInfo {
	infos := make([]protocol.FlowNoteInfo, len(notes))
	for i, n := range notes {
		infos[i] = protocol.FlowNoteInfo{
			NoteID:  n.NoteID,
			Type:    n.Type,
			Content: util.TruncateString(n.Content, maxFlowNoteContentLen),
		}
	}
	return infos
}

func noteToEntry(n *store.NoteMeta) protocol.NoteEntry {
	return protocol.NoteEntry{
		NoteID:  n.NoteID,
		Type:    n.Type,
		FlowIDs: n.FlowIDs,
		Content: n.Content,
	}
}

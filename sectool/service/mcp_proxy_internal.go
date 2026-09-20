package service

import (
	"context"
	"errors"
	"log"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

// InternalToolPrefix marks tools intended for CLI-only use.
// Tools with this prefix are excluded from tools/list via WithToolFilter,
// but remain callable by name through tools/call.
const InternalToolPrefix = "_internal_"

func (m *mcpServer) historyDeleteTool() mcp.Tool {
	return mcp.NewTool(InternalToolPrefix+"history_delete",
		mcp.WithDescription("Internal CLI-only: delete proxy and replay history entries by the exact flow_ids provided. Flow_ids referenced by saved notes are retained and reported in skipped_noted."),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithArray("flow_ids", mcp.Required(),
			mcp.Items(map[string]any{schemaTypeKey: schemaTypeString}),
			mcp.Description("Flow IDs to delete")),
	)
}

func (m *mcpServer) handleHistoryDelete(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	flowIDs := req.GetStringSlice("flow_ids", nil)
	if len(flowIDs) == 0 {
		return errorResult("flow_ids is required"), nil
	}

	deletedProxy, deletedReplay, skippedNoted, err := m.service.DeleteProxyHistory(ctx, flowIDs)
	if err != nil {
		if errors.Is(err, ErrNotSupported) {
			return errorResult("proxy history deletion is not supported by the current backend (Burp); use the native built-in proxy"), nil
		}
		return errorResultFromErr("failed to delete history entries: ", err), nil
	}

	log.Printf("history/delete: deleted_proxy=%d deleted_replay=%d skipped_noted=%d (input=%d)",
		deletedProxy, deletedReplay, len(skippedNoted), len(flowIDs))
	return jsonResult(protocol.HistoryDeleteResponse{
		DeletedProxy:  deletedProxy,
		DeletedReplay: deletedReplay,
		Skipped:       skippedNoted,
	})
}

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// CoreInvoke dispatches a core MCP tool by name with the supplied params, returning
// its result text and whether it reported an error. Internal tools (InternalToolPrefix)
// are not invocable. It reuses the exact handlers agents call, so results match.
func (m *mcpServer) CoreInvoke(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
	if strings.HasPrefix(tool, InternalToolPrefix) {
		return "", false, fmt.Errorf("tool not permitted: %s", tool)
	}
	st, ok := m.server.ListTools()[tool]
	if !ok {
		return "", false, fmt.Errorf("unknown tool: %s", tool)
	}
	args := map[string]any{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &args); err != nil {
			return "", false, fmt.Errorf("invalid params: %w", err)
		}
	}
	var req mcp.CallToolRequest
	req.Params.Name = tool
	req.Params.Arguments = args
	res, err := st.Handler(ctx, req)
	if err != nil {
		return "", false, err
	}
	return resultText(res), res.IsError, nil
}

// resultText flattens a tool result's text content blocks.
func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

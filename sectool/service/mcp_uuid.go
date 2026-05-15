package service

import (
	"context"
	"log"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
)

func (m *mcpServer) uuidGenerateTool() mcp.Tool {
	return mcp.NewTool("uuid_generate",
		mcp.WithDescription("Generate a UUID. Supported versions: v4 (random), v7 (time-ordered)."),
		mcp.WithString("version", mcp.Enum("v4", "v7"), mcp.Description("UUID version (default: v4)")),
	)
}

func (m *mcpServer) handleUUIDGenerate(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	version := req.GetString("version", "v4")

	var gen func() (uuid.UUID, error)
	switch version {
	case "v4":
		gen = uuid.NewRandom
	case "v7":
		gen = uuid.NewV7
	default:
		return errorResult("invalid version: use 'v4' or 'v7'"), nil
	}

	u, err := gen()
	if err != nil {
		return errorResult("uuid generation error: " + err.Error()), nil
	}

	uuidStr := u.String()
	log.Printf("uuid_generate: %s version=%s", uuidStr, version)
	return mcp.NewToolResultText(uuidStr), nil
}

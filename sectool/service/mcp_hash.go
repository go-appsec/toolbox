package service

import (
	"context"
	"log"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/hash"
)

func (m *mcpServer) hashTool() mcp.Tool {
	return mcp.NewTool("hash",
		mcp.WithDescription("Compute a hash digest."),
		mcp.WithString("input", mcp.Required(), mcp.Description("String to hash")),
		mcp.WithString("algorithm", mcp.Enum("md5", "sha1", "sha256", "sha512"), mcp.Description("Hash algorithm (default: sha256)")),
		mcp.WithString("key", mcp.Description("HMAC key (if set, computes HMAC instead of plain hash)")),
	)
}

func (m *mcpServer) handleHash(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := req.GetString("input", "")
	if input == "" {
		return errorResult("input is required"), nil
	}

	// Accept algorithm or type, prefer algorithm
	algorithm := req.GetString("algorithm", "")
	if algorithm == "" {
		algorithm = req.GetString("type", "sha256")
	}

	key := req.GetString("key", "")
	digest, err := hash.ComputeHash(input, algorithm, key)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	log.Printf("hash: algorithm=%s hmac=%v", algorithm, key != "")
	return mcp.NewToolResultText(digest), nil
}

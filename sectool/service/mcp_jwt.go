package service

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/jwt"
)

func (m *mcpServer) jwtDecodeTool() mcp.Tool {
	return mcp.NewTool("jwt_decode",
		mcp.WithDescription("Decode a JWT. Returns header, payload, signature, and security issues."),
		mcp.WithString("token", mcp.Required(), mcp.Description("JWT string (Bearer prefix auto-stripped)")),
	)
}

func (m *mcpServer) handleJWTDecode(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	token := req.GetString("token", "")
	if token == "" {
		return errorResult("token is required"), nil
	}

	result, err := jwt.DecodeJWT(token)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	return jsonResult(result)
}

package service

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/encoding"
)

func (m *mcpServer) encodeTool() mcp.Tool {
	return mcp.NewTool("encode",
		mcp.WithDescription("Encode a string. Supported types: url (percent-encoding), base64, html (entity encoding)."),
		mcp.WithString("input", mcp.Required(), mcp.Description("String to encode")),
		mcp.WithString("type", mcp.Required(), mcp.Enum("url", "base64", "html"), mcp.Description("Encoding type")),
	)
}

func (m *mcpServer) decodeTool() mcp.Tool {
	return mcp.NewTool("decode",
		mcp.WithDescription("Decode a string. Supported types: url (percent-encoding), base64, html (entity decoding)."),
		mcp.WithString("input", mcp.Required(), mcp.Description("String to decode")),
		mcp.WithString("type", mcp.Required(), mcp.Enum("url", "base64", "html"), mcp.Description("Encoding type")),
	)
}

func (m *mcpServer) handleEncode(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := req.GetString("input", "")
	if input == "" {
		return errorResult("input is required"), nil
	}

	result, err := encoding.Encode(input, req.GetString("type", ""))
	if err != nil {
		return errorResult(err.Error()), nil
	}

	return mcp.NewToolResultText(result), nil
}

func (m *mcpServer) handleDecode(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := req.GetString("input", "")
	if input == "" {
		return errorResult("input is required"), nil
	}

	result, err := encoding.Decode(input, req.GetString("type", ""))
	if err != nil {
		return errorResult(err.Error()), nil
	}

	return mcp.NewToolResultText(result), nil
}

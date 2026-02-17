package service

import (
	"context"
	"log"

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

	encType := req.GetString("type", "")
	result, err := encoding.Encode(input, encType)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	log.Printf("encode: type=%s len=%d", encType, len(result))
	return mcp.NewToolResultText(result), nil
}

func (m *mcpServer) handleDecode(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := req.GetString("input", "")
	if input == "" {
		return errorResult("input is required"), nil
	}

	decType := req.GetString("type", "")
	result, err := encoding.Decode(input, decType)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	log.Printf("decode: type=%s len=%d", decType, len(result))
	return mcp.NewToolResultText(result), nil
}

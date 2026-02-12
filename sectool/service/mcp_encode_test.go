package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMCP_Encode(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t)

	t.Run("url", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "encode", map[string]interface{}{
			"input": "hello world&test=<value>",
			"type":  "url",
		})
		assert.Equal(t, "hello+world%26test%3D%3Cvalue%3E", text)
	})

	t.Run("base64", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "encode", map[string]interface{}{
			"input": "hello world",
			"type":  "base64",
		})
		assert.Equal(t, "aGVsbG8gd29ybGQ=", text)
	})

	t.Run("html", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "encode", map[string]interface{}{
			"input": "<script>alert('xss')</script>",
			"type":  "html",
		})
		assert.Equal(t, "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;", text)
	})

	t.Run("invalid_type", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "encode", map[string]interface{}{
			"input": "test",
			"type":  "invalid",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "invalid type")
	})

	t.Run("missing_input", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "encode", map[string]interface{}{
			"type": "url",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "input is required")
	})
}

func TestMCP_Decode(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t)

	t.Run("url", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "decode", map[string]interface{}{
			"input": "hello+world%26test%3D%3Cvalue%3E",
			"type":  "url",
		})
		assert.Equal(t, "hello world&test=<value>", text)
	})

	t.Run("base64", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "decode", map[string]interface{}{
			"input": "aGVsbG8gd29ybGQ=",
			"type":  "base64",
		})
		assert.Equal(t, "hello world", text)
	})

	t.Run("html", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "decode", map[string]interface{}{
			"input": "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
			"type":  "html",
		})
		assert.Equal(t, "<script>alert('xss')</script>", text)
	})

	t.Run("url_malformed", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "decode", map[string]interface{}{
			"input": "%ZZ%invalid",
			"type":  "url",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "URL decode error")
	})

	t.Run("base64_invalid", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "decode", map[string]interface{}{
			"input": "not valid base64!!!",
			"type":  "base64",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "base64 decode error")
	})

	t.Run("invalid_type", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "decode", map[string]interface{}{
			"input": "test",
			"type":  "invalid",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "invalid type")
	})

	t.Run("missing_input", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "decode", map[string]interface{}{
			"type": "url",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "input is required")
	})
}

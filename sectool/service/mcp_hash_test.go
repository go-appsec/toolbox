package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMCP_Hash(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t)

	t.Run("sha256_default", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "hash", map[string]interface{}{
			"input": "test",
		})
		assert.Equal(t, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", text)
	})

	t.Run("md5", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "hash", map[string]interface{}{
			"input":     "test",
			"algorithm": "md5",
		})
		assert.Equal(t, "098f6bcd4621d373cade4e832627b4f6", text)
	})

	t.Run("sha1", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "hash", map[string]interface{}{
			"input":     "test",
			"algorithm": "sha1",
		})
		assert.Equal(t, "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", text)
	})

	t.Run("sha512", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "hash", map[string]interface{}{
			"input":     "test",
			"algorithm": "sha512",
		})
		assert.Equal(t, "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff", text)
	})

	t.Run("type_alias", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "hash", map[string]interface{}{
			"input": "test",
			"type":  "md5",
		})
		assert.Equal(t, "098f6bcd4621d373cade4e832627b4f6", text)
	})

	t.Run("hmac_sha256", func(t *testing.T) {
		text := CallMCPToolTextOK(t, mcpClient, "hash", map[string]interface{}{
			"input": "test",
			"key":   "secret",
		})
		assert.Equal(t, "0329a06b62cd16b33eb6792be8c60b158d89a2ee3a876fce9a881ebb488c0914", text)
	})

	t.Run("missing_input", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "hash", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "input is required")
	})
}

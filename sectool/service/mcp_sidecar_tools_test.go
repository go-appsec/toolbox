package service

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

func TestSidecarToolResult(t *testing.T) {
	t.Parallel()

	t.Run("structured_object", func(t *testing.T) {
		res := sidecarToolResult(wire.InvokeToolResult{Result: json.RawMessage(`{"done":true}`)})
		require.NotNil(t, res.StructuredContent)
		// text fallback is the raw JSON, never empty
		assert.JSONEq(t, `{"done":true}`, resultText(res))
		assert.False(t, res.IsError)
	})

	t.Run("empty_result", func(t *testing.T) {
		res := sidecarToolResult(wire.InvokeToolResult{})
		assert.Nil(t, res.StructuredContent)
		assert.Empty(t, resultText(res))
	})

	t.Run("error_propagates", func(t *testing.T) {
		res := sidecarToolResult(wire.InvokeToolResult{Result: json.RawMessage(`{"error":"boom"}`), IsError: true})
		require.NotNil(t, res.StructuredContent)
		assert.True(t, res.IsError)
	})

	t.Run("non_json_falls_back_to_text", func(t *testing.T) {
		res := sidecarToolResult(wire.InvokeToolResult{Result: json.RawMessage(`not json`)})
		assert.Nil(t, res.StructuredContent)
		assert.Equal(t, "not json", resultText(res))
	})

	t.Run("legacy_structured_content", func(t *testing.T) {
		res := sidecarToolResult(wire.InvokeToolResult{StructuredContent: json.RawMessage(`{"legacy":true}`)}) //nolint:staticcheck // deprecated legacy fallback
		require.NotNil(t, res.StructuredContent)
		assert.JSONEq(t, `{"legacy":true}`, resultText(res))
	})

	t.Run("legacy_content", func(t *testing.T) {
		res := sidecarToolResult(wire.InvokeToolResult{Content: "plain text"}) //nolint:staticcheck // deprecated legacy fallback
		assert.Nil(t, res.StructuredContent)
		assert.Equal(t, "plain text", resultText(res))
	})
}

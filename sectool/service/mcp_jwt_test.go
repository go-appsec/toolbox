package service

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/jwt"
)

func testMakeJWT(header, payload map[string]interface{}) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + ".test-signature"
}

func TestMCP_JWTDecode(t *testing.T) {
	t.Parallel()

	_, mcpClient, _, _, _ := setupMockMCPServer(t)

	t.Run("valid_jwt", func(t *testing.T) {
		now := time.Now()
		token := testMakeJWT(
			map[string]interface{}{"alg": "HS256", "typ": "JWT"},
			map[string]interface{}{"sub": "123", "exp": float64(now.Add(1 * time.Hour).Unix()), "iat": float64(now.Unix())},
		)

		var result jwt.Result
		text := CallMCPToolTextOK(t, mcpClient, "jwt_decode", map[string]interface{}{
			"token": token,
		})
		require.NoError(t, json.Unmarshal([]byte(text), &result))
		assert.Equal(t, "HS256", result.Header["alg"])
		assert.Equal(t, "123", result.Payload["sub"])
		assert.Empty(t, result.Issues)
		assert.Contains(t, result.Expiry, "expires in")
	})

	t.Run("expired_jwt", func(t *testing.T) {
		token := testMakeJWT(
			map[string]interface{}{"alg": "HS256"},
			map[string]interface{}{"sub": "123", "exp": float64(time.Now().Add(-2 * time.Hour).Unix())},
		)

		var result jwt.Result
		text := CallMCPToolTextOK(t, mcpClient, "jwt_decode", map[string]interface{}{
			"token": token,
		})
		require.NoError(t, json.Unmarshal([]byte(text), &result))
		assert.Contains(t, result.Expiry, "expired")
	})

	t.Run("alg_none", func(t *testing.T) {
		token := testMakeJWT(
			map[string]interface{}{"alg": "none"},
			map[string]interface{}{"sub": "123", "exp": float64(time.Now().Add(1 * time.Hour).Unix())},
		)

		var result jwt.Result
		text := CallMCPToolTextOK(t, mcpClient, "jwt_decode", map[string]interface{}{
			"token": token,
		})
		require.NoError(t, json.Unmarshal([]byte(text), &result))
		assert.Contains(t, result.Issues, "algorithm set to 'none' - signature not verified")
	})

	t.Run("bearer_prefix", func(t *testing.T) {
		token := testMakeJWT(
			map[string]interface{}{"alg": "HS256"},
			map[string]interface{}{"sub": "123", "exp": float64(time.Now().Add(1 * time.Hour).Unix())},
		)

		var result jwt.Result
		text := CallMCPToolTextOK(t, mcpClient, "jwt_decode", map[string]interface{}{
			"token": "Bearer " + token,
		})
		require.NoError(t, json.Unmarshal([]byte(text), &result))
		assert.Equal(t, "HS256", result.Header["alg"])
	})

	t.Run("malformed", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "jwt_decode", map[string]interface{}{
			"token": "not-a-jwt",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "invalid JWT")
	})

	t.Run("missing_token", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "jwt_decode", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "token is required")
	})
}

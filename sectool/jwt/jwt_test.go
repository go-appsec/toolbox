package jwt

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeJWT(header, payload map[string]interface{}) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + ".test-signature"
}

func TestDecodeJWT(t *testing.T) {
	t.Parallel()

	now := time.Now()
	futureExp := float64(now.Add(1 * time.Hour).Unix())

	token := makeJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "123", "exp": futureExp, "iat": float64(now.Unix())},
	)

	result, err := DecodeJWT(token)
	require.NoError(t, err)
	assert.Equal(t, "HS256", result.Header["alg"])
	assert.Equal(t, "123", result.Payload["sub"])
	assert.Equal(t, "test-signature", result.Signature)
	assert.Empty(t, result.Issues)
	assert.Contains(t, result.Expiry, "expires in")
}

func TestDecodeJWT_expired(t *testing.T) {
	t.Parallel()

	pastExp := float64(time.Now().Add(-2 * time.Hour).Unix())
	token := makeJWT(
		map[string]interface{}{"alg": "HS256"},
		map[string]interface{}{"sub": "123", "exp": pastExp, "iat": float64(time.Now().Add(-3 * time.Hour).Unix())},
	)

	result, err := DecodeJWT(token)
	require.NoError(t, err)
	assert.Contains(t, result.Expiry, "expired")

	var hasExpiredIssue bool
	for _, issue := range result.Issues {
		if assert.ObjectsAreEqual("token expired", issue[:13]) {
			hasExpiredIssue = true
		}
	}
	assert.True(t, hasExpiredIssue)
}

func TestDecodeJWT_alg_none(t *testing.T) {
	t.Parallel()

	token := makeJWT(
		map[string]interface{}{"alg": "none"},
		map[string]interface{}{"sub": "123", "exp": float64(time.Now().Add(1 * time.Hour).Unix())},
	)

	result, err := DecodeJWT(token)
	require.NoError(t, err)
	assert.Contains(t, result.Issues, "algorithm set to 'none' - signature not verified")
}

func TestDecodeJWT_no_exp(t *testing.T) {
	t.Parallel()

	token := makeJWT(
		map[string]interface{}{"alg": "HS256"},
		map[string]interface{}{"sub": "123"},
	)

	result, err := DecodeJWT(token)
	require.NoError(t, err)
	assert.Contains(t, result.Issues, "no 'exp' claim - token never expires")
	assert.Empty(t, result.Expiry)
}

func TestDecodeJWT_long_lived(t *testing.T) {
	t.Parallel()

	now := time.Now()
	token := makeJWT(
		map[string]interface{}{"alg": "HS256"},
		map[string]interface{}{
			"sub": "123",
			"iat": float64(now.Unix()),
			"exp": float64(now.Add(90 * 24 * time.Hour).Unix()),
		},
	)

	result, err := DecodeJWT(token)
	require.NoError(t, err)

	var hasLongLived bool
	for _, issue := range result.Issues {
		if len(issue) > 10 && issue[:10] == "long-lived" {
			hasLongLived = true
		}
	}
	assert.True(t, hasLongLived)
}

func TestDecodeJWT_bearer_prefix(t *testing.T) {
	t.Parallel()

	token := makeJWT(
		map[string]interface{}{"alg": "HS256"},
		map[string]interface{}{"sub": "123", "exp": float64(time.Now().Add(1 * time.Hour).Unix())},
	)

	result, err := DecodeJWT("Bearer " + token)
	require.NoError(t, err)
	assert.Equal(t, "HS256", result.Header["alg"])
}

func TestDecodeJWT_malformed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		token   string
		wantErr string
	}{
		{name: "too_few_parts", token: "abc.def", wantErr: "expected 3 parts"},
		{name: "invalid_header_base64", token: "!!!.def.ghi", wantErr: "invalid JWT header"},
		{name: "invalid_payload_base64", token: base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + ".!!!.sig", wantErr: "invalid JWT payload"},
		{name: "invalid_header_json", token: base64.RawURLEncoding.EncodeToString([]byte("not-json")) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{}`)) + ".sig", wantErr: "invalid JWT header JSON"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeJWT(tt.token)
			require.Error(t, err)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

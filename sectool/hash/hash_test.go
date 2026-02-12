package hash

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeHash(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		algorithm string
		expect    string
	}{
		{name: "md5", input: "test", algorithm: "md5", expect: "098f6bcd4621d373cade4e832627b4f6"},
		{name: "sha1", input: "test", algorithm: "sha1", expect: "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"},
		{name: "sha256", input: "test", algorithm: "sha256", expect: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
		{name: "sha512", input: "test", algorithm: "sha512", expect: "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ComputeHash(tt.input, tt.algorithm, "")
			require.NoError(t, err)
			assert.Equal(t, tt.expect, result)
		})
	}
}

func TestComputeHash_HMAC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		algorithm string
		key       string
		expect    string
	}{
		{name: "hmac_md5", input: "test", algorithm: "md5", key: "secret", expect: "63d6baf65df6bdee8f32b332e0930669"},
		{name: "hmac_sha256", input: "test", algorithm: "sha256", key: "secret", expect: "0329a06b62cd16b33eb6792be8c60b158d89a2ee3a876fce9a881ebb488c0914"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ComputeHash(tt.input, tt.algorithm, tt.key)
			require.NoError(t, err)
			assert.Equal(t, tt.expect, result)
		})
	}
}

func TestComputeHash_invalid_algorithm(t *testing.T) {
	t.Parallel()

	_, err := ComputeHash("test", "invalid", "")
	require.Error(t, err)
	assert.ErrorContains(t, err, "unsupported algorithm")
}

func TestComputeHash_hmac_invalid_algorithm(t *testing.T) {
	t.Parallel()

	_, err := ComputeHash("test", "invalid", "key")
	require.Error(t, err)
	assert.ErrorContains(t, err, "unsupported algorithm")
}

package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModifyFormBodyMap(t *testing.T) {
	t.Parallel()

	t.Run("no_modifications_returns_body_verbatim", func(t *testing.T) {
		in := []byte("a=1&b=2")
		out, err := modifyFormBodyMap(in, nil, nil)
		require.NoError(t, err)
		assert.Equal(t, in, out)
	})

	t.Run("set_replaces_existing_value", func(t *testing.T) {
		out, err := modifyFormBodyMap(
			[]byte("grant_type=refresh_token&client_id=x"),
			map[string]string{"grant_type": "password"},
			nil,
		)
		require.NoError(t, err)
		assert.Equal(t, "client_id=x&grant_type=password", string(out))
	})

	t.Run("set_adds_new_field", func(t *testing.T) {
		out, err := modifyFormBodyMap(
			[]byte("grant_type=password"),
			map[string]string{"scope": "read"},
			nil,
		)
		require.NoError(t, err)
		assert.Equal(t, "grant_type=password&scope=read", string(out))
	})

	t.Run("remove_drops_field", func(t *testing.T) {
		out, err := modifyFormBodyMap(
			[]byte("a=1&b=2&c=3"),
			nil,
			[]string{"b"},
		)
		require.NoError(t, err)
		assert.Equal(t, "a=1&c=3", string(out))
	})

	t.Run("special_characters_escaped", func(t *testing.T) {
		out, err := modifyFormBodyMap(
			nil,
			map[string]string{"redirect_uri": "https://example.com/cb?x=1&y=2"},
			nil,
		)
		require.NoError(t, err)
		assert.Equal(t, "redirect_uri=https%3A%2F%2Fexample.com%2Fcb%3Fx%3D1%26y%3D2", string(out))
	})

	t.Run("empty_body_with_only_sets", func(t *testing.T) {
		out, err := modifyFormBodyMap(
			nil,
			map[string]string{"grant_type": "client_credentials"},
			nil,
		)
		require.NoError(t, err)
		assert.Equal(t, "grant_type=client_credentials", string(out))
	})
}

package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemStorage_SetAndGet(t *testing.T) {
	t.Parallel()

	s := NewMemStorage()
	t.Cleanup(func() { _ = s.Close() })

	err := s.Set("key1", []byte("value1"))
	require.NoError(t, err)

	data, found, err := s.Get("key1")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, []byte("value1"), data)
}

func TestMemStorage_GetNotFound(t *testing.T) {
	t.Parallel()

	s := NewMemStorage()
	t.Cleanup(func() { _ = s.Close() })

	data, found, err := s.Get("nonexistent")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, data)
}

func TestMemStorage_Delete(t *testing.T) {
	t.Parallel()

	s := NewMemStorage()
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.Set("key1", []byte("value1")))

	err := s.Delete("key1")
	require.NoError(t, err)

	_, found, err := s.Get("key1")
	require.NoError(t, err)
	assert.False(t, found)
}

func TestMemStorage_KeySet(t *testing.T) {
	t.Parallel()

	s := NewMemStorage()
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.Set("a:1", []byte("v1")))
	require.NoError(t, s.Set("a:2", []byte("v2")))
	require.NoError(t, s.Set("b:1", []byte("v3")))

	keys := s.KeySet()
	assert.Len(t, keys, 3)
}

func TestMemStorage_DeleteAll(t *testing.T) {
	t.Parallel()

	s := NewMemStorage()
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.Set("key1", []byte("v1")))
	require.NoError(t, s.Set("key2", []byte("v2")))

	err := s.DeleteAll()
	require.NoError(t, err)

	keys := s.KeySet()
	assert.Empty(t, keys)
}

func TestMemStorage_CopiesData(t *testing.T) {
	t.Parallel()

	s := NewMemStorage()
	t.Cleanup(func() { _ = s.Close() })

	original := []byte("original")
	require.NoError(t, s.Set("key", original))

	// Modify original
	original[0] = 'X'

	// Loaded data should be unchanged
	loaded, _, err := s.Get("key")
	require.NoError(t, err)
	assert.Equal(t, byte('o'), loaded[0])

	// Modify loaded data
	loaded[0] = 'Y'

	// Load again should be unchanged
	loaded2, _, err := s.Get("key")
	require.NoError(t, err)
	assert.Equal(t, byte('o'), loaded2[0])
}

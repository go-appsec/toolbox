package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemStorage_SaveAndLoad(t *testing.T) {
	t.Parallel()

	s := NewMemStorage()
	t.Cleanup(s.Close)

	// Save
	err := s.Save("key1", []byte("value1"))
	require.NoError(t, err)

	// Load
	data, found, err := s.Load("key1")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, []byte("value1"), data)
}

func TestMemStorage_LoadNotFound(t *testing.T) {
	t.Parallel()

	s := NewMemStorage()
	t.Cleanup(s.Close)

	data, found, err := s.Load("nonexistent")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, data)
}

func TestMemStorage_Delete(t *testing.T) {
	t.Parallel()

	s := NewMemStorage()
	t.Cleanup(s.Close)

	_ = s.Save("key1", []byte("value1"))

	err := s.Delete("key1")
	require.NoError(t, err)

	_, found, _ := s.Load("key1")
	assert.False(t, found)
}

func TestMemStorage_ListKeys(t *testing.T) {
	t.Parallel()

	s := NewMemStorage()
	t.Cleanup(s.Close)

	_ = s.Save("a:1", []byte("v1"))
	_ = s.Save("a:2", []byte("v2"))
	_ = s.Save("b:1", []byte("v3"))

	keys, err := s.ListKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 3)
}

func TestMemStorage_Clear(t *testing.T) {
	t.Parallel()

	s := NewMemStorage()
	t.Cleanup(s.Close)

	_ = s.Save("key1", []byte("v1"))
	_ = s.Save("key2", []byte("v2"))

	err := s.Clear()
	require.NoError(t, err)

	keys, _ := s.ListKeys()
	assert.Empty(t, keys)
}

func TestMemStorage_CopiesData(t *testing.T) {
	t.Parallel()

	s := NewMemStorage()
	t.Cleanup(s.Close)

	original := []byte("original")
	_ = s.Save("key", original)

	// Modify original
	original[0] = 'X'

	// Loaded data should be unchanged
	loaded, _, _ := s.Load("key")
	assert.Equal(t, byte('o'), loaded[0])

	// Modify loaded data
	loaded[0] = 'Y'

	// Load again should be unchanged
	loaded2, _, _ := s.Load("key")
	assert.Equal(t, byte('o'), loaded2[0])
}

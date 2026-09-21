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

func TestPrefixedStorage(t *testing.T) {
	t.Parallel()

	base := NewMemStorage()
	t.Cleanup(func() { _ = base.Close() })
	a := NewPrefixedStorage(base, "a:")
	b := NewPrefixedStorage(base, "b:")

	// Same key in different namespaces stays isolated
	require.NoError(t, a.Set("k1", []byte("va")))
	require.NoError(t, b.Set("k1", []byte("vb")))
	data, found, err := a.Get("k1")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, []byte("va"), data)

	// Keys are unprefixed to the caller and filtered within the namespace
	require.NoError(t, a.Set("k2", []byte("v2")))
	assert.ElementsMatch(t, []string{"k1", "k2"}, a.Keys(""))
	assert.Equal(t, []string{"k2"}, a.Keys("k2"))
	assert.ElementsMatch(t, []string{"k1"}, b.Keys(""))
	assert.Equal(t, 2, a.Size())
	assert.Equal(t, 1, b.Size())

	// Raw base keys carry the namespace prefix
	assert.ElementsMatch(t, []string{"a:k1", "a:k2", "b:k1"}, base.Keys(""))

	// DeleteAll is scoped to the namespace
	require.NoError(t, b.DeleteAll())
	_, found, _ = b.Get("k1")
	assert.False(t, found)
	_, found, _ = a.Get("k1")
	assert.True(t, found)

	// Close is a no-op; the base stays usable
	require.NoError(t, a.Close())
	_, found, _ = base.Get("a:k1")
	assert.True(t, found)
}

func TestPrefixedProvider(t *testing.T) {
	t.Parallel()

	base := NewMemStorage()
	provider, closeFn := PrefixedProvider(base)
	t.Cleanup(func() { _ = closeFn() })

	replay, err := provider("replay")
	require.NoError(t, err)
	notes, err := provider("notes")
	require.NoError(t, err)

	// Namespaces are isolated
	require.NoError(t, replay.Set("x", []byte("1")))
	_, found, err := notes.Get("x")
	require.NoError(t, err)
	assert.False(t, found)

	// The same name resolves to the same data
	again, err := provider("replay")
	require.NoError(t, err)
	data, found, err := again.Get("x")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, []byte("1"), data)

	_, err = provider("")
	assert.Error(t, err)
}

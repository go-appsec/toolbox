package store

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyIndex(t *testing.T) {
	t.Parallel()

	t.Run("register_and_lookup", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		idx := NewProxyIndex(storage)

		flowID := idx.Register(42)
		assert.NotEmpty(t, flowID)
		assert.Len(t, flowID, 6)

		offset, ok := idx.Offset(flowID)
		require.True(t, ok)
		assert.Equal(t, uint32(42), offset)
	})

	t.Run("dedup_same_offset", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		idx := NewProxyIndex(storage)

		id1 := idx.Register(5)
		id2 := idx.Register(5)

		assert.Equal(t, id1, id2)
		assert.Equal(t, 1, idx.Count())
	})

	t.Run("offset_not_found", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		idx := NewProxyIndex(storage)

		_, ok := idx.Offset("nonexistent")
		assert.False(t, ok)
	})

	t.Run("clear", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		idx := NewProxyIndex(storage)

		idx.Register(0)
		idx.Register(1)
		idx.Register(2)
		assert.Equal(t, 3, idx.Count())

		idx.Clear()
		assert.Equal(t, 0, idx.Count())

		// Verify lookups fail after clear
		_, ok := idx.Offset("anything")
		assert.False(t, ok)
	})

	t.Run("count", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		idx := NewProxyIndex(storage)

		assert.Equal(t, 0, idx.Count())

		idx.Register(0)
		assert.Equal(t, 1, idx.Count())

		idx.Register(1)
		assert.Equal(t, 2, idx.Count())

		// Same offset should not increase count
		idx.Register(0)
		assert.Equal(t, 2, idx.Count())
	})
}

func TestProxyIndexConcurrency(t *testing.T) {
	t.Parallel()

	storage := NewMemStorage()
	t.Cleanup(func() { _ = storage.Close() })
	idx := NewProxyIndex(storage)
	var wg sync.WaitGroup

	// Concurrent registrations
	for i := range 100 {
		wg.Add(1)
		go func(offset uint32) {
			defer wg.Done()
			idx.Register(offset)
		}(uint32(i))
	}

	// Concurrent lookups and counts
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			idx.Count()
		}()
	}

	wg.Wait()

	assert.Equal(t, 100, idx.Count())
}

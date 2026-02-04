package store

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore(t *testing.T) {
	t.Parallel()

	t.Run("register_and_lookup", func(t *testing.T) {
		store := NewFlowStore()

		flowID := store.Register(0, "hash1", "proxy")
		assert.NotEmpty(t, flowID)
		assert.Len(t, flowID, 6) // default ID length

		entry, ok := store.Lookup(flowID)
		require.True(t, ok)
		assert.Equal(t, uint32(0), entry.Offset)
		assert.Equal(t, "hash1", entry.Hash)
		assert.Equal(t, "proxy", entry.Source)
	})

	t.Run("register_with_source", func(t *testing.T) {
		store := NewFlowStore()

		proxyID := store.Register(0, "hash1", "proxy")
		replayID := store.Register(1, "hash2", "replay")

		proxyEntry, _ := store.Lookup(proxyID)
		assert.Equal(t, "proxy", proxyEntry.Source)

		replayEntry, _ := store.Lookup(replayID)
		assert.Equal(t, "replay", replayEntry.Source)
	})

	t.Run("register_known", func(t *testing.T) {
		store := NewFlowStore()

		// Register a known flowID (like from replay)
		store.RegisterKnown("replay123", "replay")

		entry, ok := store.Lookup("replay123")
		require.True(t, ok)
		assert.Equal(t, "replay", entry.Source)
		assert.Equal(t, uint32(0), entry.Offset) // replays don't have offsets
	})

	t.Run("register_known_idempotent", func(t *testing.T) {
		store := NewFlowStore()

		// Register same ID twice
		store.RegisterKnown("replay456", "replay")
		store.RegisterKnown("replay456", "replay")

		assert.Equal(t, 1, store.Count())
	})

	t.Run("register_known_no_offset_collision", func(t *testing.T) {
		store := NewFlowStore()

		// Multiple replays should not collide (unlike offset-based Register)
		store.RegisterKnown("replayA", "replay")
		store.RegisterKnown("replayB", "replay")
		store.RegisterKnown("replayC", "replay")

		assert.Equal(t, 3, store.Count())

		_, ok := store.Lookup("replayA")
		assert.True(t, ok)
		_, ok = store.Lookup("replayB")
		assert.True(t, ok)
		_, ok = store.Lookup("replayC")
		assert.True(t, ok)
	})

	t.Run("lookup_not_found", func(t *testing.T) {
		store := NewFlowStore()

		entry, ok := store.Lookup("nonexistent")
		assert.False(t, ok)
		assert.Nil(t, entry)
	})

	t.Run("register_same_offset_returns_same_id", func(t *testing.T) {
		store := NewFlowStore()

		id1 := store.Register(5, "hash1", "proxy")
		id2 := store.Register(5, "hash2", "proxy") // different hash, same offset

		assert.Equal(t, id1, id2)
	})

	t.Run("lookup_by_hash", func(t *testing.T) {
		store := NewFlowStore()

		flowID := store.Register(0, "unique_hash", "proxy")
		flowIDs := store.LookupByHash("unique_hash")

		require.Len(t, flowIDs, 1)
		assert.Equal(t, flowID, flowIDs[0])
	})

	t.Run("lookup_by_hash_not_found", func(t *testing.T) {
		store := NewFlowStore()

		flowIDs := store.LookupByHash("nonexistent")
		assert.Nil(t, flowIDs)
	})

	t.Run("lookup_by_hash_collision", func(t *testing.T) {
		store := NewFlowStore()

		// Register two entries with the same hash (simulating collision)
		id1 := store.Register(0, "same_hash", "proxy")
		id2 := store.Register(1, "same_hash", "proxy")

		flowIDs := store.LookupByHash("same_hash")
		require.Len(t, flowIDs, 2)
		assert.Contains(t, flowIDs, id1)
		assert.Contains(t, flowIDs, id2)
	})

	t.Run("lookup_by_offset", func(t *testing.T) {
		store := NewFlowStore()

		flowID := store.Register(42, "hash", "proxy")
		foundID, ok := store.LookupByOffset(42)

		assert.True(t, ok)
		assert.Equal(t, flowID, foundID)
	})

	t.Run("lookup_by_offset_not_found", func(t *testing.T) {
		store := NewFlowStore()

		foundID, ok := store.LookupByOffset(999)
		assert.False(t, ok)
		assert.Empty(t, foundID)
	})

	t.Run("update_offset", func(t *testing.T) {
		store := NewFlowStore()

		flowID := store.Register(0, "hash", "proxy")

		ok := store.UpdateOffset(flowID, 100)
		assert.True(t, ok)

		entry, _ := store.Lookup(flowID)
		assert.Equal(t, uint32(100), entry.Offset)

		_, found := store.LookupByOffset(0)
		assert.False(t, found)

		foundID, found := store.LookupByOffset(100)
		assert.True(t, found)
		assert.Equal(t, flowID, foundID)
	})

	t.Run("update_offset_not_found", func(t *testing.T) {
		store := NewFlowStore()

		ok := store.UpdateOffset("nonexistent", 100)
		assert.False(t, ok)
	})

	t.Run("clear", func(t *testing.T) {
		store := NewFlowStore()

		store.Register(0, "hash1", "proxy")
		store.Register(1, "hash2", "proxy")
		store.Register(2, "hash3", "proxy")

		assert.Equal(t, 3, store.Count())

		store.Clear()

		assert.Equal(t, 0, store.Count())
	})

	t.Run("clear_by_source", func(t *testing.T) {
		store := NewFlowStore()

		// Register mixed sources
		proxyID1 := store.Register(0, "hash1", "proxy")
		proxyID2 := store.Register(1, "hash2", "proxy")
		store.RegisterKnown("replay1", "replay")
		store.RegisterKnown("replay2", "replay")

		assert.Equal(t, 4, store.Count())

		// Clear only proxy entries
		store.ClearBySource("proxy")

		// Only replay entries should remain
		assert.Equal(t, 2, store.Count())

		_, ok := store.Lookup(proxyID1)
		assert.False(t, ok)
		_, ok = store.Lookup(proxyID2)
		assert.False(t, ok)

		_, ok = store.Lookup("replay1")
		assert.True(t, ok)
		_, ok = store.Lookup("replay2")
		assert.True(t, ok)

		// Offset index should be cleared for proxy entries
		_, ok = store.LookupByOffset(0)
		assert.False(t, ok)
		_, ok = store.LookupByOffset(1)
		assert.False(t, ok)

		// Hash index should be cleared for proxy entries
		ids := store.LookupByHash("hash1")
		assert.Empty(t, ids)
	})

	t.Run("count", func(t *testing.T) {
		store := NewFlowStore()

		assert.Equal(t, 0, store.Count())

		store.Register(0, "hash1", "proxy")
		assert.Equal(t, 1, store.Count())

		store.Register(1, "hash2", "proxy")
		assert.Equal(t, 2, store.Count())

		// Same offset should not increase count
		store.Register(0, "hash3", "proxy")
		assert.Equal(t, 2, store.Count())
	})

	t.Run("all_flow_ids", func(t *testing.T) {
		store := NewFlowStore()

		id1 := store.Register(0, "hash1", "proxy")
		id2 := store.Register(1, "hash2", "proxy")
		id3 := store.Register(2, "hash3", "proxy")

		allIDs := store.AllFlowIDs()
		assert.Len(t, allIDs, 3)
		assert.Contains(t, allIDs, id1)
		assert.Contains(t, allIDs, id2)
		assert.Contains(t, allIDs, id3)
	})

	t.Run("empty_hash", func(t *testing.T) {
		store := NewFlowStore()

		flowID := store.Register(0, "", "proxy")

		// Should still work
		entry, ok := store.Lookup(flowID)
		require.True(t, ok)
		assert.Empty(t, entry.Hash)

		// But hash lookup should return nothing
		flowIDs := store.LookupByHash("")
		assert.Nil(t, flowIDs)
	})
}

func TestStoreConcurrency(t *testing.T) {
	t.Parallel()

	store := NewFlowStore()
	var wg sync.WaitGroup

	// Concurrent registrations
	for i := range 100 {
		wg.Add(1)
		go func(offset uint32) {
			defer wg.Done()
			store.Register(offset, "hash", "proxy")
		}(uint32(i))
	}

	// Concurrent lookups
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Count()
			store.AllFlowIDs()
		}()
	}

	wg.Wait()

	// Verify final state
	assert.Equal(t, 100, store.Count())
}

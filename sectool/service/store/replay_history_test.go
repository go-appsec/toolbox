package store

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplayHistoryStore(t *testing.T) {
	t.Parallel()

	t.Run("store_and_get", func(t *testing.T) {
		store := NewReplayHistoryStore()

		entry := &ReplayHistoryEntry{
			FlowID:          "abc123",
			ReferenceOffset: 10,
			Method:          "POST",
			Host:            "example.com",
			Path:            "/api/test",
			RespStatus:      200,
		}
		store.Store(entry)

		got, ok := store.Get("abc123")
		require.True(t, ok)
		assert.Equal(t, "abc123", got.FlowID)
		assert.Equal(t, uint32(10), got.ReferenceOffset)
		assert.Equal(t, "POST", got.Method)
		assert.Equal(t, "example.com", got.Host)
		assert.Equal(t, "/api/test", got.Path)
		assert.Equal(t, 200, got.RespStatus)
		assert.False(t, got.CreatedAt.IsZero())
	})

	t.Run("get_not_found", func(t *testing.T) {
		store := NewReplayHistoryStore()

		_, ok := store.Get("nonexistent")
		assert.False(t, ok)
	})

	t.Run("list_ordered_by_creation", func(t *testing.T) {
		store := NewReplayHistoryStore()

		store.Store(&ReplayHistoryEntry{FlowID: "first", CreatedAt: time.Now()})
		time.Sleep(time.Millisecond)
		store.Store(&ReplayHistoryEntry{FlowID: "second", CreatedAt: time.Now()})
		time.Sleep(time.Millisecond)
		store.Store(&ReplayHistoryEntry{FlowID: "third", CreatedAt: time.Now()})

		list := store.List()
		require.Len(t, list, 3)
		assert.Equal(t, "first", list[0].FlowID)
		assert.Equal(t, "second", list[1].FlowID)
		assert.Equal(t, "third", list[2].FlowID)
	})

	t.Run("count", func(t *testing.T) {
		store := NewReplayHistoryStore()

		assert.Equal(t, 0, store.Count())

		store.Store(&ReplayHistoryEntry{FlowID: "a"})
		assert.Equal(t, 1, store.Count())

		store.Store(&ReplayHistoryEntry{FlowID: "b"})
		assert.Equal(t, 2, store.Count())
	})

	t.Run("clear", func(t *testing.T) {
		store := NewReplayHistoryStore()

		store.Store(&ReplayHistoryEntry{FlowID: "a"})
		store.Store(&ReplayHistoryEntry{FlowID: "b"})
		assert.Equal(t, 2, store.Count())

		store.Clear()
		assert.Equal(t, 0, store.Count())

		_, ok := store.Get("a")
		assert.False(t, ok)
	})

	t.Run("update_reference_offset_increasing", func(t *testing.T) {
		store := NewReplayHistoryStore()

		// Simulate increasing offsets
		ref1, cleared1 := store.UpdateReferenceOffset(10)
		assert.Equal(t, uint32(10), ref1)
		assert.False(t, cleared1)

		ref2, cleared2 := store.UpdateReferenceOffset(20)
		assert.Equal(t, uint32(20), ref2)
		assert.False(t, cleared2)

		ref3, cleared3 := store.UpdateReferenceOffset(30)
		assert.Equal(t, uint32(30), ref3)
		assert.False(t, cleared3)
	})

	t.Run("history_clear_detection", func(t *testing.T) {
		store := NewReplayHistoryStore()

		// Simulate normal flow
		_, cleared1 := store.UpdateReferenceOffset(100)
		assert.False(t, cleared1)
		store.Store(&ReplayHistoryEntry{FlowID: "before_clear", ReferenceOffset: 100})

		// Simulate history clear (offset decreases)
		_, cleared2 := store.UpdateReferenceOffset(5)
		assert.True(t, cleared2)

		// Existing entries should have ReferenceOffset=0
		entry, ok := store.Get("before_clear")
		require.True(t, ok)
		assert.Equal(t, uint32(0), entry.ReferenceOffset)
	})

	t.Run("history_clear_multiple_entries", func(t *testing.T) {
		store := NewReplayHistoryStore()

		// Add entries at various reference points
		ref1, _ := store.UpdateReferenceOffset(50)
		store.Store(&ReplayHistoryEntry{FlowID: "e1", ReferenceOffset: ref1})

		ref2, _ := store.UpdateReferenceOffset(100)
		store.Store(&ReplayHistoryEntry{FlowID: "e2", ReferenceOffset: ref2})

		ref3, _ := store.UpdateReferenceOffset(150)
		store.Store(&ReplayHistoryEntry{FlowID: "e3", ReferenceOffset: ref3})

		// Verify entries have their offsets
		e1, _ := store.Get("e1")
		e2, _ := store.Get("e2")
		e3, _ := store.Get("e3")
		assert.Equal(t, uint32(50), e1.ReferenceOffset)
		assert.Equal(t, uint32(100), e2.ReferenceOffset)
		assert.Equal(t, uint32(150), e3.ReferenceOffset)

		// Simulate history clear
		_, cleared := store.UpdateReferenceOffset(10)
		assert.True(t, cleared)

		// All entries should now have ReferenceOffset=0
		e1, _ = store.Get("e1")
		e2, _ = store.Get("e2")
		e3, _ = store.Get("e3")
		assert.Equal(t, uint32(0), e1.ReferenceOffset)
		assert.Equal(t, uint32(0), e2.ReferenceOffset)
		assert.Equal(t, uint32(0), e3.ReferenceOffset)
	})

	t.Run("auto_set_created_at", func(t *testing.T) {
		store := NewReplayHistoryStore()

		entry := &ReplayHistoryEntry{FlowID: "auto_time"}
		store.Store(entry)

		got, _ := store.Get("auto_time")
		assert.False(t, got.CreatedAt.IsZero())
		assert.WithinDuration(t, time.Now(), got.CreatedAt, time.Second)
	})

	t.Run("preserve_explicit_created_at", func(t *testing.T) {
		store := NewReplayHistoryStore()

		explicit := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
		entry := &ReplayHistoryEntry{FlowID: "explicit_time", CreatedAt: explicit}
		store.Store(entry)

		got, _ := store.Get("explicit_time")
		assert.Equal(t, explicit, got.CreatedAt)
	})
}

func TestReplayHistoryStoreConcurrency(t *testing.T) {
	t.Parallel()

	store := NewReplayHistoryStore()
	var wg sync.WaitGroup

	// Concurrent stores
	for i := range 100 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			store.Store(&ReplayHistoryEntry{
				FlowID:          string(rune('a'+id%26)) + string(rune('0'+id)),
				ReferenceOffset: uint32(id),
			})
		}(i)
	}

	// Concurrent reads
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Count()
			store.List()
		}()
	}

	// Concurrent offset updates
	for i := range 50 {
		wg.Add(1)
		go func(offset uint32) {
			defer wg.Done()
			_, _ = store.UpdateReferenceOffset(offset)
		}(uint32(i * 10))
	}

	wg.Wait()

	assert.Equal(t, 100, store.Count())
}

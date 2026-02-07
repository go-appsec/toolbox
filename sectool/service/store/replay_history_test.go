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
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

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
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		_, ok := store.Get("nonexistent")
		assert.False(t, ok)
	})

	t.Run("list_ordered_by_creation", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

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
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		assert.Equal(t, 0, store.Count())

		store.Store(&ReplayHistoryEntry{FlowID: "a"})
		assert.Equal(t, 1, store.Count())

		store.Store(&ReplayHistoryEntry{FlowID: "b"})
		assert.Equal(t, 2, store.Count())
	})

	t.Run("clear", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		store.Store(&ReplayHistoryEntry{FlowID: "a"})
		store.Store(&ReplayHistoryEntry{FlowID: "b"})
		assert.Equal(t, 2, store.Count())

		store.Clear()
		assert.Equal(t, 0, store.Count())

		_, ok := store.Get("a")
		assert.False(t, ok)
	})

	t.Run("update_reference_offset_increasing", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

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
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

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
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

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
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		entry := &ReplayHistoryEntry{FlowID: "auto_time"}
		store.Store(entry)

		got, _ := store.Get("auto_time")
		assert.False(t, got.CreatedAt.IsZero())
		assert.WithinDuration(t, time.Now(), got.CreatedAt, time.Second)
	})

	t.Run("preserve_explicit_created_at", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		explicit := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
		entry := &ReplayHistoryEntry{FlowID: "explicit_time", CreatedAt: explicit}
		store.Store(entry)

		got, _ := store.Get("explicit_time")
		assert.True(t, explicit.Equal(got.CreatedAt))
	})
}

func TestReplayHistoryListMeta(t *testing.T) {
	t.Parallel()

	t.Run("returns_meta_only", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		store.Store(&ReplayHistoryEntry{
			FlowID:     "r1",
			Method:     "POST",
			Host:       "example.com",
			Path:       "/api",
			Protocol:   "http/1.1",
			RespStatus: 200,
			RespBody:   []byte("body-data"),
			RawRequest: []byte("POST /api HTTP/1.1\r\n\r\n"),
			CreatedAt:  time.Now(),
		})
		time.Sleep(time.Millisecond)
		store.Store(&ReplayHistoryEntry{
			FlowID:       "r2",
			Method:       "GET",
			Host:         "other.com",
			Path:         "/test",
			RespStatus:   404,
			RespBody:     []byte("not found"),
			SourceFlowID: "p1",
			CreatedAt:    time.Now(),
		})

		metas := store.ListMeta()
		require.Len(t, metas, 2)

		assert.Equal(t, "r1", metas[0].FlowID)
		assert.Equal(t, "POST", metas[0].Method)
		assert.Equal(t, "example.com", metas[0].Host)
		assert.Equal(t, "/api", metas[0].Path)
		assert.Equal(t, 200, metas[0].RespStatus)
		assert.Equal(t, len("body-data"), metas[0].RespLen)

		assert.Equal(t, "r2", metas[1].FlowID)
		assert.Equal(t, "p1", metas[1].SourceFlowID)
		assert.Equal(t, 404, metas[1].RespStatus)
	})

	t.Run("ordered_by_creation", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		store.Store(&ReplayHistoryEntry{FlowID: "first", CreatedAt: time.Now()})
		time.Sleep(time.Millisecond)
		store.Store(&ReplayHistoryEntry{FlowID: "second", CreatedAt: time.Now()})

		metas := store.ListMeta()
		require.Len(t, metas, 2)
		assert.Equal(t, "first", metas[0].FlowID)
		assert.Equal(t, "second", metas[1].FlowID)
	})

	t.Run("empty_store", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		metas := store.ListMeta()
		assert.Empty(t, metas)
	})
}

func TestReplayHistoryCountExcludesPayload(t *testing.T) {
	t.Parallel()

	storage := NewMemStorage()
	t.Cleanup(func() { _ = storage.Close() })
	store := NewReplayHistoryStore(storage)

	store.Store(&ReplayHistoryEntry{
		FlowID:   "a",
		RespBody: []byte("large body data"),
	})
	store.Store(&ReplayHistoryEntry{
		FlowID:   "b",
		RespBody: []byte("another body"),
	})

	// Count should reflect 2 entries, not 4 keys (meta + payload each)
	assert.Equal(t, 2, store.Count())
}

func TestReplayHistoryPayloadIsolation(t *testing.T) {
	t.Parallel()

	storage := NewMemStorage()
	t.Cleanup(func() { _ = storage.Close() })
	store := NewReplayHistoryStore(storage)

	store.Store(&ReplayHistoryEntry{
		FlowID:      "flow1",
		Method:      "POST",
		RawRequest:  []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		RespHeaders: []byte("HTTP/1.1 200 OK\r\n\r\n"),
		RespBody:    []byte("response body"),
	})

	// ListMeta should not contain payload data
	metas := store.ListMeta()
	require.Len(t, metas, 1)
	assert.Equal(t, "flow1", metas[0].FlowID)
	assert.Equal(t, "POST", metas[0].Method)
	assert.Equal(t, len("response body"), metas[0].RespLen)

	// Get should reconstruct full entry
	entry, ok := store.Get("flow1")
	require.True(t, ok)
	assert.Equal(t, []byte("POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n"), entry.RawRequest)
	assert.Equal(t, []byte("HTTP/1.1 200 OK\r\n\r\n"), entry.RespHeaders)
	assert.Equal(t, []byte("response body"), entry.RespBody)
}

func TestReplayHistoryStoreConcurrency(t *testing.T) {
	t.Parallel()

	storage := NewMemStorage()
	t.Cleanup(func() { _ = storage.Close() })
	store := NewReplayHistoryStore(storage)
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

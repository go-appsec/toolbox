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
			FlowID:     "abc123",
			Method:     "POST",
			Host:       "example.com",
			Path:       "/api/test",
			RespStatus: 200,
		}
		store.Store(entry)

		got, ok := store.Get("abc123")
		require.True(t, ok)
		assert.Equal(t, "abc123", got.FlowID)
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

		baseTime := time.Now()
		store.Store(&ReplayHistoryEntry{FlowID: "first", CreatedAt: baseTime})
		store.Store(&ReplayHistoryEntry{FlowID: "second", CreatedAt: baseTime.Add(time.Millisecond)})
		store.Store(&ReplayHistoryEntry{FlowID: "third", CreatedAt: baseTime.Add(2 * time.Millisecond)})

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

	t.Run("created_at_increases_in_store_order", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		baseTime := time.Now()
		store.Store(&ReplayHistoryEntry{FlowID: "first", CreatedAt: baseTime})
		store.Store(&ReplayHistoryEntry{FlowID: "second", CreatedAt: baseTime.Add(time.Millisecond)})

		first, ok := store.Get("first")
		require.True(t, ok)
		second, ok := store.Get("second")
		require.True(t, ok)
		assert.True(t, first.CreatedAt.Before(second.CreatedAt))
	})

	t.Run("auto_set_created_at", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		entry := &ReplayHistoryEntry{FlowID: "auto_time"}
		store.Store(entry)

		got, ok := store.Get("auto_time")
		require.True(t, ok)
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

		got, ok := store.Get("explicit_time")
		require.True(t, ok)
		assert.True(t, explicit.Equal(got.CreatedAt))
	})
}

func TestReplayHistoryComplete(t *testing.T) {
	t.Parallel()

	t.Run("updates_response_and_meta", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		created := time.Now().Add(-time.Second)
		store.Store(&ReplayHistoryEntry{FlowID: "f1", Method: "GET", CreatedAt: created})
		require.Equal(t, 1, store.Count())

		completedAt := created.Add(250 * time.Millisecond)
		require.True(t, store.Complete("f1", []byte("HTTP/1.1 200 OK\r\n\r\n"), []byte("data: one\n\n"), 200, completedAt, nil))

		got, ok := store.Get("f1")
		require.True(t, ok)
		assert.Equal(t, 200, got.RespStatus)
		assert.Equal(t, "data: one\n\n", string(got.RespBody))
		assert.Equal(t, 250*time.Millisecond, got.Duration)

		// Cached meta stays in sync; Complete does not change count
		assert.Equal(t, 1, store.Count())
		metas := store.ListMeta()
		require.Len(t, metas, 1)
		assert.Equal(t, 200, metas[0].RespStatus)
		assert.Equal(t, len("data: one\n\n"), metas[0].RespLen)
		assert.Equal(t, 250*time.Millisecond, metas[0].Duration)
	})

	t.Run("unknown_flow", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)
		assert.False(t, store.Complete("missing", nil, nil, 200, time.Now(), nil))
	})

	t.Run("in_progress_leaves_duration_zero", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		store.Store(&ReplayHistoryEntry{FlowID: "f2", Method: "GET"})
		require.True(t, store.Complete("f2", nil, []byte("partial"), 200, time.Time{}, nil))

		got, ok := store.Get("f2")
		require.True(t, ok)
		assert.Equal(t, "partial", string(got.RespBody))
		assert.Zero(t, got.Duration)
	})

	t.Run("annotations_merged", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		store.Store(&ReplayHistoryEntry{
			FlowID:      "f3",
			Method:      "GET",
			Annotations: map[string]any{"replay": true, "phase": "captured"},
		})
		require.True(t, store.Complete("f3", nil, nil, 200, time.Time{},
			map[string]any{"phase": "mutated", "fired_rules": []string{"r1"}}))

		got, ok := store.Get("f3")
		require.True(t, ok)
		assert.Equal(t, true, got.Annotations["replay"])
		assert.Equal(t, "mutated", got.Annotations["phase"])
		assert.Equal(t, []any{"r1"}, got.Annotations["fired_rules"]) // msgpack decodes slices as []any

		metas := store.ListMeta()
		require.Len(t, metas, 1)
		assert.Equal(t, "mutated", metas[0].Annotations["phase"])
	})
}

func TestReplayHistorySetInvokedBy(t *testing.T) {
	t.Parallel()

	t.Run("sets_and_round_trips", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		store.Store(&ReplayHistoryEntry{FlowID: "f1", Method: "GET"})
		require.True(t, store.SetInvokedBy("f1", "httpsidecar"))

		got, ok := store.Get("f1")
		require.True(t, ok)
		assert.Equal(t, "httpsidecar", got.InvokedBy)

		metas := store.ListMeta()
		require.Len(t, metas, 1)
		assert.Equal(t, "httpsidecar", metas[0].InvokedBy)
	})

	t.Run("unknown_flow", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)
		assert.False(t, store.SetInvokedBy("missing", "httpsidecar"))
	})
}

func TestReplayHistoryListMeta(t *testing.T) {
	t.Parallel()

	t.Run("returns_meta_only", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		baseTime := time.Now()
		store.Store(&ReplayHistoryEntry{
			FlowID:     "r1",
			Method:     "POST",
			Host:       "example.com",
			Path:       "/api",
			Protocol:   "http/1.1",
			RespStatus: 200,
			RespBody:   []byte("body-data"),
			RawRequest: []byte("POST /api HTTP/1.1\r\n\r\n"),
			CreatedAt:  baseTime,
		})
		store.Store(&ReplayHistoryEntry{
			FlowID:       "r2",
			Method:       "GET",
			Host:         "other.com",
			Path:         "/test",
			RespStatus:   404,
			RespBody:     []byte("not found"),
			SourceFlowID: "p1",
			CreatedAt:    baseTime.Add(time.Millisecond),
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

		baseTime := time.Now()
		store.Store(&ReplayHistoryEntry{FlowID: "first", CreatedAt: baseTime})
		store.Store(&ReplayHistoryEntry{FlowID: "second", CreatedAt: baseTime.Add(time.Millisecond)})

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

func TestReplayHistoryDelete(t *testing.T) {
	t.Parallel()

	t.Run("empty_input", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		store.Store(&ReplayHistoryEntry{FlowID: "a"})
		assert.Equal(t, 0, store.Delete(nil))
		assert.Equal(t, 0, store.Delete([]string{}))
		assert.Equal(t, 1, store.Count())
	})

	t.Run("missing_only", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		store.Store(&ReplayHistoryEntry{FlowID: "a"})
		assert.Equal(t, 0, store.Delete([]string{"x", "y", "z"}))
		assert.Equal(t, 1, store.Count())
	})

	t.Run("single", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		store.Store(&ReplayHistoryEntry{FlowID: "a", RespBody: []byte("body")})

		assert.Equal(t, 1, store.Delete([]string{"a"}))
		assert.Equal(t, 0, store.Count())

		_, ok := store.Get("a")
		assert.False(t, ok)
		// payload key should also be gone
		_, found, _ := storage.Get("a" + replayPayloadSuffix)
		assert.False(t, found)
	})

	t.Run("mixed_known_and_unknown", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		for _, id := range []string{"a", "b", "c", "d", "e"} {
			store.Store(&ReplayHistoryEntry{FlowID: id})
		}
		assert.Equal(t, 5, store.Count())

		assert.Equal(t, 2, store.Delete([]string{"a", "missing", "c"}))
		assert.Equal(t, 3, store.Count())

		_, okA := store.Get("a")
		_, okB := store.Get("b")
		_, okC := store.Get("c")
		assert.False(t, okA)
		assert.True(t, okB)
		assert.False(t, okC)
	})

	t.Run("all", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		ids := []string{"a", "b", "c"}
		for _, id := range ids {
			store.Store(&ReplayHistoryEntry{FlowID: id})
		}

		assert.Equal(t, 3, store.Delete(ids))
		assert.Equal(t, 0, store.Count())
		assert.Empty(t, store.List())
	})

	t.Run("idempotent_double_delete", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		store := NewReplayHistoryStore(storage)

		store.Store(&ReplayHistoryEntry{FlowID: "a"})
		assert.Equal(t, 1, store.Delete([]string{"a"}))
		assert.Equal(t, 0, store.Delete([]string{"a"}))
		assert.Equal(t, 0, store.Count())
	})
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
				FlowID: string(rune('a'+id%26)) + string(rune('0'+id)),
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

	wg.Wait()

	assert.Equal(t, 100, store.Count())
}

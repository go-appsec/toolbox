package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestStoreStoreAndGet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		entry    *RequestEntry
		assertFn func(t *testing.T, entry *RequestEntry)
	}{
		{
			name: "sets_created_time_when_zero",
			entry: &RequestEntry{
				Headers:  []byte("h1"),
				Body:     []byte("body"),
				Duration: time.Second,
			},
			assertFn: func(t *testing.T, entry *RequestEntry) {
				t.Helper()
				
				assert.NotZero(t, entry.CreatedAt)
				assert.InDelta(t, time.Now().Unix(), entry.CreatedAt.Unix(), 1)
			},
		},
		{
			name: "preserves_existing_created_time",
			entry: &RequestEntry{
				Headers:   []byte("h2"),
				Body:      []byte("body2"),
				Duration:  time.Minute,
				CreatedAt: time.Unix(100, 0),
			},
			assertFn: func(t *testing.T, entry *RequestEntry) {
				t.Helper()
				
				assert.Equal(t, time.Unix(100, 0), entry.CreatedAt)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewRequestStore()

			store.Store("id", tt.entry)
			stored, ok := store.Get("id")
			require.True(t, ok)

			assert.Equal(t, tt.entry.Headers, stored.Headers)
			assert.Equal(t, tt.entry.Body, stored.Body)
			assert.Equal(t, tt.entry.Duration, stored.Duration)
			tt.assertFn(t, stored)
		})
	}
}

func TestRequestStoreDelete(t *testing.T) {
	t.Parallel()

	store := NewRequestStore()

	store.Store("delete", &RequestEntry{})
	assert.Equal(t, 1, store.Count())

	store.Delete("delete")
	_, ok := store.Get("delete")
	assert.False(t, ok)
	assert.Equal(t, 0, store.Count())
}

func TestRequestStoreCount(t *testing.T) {
	t.Parallel()

	store := NewRequestStore()

	store.Store("one", &RequestEntry{})
	store.Store("two", &RequestEntry{})

	assert.Equal(t, 2, store.Count())
}

func TestRequestStoreClear(t *testing.T) {
	t.Parallel()

	store := NewRequestStore()

	store.Store("one", &RequestEntry{})
	store.Store("two", &RequestEntry{})

	store.Clear()

	assert.Equal(t, 0, store.Count())
	_, ok := store.Get("one")
	assert.False(t, ok)
}

package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/toolbox/sectool/service/store"
)

func TestShouldCapture(t *testing.T) {
	t.Parallel()

	t.Run("no_filter", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		entry := &HistoryEntry{
			Protocol: "http/1.1",
			Request:  &RawHTTP1Request{Method: "GET", Path: "/style.css"},
		}
		assert.True(t, h.ShouldCapture(entry))
	})

	t.Run("filter_allows", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)
		h.SetCaptureFilter(func(e *HistoryEntry) bool { return true })

		entry := &HistoryEntry{
			Protocol: "http/1.1",
			Request:  &RawHTTP1Request{Method: "GET", Path: "/api/data"},
		}
		assert.True(t, h.ShouldCapture(entry))
	})

	t.Run("filter_rejects", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)
		h.SetCaptureFilter(func(e *HistoryEntry) bool { return false })

		entry := &HistoryEntry{
			Protocol: "http/1.1",
			Request:  &RawHTTP1Request{Method: "GET", Path: "/logo.png"},
		}
		assert.False(t, h.ShouldCapture(entry))
	})
}

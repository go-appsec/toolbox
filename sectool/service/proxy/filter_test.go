package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

func TestShouldCapture(t *testing.T) {
	t.Parallel()

	t.Run("no_filter", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		flow := &types.Flow{
			ProtocolTag: types.ProtocolHTTP11,
			Request:     &types.Message{Method: "GET", Path: "/style.css"},
		}
		assert.True(t, h.ShouldCapture(flow))
	})

	t.Run("filter_allows", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)
		h.SetCaptureFilter(func(f *types.Flow) bool { return true })

		flow := &types.Flow{
			ProtocolTag: types.ProtocolHTTP11,
			Request:     &types.Message{Method: "GET", Path: "/api/data"},
		}
		assert.True(t, h.ShouldCapture(flow))
	})

	t.Run("filter_rejects", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)
		h.SetCaptureFilter(func(f *types.Flow) bool { return false })

		flow := &types.Flow{
			ProtocolTag: types.ProtocolHTTP11,
			Request:     &types.Message{Method: "GET", Path: "/logo.png"},
		}
		assert.False(t, h.ShouldCapture(flow))
	})
}

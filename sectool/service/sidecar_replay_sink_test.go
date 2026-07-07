package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// fakeFlowSink is an in-memory FlowSink standing in for the proxy HistoryStore.
type fakeFlowSink struct {
	flows map[string]*types.Flow
	seq   int
}

func newFakeFlowSink() *fakeFlowSink { return &fakeFlowSink{flows: map[string]*types.Flow{}} }

func (s *fakeFlowSink) Store(flow *types.Flow) string {
	s.seq++
	id := "proxy" + string(rune('0'+s.seq))
	flow.FlowID = id
	s.flows[id] = flow
	return id
}

func (s *fakeFlowSink) Complete(flowID string, resp *types.Message, _ time.Time, _ map[string]any) bool {
	f, ok := s.flows[flowID]
	if !ok {
		return false
	}
	f.Response = resp
	return true
}

func (s *fakeFlowSink) SetInvokedBy(flowID, invokedBy string) bool {
	f, ok := s.flows[flowID]
	if ok {
		f.InvokedBy = invokedBy
	}
	return ok
}

func (s *fakeFlowSink) Get(flowID string) (*types.Flow, bool) {
	f, ok := s.flows[flowID]
	return f, ok
}

func (s *fakeFlowSink) ShouldCapture(*types.Flow) bool { return true }

func replayFlow() *types.Flow {
	now := time.Now()
	return &types.Flow{
		Adapter:      "httpsidecar-tls",
		ProtocolTag:  "http/1.1",
		ParentFlowID: "src123",
		Scheme:       "https",
		Port:         443,
		Request: &types.Message{
			Method:  "GET",
			Path:    "/x",
			Version: "HTTP/1.1",
			Headers: types.Headers{{Name: "Host", Value: "other.test"}},
		},
		Response: &types.Message{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Headers:    types.Headers{{Name: "Content-Type", Value: "text/plain"}},
			Body:       []byte("hello"),
		},
		StartedAt:   now,
		CompletedAt: now,
		Annotations: map[string]any{wire.AnnotationReplay: true},
	}
}

func TestReplayRoutingSink(t *testing.T) {
	t.Parallel()

	t.Run("replay_flow_routed_to_replay_store", func(t *testing.T) {
		history := newFakeFlowSink()
		replay := store.NewReplayHistoryStore(store.NewMemStorage())
		sink := &replayRoutingSink{history: history, replay: replay}

		id := sink.Store(replayFlow())
		require.NotEmpty(t, id)
		assert.Empty(t, history.flows, "replay must not land in proxy history")

		entry, ok := replay.Get(id)
		require.True(t, ok)
		assert.Equal(t, "httpsidecar-tls", entry.Adapter)
		assert.Equal(t, "src123", entry.SourceFlowID)
		assert.Equal(t, "other.test", entry.Host)
		assert.Equal(t, "/x", entry.Path)
		assert.Equal(t, 200, entry.RespStatus)
		assert.Contains(t, string(entry.RespBody), "hello")
	})

	t.Run("non_replay_flow_delegates_to_history", func(t *testing.T) {
		history := newFakeFlowSink()
		replay := store.NewReplayHistoryStore(store.NewMemStorage())
		sink := &replayRoutingSink{history: history, replay: replay}

		f := replayFlow()
		f.Annotations = nil // ordinary capture
		id := sink.Store(f)
		_, ok := history.Get(id)
		assert.True(t, ok)
		assert.Equal(t, 0, replay.Count())
	})

	t.Run("get_bridges_to_replay_store", func(t *testing.T) {
		history := newFakeFlowSink()
		replay := store.NewReplayHistoryStore(store.NewMemStorage())
		sink := &replayRoutingSink{history: history, replay: replay}

		id := sink.Store(replayFlow())
		// Not in proxy history, so Get must reconstruct it from the replay store.
		got, ok := sink.Get(id)
		require.True(t, ok)
		assert.Equal(t, "httpsidecar-tls", got.Adapter)
		assert.Equal(t, "GET", got.Request.Method)
		assert.Equal(t, "/x", got.Request.Path)
		assert.Equal(t, "other.test", got.Request.GetHeader("Host"))
	})
}

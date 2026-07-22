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
		CompletedAt: now.Add(100 * time.Millisecond),
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

		f := replayFlow()
		id := sink.Store(f)
		// Not in proxy history, so Get must reconstruct it from the replay store.
		got, ok := sink.Get(id)
		require.True(t, ok)
		assert.Equal(t, "httpsidecar-tls", got.Adapter)
		assert.Equal(t, "GET", got.Request.Method)
		assert.Equal(t, "/x", got.Request.Path)
		assert.Equal(t, "other.test", got.Request.GetHeader("Host"))

		require.NotNil(t, got.Response)
		assert.Equal(t, 200, got.Response.StatusCode)
		assert.Equal(t, "hello", string(got.Response.Body))
		assert.Equal(t, f.CompletedAt.Sub(f.StartedAt), got.CompletedAt.Sub(got.StartedAt))
	})

	t.Run("complete_routes_to_replay_store", func(t *testing.T) {
		history := newFakeFlowSink()
		replay := store.NewReplayHistoryStore(store.NewMemStorage())
		sink := &replayRoutingSink{history: history, replay: replay}

		f := replayFlow()
		f.Response = nil // deferred: response attached later
		f.CompletedAt = time.Time{}
		id := sink.Store(f)

		resp := &types.Message{Version: "HTTP/1.1", StatusCode: 200, StatusText: "OK", Body: []byte("late")}
		completedAt := f.StartedAt.Add(300 * time.Millisecond)
		ok := sink.Complete(id, resp, completedAt, map[string]any{"phase": "mutated"})
		require.True(t, ok)
		assert.Empty(t, history.flows, "replay completion must not touch proxy history")

		entry, ok := replay.Get(id)
		require.True(t, ok)
		assert.Equal(t, 200, entry.RespStatus)
		assert.Contains(t, string(entry.RespBody), "late")
		assert.Equal(t, 300*time.Millisecond, entry.Duration)
		assert.Equal(t, "mutated", entry.Annotations["phase"])
	})

	t.Run("set_invoked_by_replay_flow", func(t *testing.T) {
		history := newFakeFlowSink()
		replay := store.NewReplayHistoryStore(store.NewMemStorage())
		sink := &replayRoutingSink{history: history, replay: replay}

		id := sink.Store(replayFlow())
		require.True(t, sink.SetInvokedBy(id, "caller"))

		entry, ok := replay.Get(id)
		require.True(t, ok)
		assert.Equal(t, "caller", entry.InvokedBy)

		// proxy-owned ids still route to history
		pid := sink.Store(func() *types.Flow { f := replayFlow(); f.Annotations = nil; return f }())
		require.True(t, sink.SetInvokedBy(pid, "caller"))
		pf, ok := history.Get(pid)
		require.True(t, ok)
		assert.Equal(t, "caller", pf.InvokedBy)
	})

	t.Run("get_keeps_h2_unframed_body", func(t *testing.T) {
		history := newFakeFlowSink()
		replay := store.NewReplayHistoryStore(store.NewMemStorage())
		sink := &replayRoutingSink{history: history, replay: replay}

		f := replayFlow()
		f.ProtocolTag = types.ProtocolH2
		f.Request = &types.Message{
			Headers: types.Headers{
				{Name: ":method", Value: "POST"},
				{Name: ":authority", Value: "other.test"},
				{Name: ":path", Value: "/x"},
			},
			Body: []byte(`{"a":1}`),
		}
		id := sink.Store(f)

		got, ok := sink.Get(id)
		require.True(t, ok)
		assert.Equal(t, []byte(`{"a":1}`), got.Request.Body)
	})
}

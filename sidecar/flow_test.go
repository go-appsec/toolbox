package sidecar

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// flowCapture is a fake sectool that records pushed flows and assigns ids, with the
// first assigned id overridable to simulate a capture-filtered flow.
type flowCapture struct {
	mu        sync.Mutex
	pushed    []wire.Flow
	firstID   string // id returned for the first push_flow ("" simulates filtered)
	nextIndex int
}

func (f *flowCapture) handle(method string, params json.RawMessage) (any, *wire.Error) {
	if method == wire.MethodRegister {
		return registerOK(method, params)
	} else if method != wire.MethodPushFlow {
		return nil, wire.NewError(-32601, "no")
	}
	var flow wire.Flow
	_ = json.Unmarshal(params, &flow)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pushed = append(f.pushed, flow)
	id := "f" + strconv.Itoa(f.nextIndex+1)
	if f.nextIndex == 0 {
		id = f.firstID
	}
	f.nextIndex++
	return wire.PushFlowResult{FlowID: id}, nil
}

func TestEmitMutatedPair(t *testing.T) {
	t.Parallel()

	t.Run("links_captured_and_mutated", func(t *testing.T) {
		cap := &flowCapture{firstID: "f1"}
		addr, _ := fakeServer(t, cap.handle)
		conn, err := Dial(t.Context(), addr, Registration{Name: "alpha"})
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		capturedID, mutatedID, err := conn.EmitMutatedPair(ctx,
			wire.Flow{Request: &wire.FlowMessage{Body: []byte("foo")}},
			wire.Flow{ParentFlowID: "stream1", Request: &wire.FlowMessage{Body: []byte("bar")}},
			[]string{"r1"},
		)
		require.NoError(t, err)
		assert.Equal(t, "f1", capturedID)
		assert.Equal(t, "f2", mutatedID)

		cap.mu.Lock()
		defer cap.mu.Unlock()
		require.Len(t, cap.pushed, 2)
		assert.Equal(t, "captured", cap.pushed[0].Annotations["phase"])

		mutated := cap.pushed[1]
		assert.Equal(t, "mutated", mutated.Annotations["phase"])
		assert.Equal(t, "f1", mutated.Annotations["parent_flow_id"])
		assert.Equal(t, []any{"r1"}, mutated.Annotations["fired_rules"])
		// structural parent preserved alongside annotation link
		assert.Equal(t, "stream1", mutated.ParentFlowID)
	})

	t.Run("skips_link_when_captured_filtered", func(t *testing.T) {
		cap := &flowCapture{firstID: ""} // captured flow excluded by capture filter
		addr, _ := fakeServer(t, cap.handle)
		conn, err := Dial(t.Context(), addr, Registration{Name: "alpha"})
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		capturedID, _, err := conn.EmitMutatedPair(t.Context(),
			wire.Flow{Request: &wire.FlowMessage{Body: []byte("foo")}},
			wire.Flow{Request: &wire.FlowMessage{Body: []byte("bar")}},
			[]string{"r1"},
		)
		require.NoError(t, err)
		assert.Empty(t, capturedID)

		cap.mu.Lock()
		defer cap.mu.Unlock()
		require.Len(t, cap.pushed, 2)
		_, hasParent := cap.pushed[1].Annotations["parent_flow_id"]
		assert.False(t, hasParent)
	})
}

func TestPushFlow(t *testing.T) {
	t.Parallel()

	pushOne := func(t *testing.T, flow wire.Flow) wire.Flow {
		t.Helper()
		cap := &flowCapture{firstID: "f1"}
		addr, _ := fakeServer(t, cap.handle)
		conn, err := Dial(t.Context(), addr, Registration{Name: "alpha"})
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		_, err = conn.PushFlow(t.Context(), flow)
		require.NoError(t, err)

		cap.mu.Lock()
		defer cap.mu.Unlock()
		require.Len(t, cap.pushed, 1)
		return cap.pushed[0]
	}

	t.Run("replay_without_response_stays_in_progress", func(t *testing.T) {
		got := pushOne(t, wire.Flow{
			Request:     &wire.FlowMessage{Method: "PUBLISH", Path: "/topic"},
			Annotations: map[string]any{wire.AnnotationReplay: true},
		})
		assert.Nil(t, got.Response)
	})

	t.Run("replay_with_response_unchanged", func(t *testing.T) {
		got := pushOne(t, wire.Flow{
			Request:     &wire.FlowMessage{Method: "GET"},
			Response:    &wire.FlowMessage{StatusCode: 200},
			Annotations: map[string]any{wire.AnnotationReplay: true},
		})
		assert.Equal(t, 200, got.Response.StatusCode)
	})

	t.Run("non_replay_without_response_unchanged", func(t *testing.T) {
		got := pushOne(t, wire.Flow{Request: &wire.FlowMessage{Method: "GET"}})
		assert.Nil(t, got.Response)
	})

	t.Run("two_phase_completion_not_synthesized", func(t *testing.T) {
		got := pushOne(t, wire.Flow{
			FlowID:      "existing",
			Annotations: map[string]any{wire.AnnotationReplay: true},
		})
		assert.Nil(t, got.Response)
	})
}

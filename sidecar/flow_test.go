package sidecar

import (
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

	t.Run("request_without_response_stays_in_progress", func(t *testing.T) {
		got := pushOne(t, wire.Flow{Request: &wire.FlowMessage{Method: "PUBLISH", Path: "/topic"}})
		assert.Nil(t, got.Response)
	})

	t.Run("request_with_response_unchanged", func(t *testing.T) {
		got := pushOne(t, wire.Flow{
			Request:  &wire.FlowMessage{Method: "GET"},
			Response: &wire.FlowMessage{StatusCode: 200},
		})
		assert.Equal(t, 200, got.Response.StatusCode)
	})

	t.Run("two_phase_completion_not_synthesized", func(t *testing.T) {
		got := pushOne(t, wire.Flow{FlowID: "existing"})
		assert.Nil(t, got.Response)
	})
}

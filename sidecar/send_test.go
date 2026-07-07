package sidecar

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

func TestApplyMutations(t *testing.T) {
	t.Parallel()

	t.Run("mixed_ops", func(t *testing.T) {
		msg := &wire.FlowMessage{
			Headers: []wire.Header{{Name: "X-Keep", Value: "1"}, {Name: "X-Drop", Value: "2"}},
			Body:    []byte(`{"a":1,"b":2}`),
		}
		require.NoError(t, ApplyMutations(msg, []wire.Mutation{
			{Op: "remove_header", Name: "x-drop"},
			{Op: "set_header", Name: "X-Keep", Value: "9"},
			{Op: "set_json", Name: "a", Value: "5"},
			{Op: "remove_json", Name: "b"},
		}))
		assert.Equal(t, []wire.Header{{Name: "X-Keep", Value: "9"}}, msg.Headers)
		assert.JSONEq(t, `{"a":5}`, string(msg.Body))
	})

	t.Run("order_sensitive", func(t *testing.T) {
		// body after set_json discards the structured edit
		a := &wire.FlowMessage{Body: []byte(`{}`)}
		require.NoError(t, ApplyMutations(a, []wire.Mutation{
			{Op: "set_json", Name: "a", Value: "1"},
			{Op: "body", Value: "raw"},
		}))
		assert.Equal(t, "raw", string(a.Body))

		// set_json after body edits the replacement body
		b := &wire.FlowMessage{Body: []byte("x")}
		require.NoError(t, ApplyMutations(b, []wire.Mutation{
			{Op: "body", Value: `{"a":0}`},
			{Op: "set_json", Name: "a", Value: "1"},
		}))
		assert.JSONEq(t, `{"a":1}`, string(b.Body))
	})

	t.Run("routing_fields", func(t *testing.T) {
		msg := &wire.FlowMessage{Method: "GET", Path: "/old"}
		require.NoError(t, ApplyMutations(msg, []wire.Mutation{
			{Op: "method", Value: "POST"},
			{Op: "path", Value: "/new"},
			{Op: "set_query", Name: "id", Value: "7"},
		}))
		assert.Equal(t, "POST", msg.Method)
		assert.Equal(t, "/new", msg.Path)
		assert.Equal(t, "id=7", msg.Query)
	})

	t.Run("unknown_op", func(t *testing.T) {
		require.Error(t, ApplyMutations(&wire.FlowMessage{}, []wire.Mutation{{Op: "bogus"}}))
	})
}

// sendFixture is an emit-only handler that echoes the request back.
type sendFixture struct{ BaseHandler }

func (sendFixture) OnShutdown(int) {}
func (sendFixture) OnSidecarSend(p wire.SidecarSendParams) (wire.SidecarSendResult, error) {
	return wire.SidecarSendResult{NewFlowIDs: []string{p.FlowID}}, nil
}

func TestSidecarSendDispatch(t *testing.T) {
	t.Parallel()

	t.Run("routes_to_handler", func(t *testing.T) {
		addr, peerCh := fakeServer(t, registerOK)
		conn, err := Dial(addr, Registration{Name: "demo"})
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		srv := <-peerCh
		go func() { _ = conn.Serve(t.Context(), sendFixture{}) }()

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		t.Cleanup(cancel)
		var res wire.SidecarSendResult
		require.Nil(t, srv.Call(ctx, wire.MethodSidecarSend, wire.SidecarSendParams{FlowID: "src"}, &res))
		assert.Equal(t, []string{"src"}, res.NewFlowIDs)
	})

	t.Run("no_send_handler", func(t *testing.T) {
		addr, peerCh := fakeServer(t, registerOK)
		conn, err := Dial(addr, Registration{Name: "demo"})
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		srv := <-peerCh
		go func() { _ = conn.Serve(t.Context(), nil) }()

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		t.Cleanup(cancel)
		var res wire.SidecarSendResult
		rpcErr := srv.Call(ctx, wire.MethodSidecarSend, wire.SidecarSendParams{}, &res)
		require.NotNil(t, rpcErr)
		assert.Equal(t, wire.CodeTransportInternal, rpcErr.Code)
	})
}

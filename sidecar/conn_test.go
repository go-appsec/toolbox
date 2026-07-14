package sidecar

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeServer accepts one connection on a loopback TCP listener and drives it
// with the supplied request handler. It returns the dial address.
func fakeServer(t *testing.T, req func(method string, params json.RawMessage) (any, *wire.Error)) (string, chan *wire.Peer) {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	peerCh := make(chan *wire.Peer, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		p := wire.NewPeer(conn, wire.HandlerFuncs{
			Request: func(_ context.Context, method string, params json.RawMessage) (any, *wire.Error) {
				return req(method, params)
			},
		})
		peerCh <- p
		go func() { _ = p.Run(t.Context()) }()
	}()
	return ln.Addr().String(), peerCh
}

func registerOK(method string, _ json.RawMessage) (any, *wire.Error) {
	if method == wire.MethodRegister {
		return wire.RegisterResult{
			ProtocolVersion: wire.ProtocolVersion{Major: wire.VersionMajor, Minor: wire.VersionMinor},
			RulesSnapshot:   []wire.Rule{},
			ServerTime:      "2026-06-28T00:00:00Z",
		}, nil
	}
	return nil, wire.NewError(-32601, "no")
}

func TestDial(t *testing.T) {
	t.Parallel()

	t.Run("handshake", func(t *testing.T) {
		var gotName string
		addr, _ := fakeServer(t, func(method string, params json.RawMessage) (any, *wire.Error) {
			if method == wire.MethodRegister {
				var p wire.RegisterParams
				_ = json.Unmarshal(params, &p)
				gotName = p.Name
			}
			return registerOK(method, params)
		})

		conn, err := Dial(t.Context(), addr, Registration{Name: "demo", Protocols: []string{"custom.foo"}})
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		assert.Equal(t, "demo", gotName)
	})

	t.Run("major_mismatch", func(t *testing.T) {
		addr, _ := fakeServer(t, func(method string, _ json.RawMessage) (any, *wire.Error) {
			if method == wire.MethodRegister {
				return nil, wire.NewError(wire.CodeVersionUnsupported, "major mismatch").
					WithData(&wire.ErrorData{Adapter: "demo"})
			}
			return nil, wire.NewError(-32601, "no")
		})

		_, err := Dial(t.Context(), addr, Registration{Name: "demo"})
		require.ErrorIs(t, err, ErrVersionUnsupported)
	})

	t.Run("minor_too_new", func(t *testing.T) {
		addr, _ := fakeServer(t, func(method string, _ json.RawMessage) (any, *wire.Error) {
			if method == wire.MethodRegister {
				return nil, wire.NewError(wire.CodeVersionUnsupported, "minor too new").
					WithData(&wire.ErrorData{Adapter: "demo"})
			}
			return nil, wire.NewError(-32601, "no")
		})

		_, err := Dial(t.Context(), addr, Registration{Name: "demo"})
		require.ErrorIs(t, err, ErrVersionUnsupported)
	})
}

type toolTestHandler struct {
	BaseHandler
	gotName string
	gotArgs json.RawMessage
}

func (*toolTestHandler) OnShutdown(int) {}

func (h *toolTestHandler) OnInvokeTool(p wire.InvokeToolParams) (wire.InvokeToolResult, error) {
	h.gotName = p.Name
	h.gotArgs = p.Arguments
	return wire.InvokeToolResult{Content: "ran " + p.Name, StructuredContent: json.RawMessage(`{"ok":true}`)}, nil
}

// shutdownHandler is a shutdown-only handler; other callbacks use BaseHandler defaults.
type shutdownHandler struct {
	BaseHandler
	fn func(int)
}

func (h shutdownHandler) OnShutdown(d int) {
	if h.fn != nil {
		h.fn(d)
	}
}

func TestConnInvokeTool(t *testing.T) {
	t.Parallel()

	t.Run("delegates_to_handler", func(t *testing.T) {
		addr, peerCh := fakeServer(t, registerOK)
		conn, err := Dial(t.Context(), addr, Registration{Name: "demo"})
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		srv := <-peerCh

		h := &toolTestHandler{}
		conn.SetHandler(h)

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		t.Cleanup(cancel)
		var res wire.InvokeToolResult
		rpcErr := srv.Call(ctx, wire.MethodInvokeTool,
			wire.InvokeToolParams{Name: "ts_inject", Arguments: json.RawMessage(`{"a":1}`)}, &res)
		require.Nil(t, rpcErr)
		assert.Equal(t, "ran ts_inject", res.Content)
		assert.JSONEq(t, `{"ok":true}`, string(res.StructuredContent))
		assert.Equal(t, "ts_inject", h.gotName)
		assert.JSONEq(t, `{"a":1}`, string(h.gotArgs))
	})

	t.Run("no_tool_handler", func(t *testing.T) {
		addr, peerCh := fakeServer(t, registerOK)
		conn, err := Dial(t.Context(), addr, Registration{Name: "demo"})
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		srv := <-peerCh

		// shutdownHandler embeds BaseHandler, whose OnInvokeTool default errors.
		conn.SetHandler(shutdownHandler{})

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		t.Cleanup(cancel)
		var res wire.InvokeToolResult
		rpcErr := srv.Call(ctx, wire.MethodInvokeTool, wire.InvokeToolParams{Name: "x"}, &res)
		require.NotNil(t, rpcErr)
		assert.Equal(t, wire.CodeTransportInternal, rpcErr.Code)
	})
}

func TestConnHeartbeatAndShutdown(t *testing.T) {
	t.Parallel()

	addr, peerCh := fakeServer(t, registerOK)
	conn, err := Dial(t.Context(), addr, Registration{Name: "demo"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	srv := <-peerCh

	// ping auto-answered with pong
	pong := make(chan struct{}, 1)
	srv.SetHandler(wire.HandlerFuncs{
		Notification: func(_ context.Context, method string, _ json.RawMessage) {
			if method == wire.MethodPong {
				select {
				case pong <- struct{}{}:
				default:
				}
			}
		},
	})

	drained := make(chan int, 1)
	go func() { _ = conn.Serve(t.Context(), shutdownHandler{fn: func(d int) { drained <- d }}) }()

	require.NoError(t, srv.Notify(wire.MethodPing, nil))
	select {
	case <-pong:
	case <-time.After(2 * time.Second):
		t.Fatal("did not receive pong")
	}

	// Shutdown request drains via the handler and returns an ack
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	t.Cleanup(cancel)
	var res wire.ShutdownResult
	require.Nil(t, srv.Call(ctx, wire.MethodShutdown, wire.ShutdownParams{DrainSeconds: 5}, &res))
	assert.True(t, res.Ack)
	select {
	case d := <-drained:
		assert.Equal(t, 5, d)
	case <-time.After(2 * time.Second):
		t.Fatal("OnShutdown not called")
	}
}

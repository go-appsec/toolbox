package sidecar

import (
	"context"
	"encoding/json"
	"maps"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// fakeFlows is an in-memory FlowSink for routing tests.
type fakeFlows struct {
	mu    sync.Mutex
	seq   int
	flows map[string]*types.Flow
}

func newFakeFlows() *fakeFlows { return &fakeFlows{flows: map[string]*types.Flow{}} }

func (f *fakeFlows) Store(fl *types.Flow) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	id := "flow" + strconv.Itoa(f.seq)
	fl.FlowID = id
	f.flows[id] = fl
	return id
}

func (f *fakeFlows) Complete(id string, resp *types.Message, _ time.Time, ann map[string]any) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	fl, ok := f.flows[id]
	if !ok {
		return false
	}
	if resp != nil {
		fl.Response = resp
	}
	if len(ann) > 0 {
		if fl.Annotations == nil {
			fl.Annotations = map[string]any{}
		}
		maps.Copy(fl.Annotations, ann)
	}
	return true
}

func (f *fakeFlows) SetInvokedBy(id, invokedBy string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	fl, ok := f.flows[id]
	if !ok {
		return false
	}
	fl.InvokedBy = invokedBy
	return true
}

func (f *fakeFlows) Get(id string) (*types.Flow, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fl, ok := f.flows[id]
	return fl, ok
}

func (f *fakeFlows) ShouldCapture(*types.Flow) bool { return true }

func managerWithFlows(flows FlowSink) *Manager {
	return NewManager(Config{
		HeartbeatInterval: time.Hour,
		HeartbeatTimeout:  time.Hour,
		ReservedNames:     []string{"http/1.1", "http/2", "websocket"},
	}, &protocol.Registry{}, flows, fakeCoreTools{}, fakeRules{})
}

// dialManagerReq connects a client peer that answers ping and dispatches inbound
// requests (e.g. sidecar_send) to onReq.
func dialManagerReq(t *testing.T, m *Manager, onReq func(method string, params json.RawMessage) (any, *wire.Error)) *wire.Peer {
	t.Helper()
	srv, cli := net.Pipe()
	go m.HandleConn(t.Context(), srv)
	p := wire.NewPeer(cli, nil)
	p.SetHandler(wire.HandlerFuncs{
		Request: func(_ context.Context, method string, params json.RawMessage) (any, *wire.Error) {
			return onReq(method, params)
		},
		Notification: func(_ context.Context, method string, _ json.RawMessage) {
			if method == wire.MethodPing {
				_ = p.Notify(wire.MethodPong, nil)
			}
		},
	})
	go func() { _ = p.Run(t.Context()) }()
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func declineUnknown(string, json.RawMessage) (any, *wire.Error) {
	return nil, wire.NewError(-32601, "no")
}

func TestManagerSidecarSend(t *testing.T) {
	t.Parallel()

	t.Run("routes_with_source_flow", func(t *testing.T) {
		flows := newFakeFlows()
		srcID := flows.Store(&types.Flow{Adapter: "demo", Request: &types.Message{Method: "POST", Body: []byte("hi")}})
		m := managerWithFlows(flows)

		inlined := make(chan bool, 1)
		p := dialManagerReq(t, m, func(method string, params json.RawMessage) (any, *wire.Error) {
			if method == wire.MethodSidecarSend {
				var sp wire.SidecarSendParams
				_ = json.Unmarshal(params, &sp)
				inlined <- sp.Flow != nil && sp.FlowID == srcID
				return wire.SidecarSendResult{NewFlowIDs: []string{"new1"}}, nil
			}
			return declineUnknown(method, params)
		})
		_, err := register(t, p, baseParams("demo"))
		require.Nil(t, err)

		res, serr := m.SidecarSend(t.Context(), "demo", wire.SidecarSendParams{FlowID: srcID})
		require.Nil(t, serr)
		assert.Equal(t, []string{"new1"}, res.NewFlowIDs)
		select {
		case ok := <-inlined:
			assert.True(t, ok)
		case <-time.After(2 * time.Second):
			t.Fatal("sidecar_send not delivered")
		}
	})

	t.Run("unknown_adapter", func(t *testing.T) {
		m := managerWithFlows(newFakeFlows())
		_, serr := m.SidecarSend(t.Context(), "ghost", wire.SidecarSendParams{})
		require.NotNil(t, serr)
		assert.Equal(t, wire.CodeUnknownDestAdapter, serr.Code)
	})
}

func TestHandleInvokeAdapter(t *testing.T) {
	t.Parallel()

	t.Run("originates_and_stamps_invoked_by", func(t *testing.T) {
		flows := newFakeFlows()
		destFlowID := flows.Store(&types.Flow{Adapter: "dest"})
		m := managerWithFlows(flows)

		pd := dialManagerReq(t, m, func(method string, params json.RawMessage) (any, *wire.Error) {
			if method == wire.MethodSidecarSend {
				return wire.SidecarSendResult{NewFlowIDs: []string{destFlowID}}, nil
			}
			return declineUnknown(method, params)
		})
		dp := baseParams("dest")
		dp.Capabilities.InjectionTargets = []wire.InjectionTarget{{}}
		_, err := register(t, pd, dp)
		require.Nil(t, err)

		pc := dialManagerReq(t, m, declineUnknown)
		_, err = register(t, pc, baseParams("caller"))
		require.Nil(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		t.Cleanup(cancel)
		var res wire.InvokeAdapterResult
		require.Nil(t, pc.Call(ctx, wire.MethodInvokeAdapter, wire.InvokeAdapterParams{Adapter: "dest"}, &res))
		assert.Equal(t, []string{destFlowID}, res.NewFlowIDs)
		fl, ok := flows.Get(destFlowID)
		require.True(t, ok)
		assert.Equal(t, "caller", fl.InvokedBy)
	})

	t.Run("unknown_destination", func(t *testing.T) {
		m := managerWithFlows(newFakeFlows())
		pc := dialManagerReq(t, m, declineUnknown)
		_, err := register(t, pc, baseParams("caller"))
		require.Nil(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		t.Cleanup(cancel)
		var res wire.InvokeAdapterResult
		rpcErr := pc.Call(ctx, wire.MethodInvokeAdapter, wire.InvokeAdapterParams{Adapter: "ghost"}, &res)
		require.NotNil(t, rpcErr)
		assert.Equal(t, wire.CodeUnknownDestAdapter, rpcErr.Code)
	})

	t.Run("destination_without_injection_target", func(t *testing.T) {
		m := managerWithFlows(newFakeFlows())
		pd := dialManagerReq(t, m, declineUnknown)
		_, err := register(t, pd, baseParams("dest"))
		require.Nil(t, err)
		pc := dialManagerReq(t, m, declineUnknown)
		_, err = register(t, pc, baseParams("caller"))
		require.Nil(t, err)

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		t.Cleanup(cancel)
		var res wire.InvokeAdapterResult
		rpcErr := pc.Call(ctx, wire.MethodInvokeAdapter, wire.InvokeAdapterParams{Adapter: "dest"}, &res)
		require.NotNil(t, rpcErr)
		assert.Equal(t, wire.CodeNoInjectionTarget, rpcErr.Code)
	})
}

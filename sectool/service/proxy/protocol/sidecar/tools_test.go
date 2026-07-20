package sidecar

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// fakeCoreTools is a CoreService stub reporting core tool names for collision checks.
type fakeCoreTools struct{ names []string }

func (fakeCoreTools) CoreInvoke(context.Context, string, json.RawMessage) (string, bool, error) {
	return "", false, nil
}

func (f fakeCoreTools) CoreToolNames() []string { return f.names }

func toolManager(coreNames []string) *Manager {
	cfg := Config{
		HeartbeatInterval: time.Hour,
		HeartbeatTimeout:  time.Hour,
		ReservedNames:     []string{"http/1.1", "http/2", "websocket"},
	}
	return NewManager(cfg, &protocol.Registry{}, newFakeFlows(), fakeCoreTools{names: coreNames}, fakeRules{})
}

func toolParams(name string, toolNames ...string) wire.RegisterParams {
	p := baseParams(name)
	for _, tn := range toolNames {
		p.MCPTools = append(p.MCPTools, wire.MCPTool{Name: tn})
	}
	return p
}

func TestManagerRegisterToolCollision(t *testing.T) {
	t.Parallel()

	t.Run("collides_with_core", func(t *testing.T) {
		m := toolManager([]string{"proxy_poll", "flow_get"})
		p := dialManager(t, m, true)
		_, err := register(t, p, toolParams("demo", "proxy_poll"))
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeToolNameConflict, err.Code)
		require.NotNil(t, err.Data)
		assert.Equal(t, "demo", err.Data.Adapter)
		assert.Equal(t, "sectool", err.Data.ConflictAdapter)
		assert.Equal(t, 0, m.Count())
	})

	t.Run("collides_with_other_sidecar", func(t *testing.T) {
		m := toolManager([]string{"proxy_poll"})
		p1 := dialManager(t, m, true)
		_, err1 := register(t, p1, toolParams("first", "ts_inject"))
		require.Nil(t, err1)

		p2 := dialManager(t, m, true)
		_, err2 := register(t, p2, toolParams("second", "ts_inject"))
		require.NotNil(t, err2)
		assert.Equal(t, wire.CodeToolNameConflict, err2.Code)
		assert.Equal(t, "second", err2.Data.Adapter)
		assert.Equal(t, "first", err2.Data.ConflictAdapter)
	})

	t.Run("duplicate_in_registration", func(t *testing.T) {
		m := toolManager([]string{"proxy_poll"})
		p := dialManager(t, m, true)
		_, err := register(t, p, toolParams("demo", "dup", "dup"))
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeToolNameConflict, err.Code)
	})

	t.Run("core_tools_unavailable", func(t *testing.T) {
		m := toolManager(nil)
		p := dialManager(t, m, true)
		_, err := register(t, p, toolParams("demo", "demo_tool"))
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeRegistrationRejected, err.Code)
		assert.Equal(t, 0, m.Count())
	})

	t.Run("no_tools_without_core", func(t *testing.T) {
		m := toolManager(nil)
		p := dialManager(t, m, true)
		_, err := register(t, p, toolParams("demo"))
		require.Nil(t, err)
		assert.Equal(t, 1, m.Count())
	})

	t.Run("distinct_tools_ok", func(t *testing.T) {
		m := toolManager([]string{"proxy_poll"})
		p1 := dialManager(t, m, true)
		_, err1 := register(t, p1, toolParams("first", "a_tool"))
		require.Nil(t, err1)

		p2 := dialManager(t, m, true)
		_, err2 := register(t, p2, toolParams("second", "b_tool"))
		require.Nil(t, err2)
		assert.Equal(t, 2, m.Count())
	})
}

func TestManagerInvokeTool(t *testing.T) {
	t.Parallel()

	t.Run("delegates_to_owner", func(t *testing.T) {
		m := toolManager([]string{"proxy_poll"})
		srv, cli := net.Pipe()
		go m.HandleConn(t.Context(), srv)

		var gotName string
		var gotArgs json.RawMessage
		p := wire.NewPeer(cli, nil)
		p.SetHandler(wire.HandlerFuncs{
			Notification: func(_ context.Context, method string, _ json.RawMessage) {
				if method == wire.MethodPing {
					_ = p.Notify(wire.MethodPong, nil)
				}
			},
			Request: func(_ context.Context, method string, params json.RawMessage) (any, *wire.Error) {
				if method != wire.MethodInvokeTool {
					return nil, wire.NewError(-32601, "no")
				}
				var ip wire.InvokeToolParams
				_ = json.Unmarshal(params, &ip)
				gotName, gotArgs = ip.Name, ip.Arguments
				return wire.InvokeToolResult{Content: "delegated"}, nil
			},
		})
		go func() { _ = p.Run(t.Context()) }()
		t.Cleanup(func() { _ = p.Close() })

		_, err := register(t, p, toolParams("demo", "demo_tool"))
		require.Nil(t, err)

		res, ierr := m.InvokeTool(t.Context(), "demo_tool", json.RawMessage(`{"x":1}`))
		require.Nil(t, ierr)
		assert.Equal(t, "delegated", res.Content)
		assert.Equal(t, "demo_tool", gotName)
		assert.JSONEq(t, `{"x":1}`, string(gotArgs))
	})

	t.Run("unknown_tool", func(t *testing.T) {
		m := toolManager([]string{"proxy_poll"})
		_, ierr := m.InvokeTool(t.Context(), "nope", nil)
		require.NotNil(t, ierr)
		assert.Equal(t, wire.CodeUnknownDestAdapter, ierr.Code)
	})
}

func TestManagerAdapterTools(t *testing.T) {
	t.Parallel()

	t.Run("healthy_snapshot", func(t *testing.T) {
		m := toolManager([]string{"proxy_poll"})
		p1 := dialManager(t, m, true)
		_, err := register(t, p1, toolParams("first", "a_tool"))
		require.Nil(t, err)
		p2 := dialManager(t, m, true)
		_, err = register(t, p2, toolParams("second", "b_tool", "c_tool"))
		require.Nil(t, err)

		tools := m.AdapterTools()
		require.Len(t, tools, 2)
		require.Len(t, tools["first"], 1)
		assert.Equal(t, "a_tool", tools["first"][0].Name)
		require.Len(t, tools["second"], 2)
		assert.Equal(t, "b_tool", tools["second"][0].Name)
		assert.Equal(t, "c_tool", tools["second"][1].Name)
	})

	t.Run("excludes_unhealthy", func(t *testing.T) {
		m := NewManager(
			Config{HeartbeatInterval: 15 * time.Millisecond, HeartbeatTimeout: 40 * time.Millisecond, ReservedNames: []string{"http/1.1", "http/2", "websocket"}},
			&protocol.Registry{}, newFakeFlows(), fakeCoreTools{names: []string{"proxy_poll"}}, fakeRules{},
		)
		p := dialManager(t, m, false) // silent: never answers ping -> goes unhealthy
		_, err := register(t, p, toolParams("silent", "q_tool"))
		require.Nil(t, err)

		assert.Eventually(t, func() bool { return len(m.AdapterTools()) == 0 }, 2*time.Second, 20*time.Millisecond)
	})
}

//go:build unix

package service

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// toolSidecar is a fixture adapter that registers an MCP tool. Its handler reads
// sectool state and emits a flow before returning a result, exercising the full
// invoke_tool delegation path.
type toolSidecar struct {
	sidecar.BaseHandler
	conn *sidecar.Conn
}

func (*toolSidecar) OnShutdown(int) {}

func (h *toolSidecar) OnInvokeTool(p wire.InvokeToolParams) (wire.InvokeToolResult, error) {
	ctx := context.Background()
	if _, err := h.conn.CoreInvoke(ctx, "proxy_poll", map[string]any{"output_mode": "summary"}); err != nil {
		return wire.InvokeToolResult{}, err
	}
	if _, err := h.conn.PushFlow(ctx, wire.Flow{
		ProtocolTag: "custom/1.tool",
		Request:     &wire.FlowMessage{Method: "TOOL", Path: "/invoked", Headers: []wire.Header{{Name: "Host", Value: "unit.test"}}},
	}); err != nil {
		return wire.InvokeToolResult{}, err
	}
	var args struct {
		Marker string `json:"marker"`
	}
	_ = json.Unmarshal(p.Arguments, &args)
	return wire.InvokeToolResult{
		Content:           "echoed " + args.Marker,
		StructuredContent: json.RawMessage(`{"done":true}`),
	}, nil
}

func TestSidecarToolsE2E(t *testing.T) {
	t.Parallel()

	const adapterName = "tool-sidecar"
	const toolName = "custom_echo"

	socket := filepath.Join(t.TempDir(), "sidecar.sock")
	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.MemProvider, proxy.TimeoutConfig{}, false)
	require.NoError(t, err)

	srv, err := NewServerWithStorageDir(MCPServerFlags{
		MCPPort:      -1,
		WorkflowMode: protocol.WorkflowModeNone,
		ConfigPath:   filepath.Join(t.TempDir(), "config.json"),
	}, t.TempDir(), backend, newMockOastBackend(), newMockCrawlerBackend())
	require.NoError(t, err)
	srv.SetQuietLogging()

	require.NoError(t, backend.EnableSidecars(scsidecar.Config{Socket: socket, NativeProxyPort: 0}, srv, srv.replayHistoryStore))

	go func() { _ = srv.Run(t.Context()) }()
	srv.WaitTillStarted()
	require.NoError(t, backend.WaitReady(t.Context()))
	t.Cleanup(func() {
		srv.RequestShutdown()
	})

	// The sidecar registers before the MCP client connects, so its tool is composed
	// into that client's session at connect.
	conn, err := sidecar.Dial(t.Context(), socket, sidecar.Registration{
		Name:            adapterName,
		Protocols:       []string{"custom/1"},
		ProtocolVersion: wire.ProtocolVersion{Major: wire.VersionMajor, Minor: wire.VersionMinor},
		MCPTools: []wire.MCPTool{{
			Name:        toolName,
			Description: "Echo a marker back",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"marker":{"type":"string"}},"required":["marker"]}`),
		}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	// install up front: Serve's own install races inbound invoke_tool requests
	h := &toolSidecar{conn: conn}
	conn.SetHandler(h)
	go func() { _ = conn.Serve(t.Context(), h) }()

	mcpClient, err := mcpclient.Connect(t.Context(), "http://"+srv.mcpServer.Addr()+"/mcp")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mcpClient.Close() })
	ctx := t.Context()

	// The session-composed tool list converges shortly after connect.
	require.Eventually(t, func() bool {
		tools, lerr := mcpClient.ListTools(ctx)
		if lerr != nil {
			return false
		}
		_, ok := findTool(tools, toolName)
		return ok
	}, 2*time.Second, 20*time.Millisecond)

	t.Run("tool_listed_with_metadata", func(t *testing.T) {
		tools, lerr := mcpClient.ListTools(ctx)
		require.NoError(t, lerr)
		tool, ok := findTool(tools, toolName)
		require.True(t, ok)
		assert.Equal(t, "Echo a marker back", tool.Description)
		assert.Contains(t, tool.InputSchema.Properties, "marker")
	})

	t.Run("core_tools_gain_sidecar_params", func(t *testing.T) {
		tools, lerr := mcpClient.ListTools(ctx)
		require.NoError(t, lerr)
		poll, ok := findTool(tools, "proxy_poll")
		require.True(t, ok)
		assert.Contains(t, poll.InputSchema.Properties, "adapter")
		assert.Contains(t, poll.InputSchema.Properties, "protocol_tag")
		ruleAdd, ok := findTool(tools, "proxy_rule_add")
		require.True(t, ok)
		assert.Contains(t, ruleAdd.InputSchema.Properties, "adapter")
	})

	t.Run("invoke_delegates_and_returns_verbatim", func(t *testing.T) {
		res, cerr := mcpClient.CallTool(ctx, toolName, map[string]any{"marker": "xyz"})
		require.NoError(t, cerr)
		assert.Equal(t, "echoed xyz", resultText(res))
		require.NotNil(t, res.StructuredContent)

		// The flow the handler pushed mid-call is captured under the adapter.
		poll, perr := mcpClient.ProxyPoll(ctx, mcpclient.ProxyPollOpts{OutputMode: "flows", Adapter: adapterName, Limit: 100})
		require.NoError(t, perr)
		assert.True(t, containsPath(poll.Flows, "/invoked"))
	})

	t.Run("invalid_arguments_rejected", func(t *testing.T) {
		_, cerr := mcpClient.CallTool(ctx, toolName, map[string]any{})
		require.Error(t, cerr)
		assert.Contains(t, cerr.Error(), "invalid arguments")
	})
}

func TestSidecarCoreToolNameRejected(t *testing.T) {
	t.Parallel()

	// registration declaring a core tool name, rejected at any point in startup
	coreToolReg := sidecar.Registration{
		Name:            "hijack",
		Protocols:       []string{"custom/1"},
		ProtocolVersion: wire.ProtocolVersion{Major: wire.VersionMajor, Minor: wire.VersionMinor},
		MCPTools:        []wire.MCPTool{{Name: "proxy_poll", Description: "hijack attempt"}},
	}

	t.Run("before_core_tools_ready", func(t *testing.T) {
		socket := filepath.Join(t.TempDir(), "sidecar.sock")
		backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.MemProvider, proxy.TimeoutConfig{}, false)
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close(context.Background()) })

		srv, err := NewServerWithStorageDir(MCPServerFlags{
			MCPPort:      -1,
			WorkflowMode: protocol.WorkflowModeNone,
			ConfigPath:   filepath.Join(t.TempDir(), "config.json"),
		}, t.TempDir(), backend, newMockOastBackend(), newMockCrawlerBackend())
		require.NoError(t, err)
		srv.SetQuietLogging()

		// accept without ever running the server, so no core tools exist
		require.NoError(t, backend.EnableSidecars(scsidecar.Config{Socket: socket, NativeProxyPort: 0}, srv, srv.replayHistoryStore))
		go func() { _ = backend.Serve() }()
		require.NoError(t, backend.WaitReady(t.Context()))

		_, err = sidecar.Dial(t.Context(), socket, coreToolReg)
		require.Error(t, err)
		var werr *wire.Error
		require.ErrorAs(t, err, &werr)
		assert.Equal(t, wire.CodeRegistrationRejected, werr.Code)
	})

	t.Run("after_core_tools_ready", func(t *testing.T) {
		socket := filepath.Join(t.TempDir(), "sidecar.sock")
		backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.MemProvider, proxy.TimeoutConfig{}, false)
		require.NoError(t, err)

		srv, err := NewServerWithStorageDir(MCPServerFlags{
			MCPPort:      -1,
			WorkflowMode: protocol.WorkflowModeNone,
			ConfigPath:   filepath.Join(t.TempDir(), "config.json"),
		}, t.TempDir(), backend, newMockOastBackend(), newMockCrawlerBackend())
		require.NoError(t, err)
		srv.SetQuietLogging()

		require.NoError(t, backend.EnableSidecars(scsidecar.Config{Socket: socket, NativeProxyPort: 0}, srv, srv.replayHistoryStore))

		go func() { _ = srv.Run(t.Context()) }()
		srv.WaitTillStarted()
		require.NoError(t, backend.WaitReady(t.Context()))
		t.Cleanup(func() {
			srv.RequestShutdown()
		})

		_, err = sidecar.Dial(t.Context(), socket, coreToolReg)
		require.Error(t, err)
		var werr *wire.Error
		require.ErrorAs(t, err, &werr)
		assert.Equal(t, wire.CodeToolNameConflict, werr.Code)
		assert.Equal(t, types.AdapterScopeCore, werr.Data.ConflictAdapter)
	})
}

func TestSidecarToolsAbsentWithoutSidecar(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.MemProvider, proxy.TimeoutConfig{}, false)
	require.NoError(t, err)

	srv, err := NewServerWithStorageDir(MCPServerFlags{
		MCPPort:      -1,
		WorkflowMode: protocol.WorkflowModeNone,
		ConfigPath:   filepath.Join(t.TempDir(), "config.json"),
	}, t.TempDir(), backend, newMockOastBackend(), newMockCrawlerBackend())
	require.NoError(t, err)
	srv.SetQuietLogging()

	// Sidecars enabled but none connected: the surface must be unchanged.
	require.NoError(t, backend.EnableSidecars(scsidecar.Config{Socket: filepath.Join(t.TempDir(), "sidecar.sock"), NativeProxyPort: 0}, srv, srv.replayHistoryStore))

	go func() { _ = srv.Run(t.Context()) }()
	srv.WaitTillStarted()
	require.NoError(t, backend.WaitReady(t.Context()))
	t.Cleanup(func() {
		srv.RequestShutdown()
	})

	mcpClient, err := mcpclient.Connect(t.Context(), "http://"+srv.mcpServer.Addr()+"/mcp")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mcpClient.Close() })

	tools, err := mcpClient.ListTools(t.Context())
	require.NoError(t, err)
	poll, ok := findTool(tools, "proxy_poll")
	require.True(t, ok)
	assert.NotContains(t, poll.InputSchema.Properties, "adapter")
	assert.NotContains(t, poll.InputSchema.Properties, "protocol_tag")
	ruleAdd, ok := findTool(tools, "proxy_rule_add")
	require.True(t, ok)
	assert.NotContains(t, ruleAdd.InputSchema.Properties, "adapter")
}

func findTool(tools []mcp.Tool, name string) (mcp.Tool, bool) {
	for _, t := range tools {
		if t.Name == name {
			return t, true
		}
	}
	return mcp.Tool{}, false
}

func containsPath(flows []protocol.FlowEntry, path string) bool {
	for _, f := range flows {
		if f.Path == path {
			return true
		}
	}
	return false
}

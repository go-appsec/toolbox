//go:build unix

package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// replaySendHandler records the routed request and returns a canned result.
type replaySendHandler struct {
	sidecar.BaseHandler
	got chan wire.SidecarSendParams
}

func (h *replaySendHandler) OnSidecarSend(p wire.SidecarSendParams) (wire.SidecarSendResult, error) {
	h.got <- p
	return wire.SidecarSendResult{
		NewFlowIDs: []string{"sc-replayed"},
		Response:   &wire.FlowMessage{StatusCode: 202, Body: []byte("queued")},
	}, nil
}

// TestSidecarReplaySendE2E drives replay_send against a sidecar-owned flow and
// asserts it routes to the owning adapter's OnSidecarSend (with the source flow
// and built mutations) rather than the native HTTP send path.
func TestSidecarReplaySendE2E(t *testing.T) {
	const adapterName = "mqtt"

	socket := filepath.Join(t.TempDir(), "sidecar.sock")
	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.MemProvider, proxy.TimeoutConfig{})
	require.NoError(t, err)

	srv, err := NewServer(MCPServerFlags{
		MCPPort:      0,
		WorkflowMode: protocol.WorkflowModeNone,
		ConfigPath:   filepath.Join(t.TempDir(), "config.json"),
	}, backend, newMockOastBackend(), newMockCrawlerBackend())
	require.NoError(t, err)
	srv.SetQuietLogging()

	require.NoError(t, backend.EnableSidecars(scsidecar.Config{Socket: socket, NativeProxyPort: 0}, srv, srv.replayHistoryStore))
	go func() { _ = backend.Serve() }()

	serverErr := make(chan error, 1)
	go func() { serverErr <- srv.Run(t.Context()) }()
	srv.WaitTillStarted()
	t.Cleanup(func() {
		srv.RequestShutdown()
		<-serverErr
	})

	mcpClient, err := mcpclient.Connect(t.Context(), "http://"+srv.mcpServer.Addr()+"/mcp")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mcpClient.Close() })

	conn, err := sidecar.Dial(socket, sidecar.Registration{
		Name:            adapterName,
		Protocols:       []string{"mqtt/3"},
		ProtocolVersion: wire.ProtocolVersion{Major: wire.VersionMajor, Minor: wire.VersionMinor},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	ctx := t.Context()

	h := &replaySendHandler{got: make(chan wire.SidecarSendParams, 1)}
	go func() { _ = conn.Serve(ctx, h) }()

	// The adapter owns a flow in history.
	flowID, err := conn.PushFlow(ctx, wire.Flow{
		ProtocolTag: "mqtt/3.publish",
		Request: &wire.FlowMessage{
			Method:  "PUBLISH",
			Path:    "/topic",
			Headers: []wire.Header{{Name: "Host", Value: "broker.test"}},
			Body:    []byte("{}"),
		},
	})
	require.NoError(t, err)

	resp, err := mcpClient.ReplaySend(ctx, mcpclient.ReplaySendOpts{
		FlowID:         flowID,
		SetHeaders:     []string{"X-New: 1"},
		Body:           "raw",
		StreamStrategy: "per_chunk",
	})
	require.NoError(t, err)
	assert.Equal(t, "sc-replayed", resp.FlowID)
	assert.Equal(t, 202, resp.Status)
	assert.Contains(t, resp.RespPreview, "queued")

	// The replay routed to the adapter with the source flow inline and the
	// built mutation list.
	select {
	case p := <-h.got:
		assert.Equal(t, flowID, p.FlowID)
		require.NotNil(t, p.Flow)
		assert.Equal(t, "per_chunk", p.StreamStrategy)
		ops := make([]string, 0, len(p.Mutations))
		for _, mu := range p.Mutations {
			ops = append(ops, mu.Op)
		}
		assert.Equal(t, []string{"set_header", "body"}, ops)
	case <-time.After(2 * time.Second):
		t.Fatal("sidecar_send was not routed to the adapter")
	}
}

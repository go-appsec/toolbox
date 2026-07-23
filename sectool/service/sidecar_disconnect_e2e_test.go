//go:build unix

package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

func TestSidecarDisconnectFinalizeE2E(t *testing.T) {
	t.Parallel()

	const adapterName = "disconnect-sidecar"

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
	t.Cleanup(func() {
		srv.RequestShutdown()
	})

	ctx := t.Context()
	host := []wire.Header{{Name: "Host", Value: "unit.test"}}

	t.Run("non_resume_finalizes_open_flow", func(t *testing.T) {
		conn, derr := sidecar.Dial(ctx, socket, sidecar.Registration{
			Name:            adapterName,
			InstanceID:      uuid.NewString(),
			ProtocolVersion: wire.ProtocolVersion{Major: wire.VersionMajor, Minor: wire.VersionMinor},
		})
		require.NoError(t, derr)

		flowID, perr := conn.PushFlow(ctx, wire.Flow{
			ProtocolTag: "custom/1.req",
			Request:     &wire.FlowMessage{Method: "GET", Path: "/open", Headers: host},
		})
		require.NoError(t, perr)
		require.NoError(t, conn.Close())

		require.Eventually(t, func() bool {
			flow, ok := backend.server.History().Get(flowID)
			return ok && !flow.CompletedAt.IsZero()
		}, 2*time.Second, 10*time.Millisecond)

		flow, ok := backend.server.History().Get(flowID)
		require.True(t, ok)
		assert.Nil(t, flow.Response)
		assert.Equal(t, true, flow.Annotations[scsidecar.AnnotationDisconnected])
	})

	t.Run("resume_keeps_open_flow_for_reclaim", func(t *testing.T) {
		instanceID := uuid.NewString()
		reg := sidecar.Registration{
			Name:            adapterName,
			InstanceID:      instanceID,
			Resume:          true,
			ProtocolVersion: wire.ProtocolVersion{Major: wire.VersionMajor, Minor: wire.VersionMinor},
		}
		conn, derr := sidecar.Dial(ctx, socket, reg)
		require.NoError(t, derr)

		flowID, perr := conn.PushFlow(ctx, wire.Flow{
			ProtocolTag: "custom/1.req",
			Request:     &wire.FlowMessage{Method: "GET", Path: "/resumable", Headers: host},
		})
		require.NoError(t, perr)
		require.NoError(t, conn.Close())

		// reconnect with the same instance and complete the flow the sidecar left open
		conn2, derr := sidecar.Dial(ctx, socket, reg)
		require.NoError(t, derr)
		t.Cleanup(func() { _ = conn2.Close() })
		require.NoError(t, conn2.CompleteFlow(ctx, flowID, &wire.FlowMessage{StatusCode: 200}, time.Now()))

		flow, ok := backend.server.History().Get(flowID)
		require.True(t, ok)
		assert.NotContains(t, flow.Annotations, scsidecar.AnnotationDisconnected)
		require.NotNil(t, flow.Response)
		assert.Equal(t, 200, flow.Response.StatusCode)
	})
}

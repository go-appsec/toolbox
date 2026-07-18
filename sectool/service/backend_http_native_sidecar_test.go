//go:build unix

package service

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy"
	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

func TestNativeProxyBackendSidecarLifecycle(t *testing.T) {
	t.Parallel()

	socket := filepath.Join(t.TempDir(), "sidecar.sock")
	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.MemProvider, proxy.TimeoutConfig{}, false)
	require.NoError(t, err)
	require.NoError(t, backend.EnableSidecars(scsidecar.Config{Socket: socket, NativeProxyPort: 0}, nil, store.NewReplayHistoryStore(store.NewMemStorage())))

	go func() { _ = backend.Serve() }()

	var conn net.Conn
	require.Eventually(t, func() bool {
		var d net.Dialer
		c, derr := d.DialContext(t.Context(), "unix", socket)
		if derr != nil {
			return false
		}
		conn = c
		return true
	}, 2*time.Second, 20*time.Millisecond)

	p := wire.NewPeer(conn, nil)
	go func() { _ = p.Run(t.Context()) }()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	t.Cleanup(cancel)
	var res wire.RegisterResult
	params := wire.RegisterParams{
		Name:            "demo",
		ProtocolVersion: wire.ProtocolVersion{Major: wire.VersionMajor, Minor: wire.VersionMinor},
		Protocols:       []string{"custom.foo"},
	}
	require.Nil(t, p.Call(ctx, wire.MethodRegister, params, &res))
	assert.Equal(t, 1, backend.sidecarManager.Count())

	require.NoError(t, backend.Close(context.Background()))
	_, statErr := os.Stat(socket)
	assert.True(t, os.IsNotExist(statErr), "socket should be removed on close")
}

//go:build unix

package sidecar

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

func TestListenerUnix(t *testing.T) {
	t.Parallel()

	socket := filepath.Join(t.TempDir(), "sub", "sidecar.sock")
	m := testManager(Config{})
	ln, err := NewListener(Config{Socket: socket}, m)
	require.NoError(t, err)
	go func() { _ = ln.Serve() }()

	dirInfo, err := os.Stat(filepath.Dir(socket))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
	sockInfo, err := os.Stat(socket)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), sockInfo.Mode().Perm())

	conn, err := net.Dial("unix", socket)
	require.NoError(t, err)
	p := wire.NewPeer(conn, nil)
	go func() { _ = p.Run(t.Context()) }()
	t.Cleanup(func() { _ = p.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	t.Cleanup(cancel)
	var res wire.RegisterResult
	require.Nil(t, p.Call(ctx, wire.MethodRegister, baseParams("demo"), &res))
	assert.Eventually(t, func() bool { return m.Count() == 1 }, 2*time.Second, 10*time.Millisecond)

	require.NoError(t, ln.Close())
	_, statErr := os.Stat(socket)
	assert.True(t, os.IsNotExist(statErr))
}

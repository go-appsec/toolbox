package service

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServer(t *testing.T) {
	t.Parallel()

	t.Run("rejects_empty_workdir", func(t *testing.T) {
		_, err := NewServer(DaemonFlags{WorkDir: ""})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "workdir is required")
	})

	t.Run("accepts_valid_config", func(t *testing.T) {
		srv, err := NewServer(DaemonFlags{
			WorkDir:    "/tmp/test",
			BurpMCPURL: "http://127.0.0.1:9876/sse",
		})
		require.NoError(t, err)
		assert.NotNil(t, srv)
	})
}

func TestServerRun(t *testing.T) {
	t.Parallel()

	t.Run("creates_dirs_on_start", func(t *testing.T) {
		mockMCP := NewTestMCPServer(t)
		workDir := t.TempDir()
		srv, err := NewServer(DaemonFlags{
			WorkDir:    workDir,
			BurpMCPURL: mockMCP.URL(),
		})
		require.NoError(t, err)

		serverErr := make(chan error, 1)
		go func() {
			serverErr <- srv.Run(t.Context())
		}()
		srv.WaitTillStarted()

		assert.DirExists(t, filepath.Join(workDir, ".sectool", "service"))
		assert.DirExists(t, filepath.Join(workDir, ".sectool", "requests"))

		pidPath := filepath.Join(workDir, ".sectool", "service", "pid")
		pidData, err := os.ReadFile(pidPath)
		require.NoError(t, err)
		pid, err := strconv.Atoi(string(pidData))
		require.NoError(t, err)
		assert.Equal(t, os.Getpid(), pid)

		socketPath := filepath.Join(workDir, ".sectool", "service", "socket")
		assert.FileExists(t, socketPath)

		srv.RequestShutdown()
		select {
		case err := <-serverErr:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("server did not shut down in time")
		}

		assert.NoFileExists(t, pidPath)
		assert.NoFileExists(t, socketPath)
	})
}

func TestRequestShutdownIdempotent(t *testing.T) {
	t.Parallel()

	mockMCP := NewTestMCPServer(t)
	workDir := t.TempDir()
	srv, err := NewServer(DaemonFlags{
		WorkDir:    workDir,
		BurpMCPURL: mockMCP.URL(),
	})
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Run(t.Context())
	}()
	srv.WaitTillStarted()

	// Call RequestShutdown multiple times - should not panic
	srv.RequestShutdown()
	srv.RequestShutdown()
	srv.RequestShutdown()

	select {
	case err := <-serverErr:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestServerLockPreventsSecondInstance(t *testing.T) {
	t.Parallel()

	mockMCP := NewTestMCPServer(t)
	workDir := t.TempDir()

	srv1, err := NewServer(DaemonFlags{
		WorkDir:    workDir,
		BurpMCPURL: mockMCP.URL(),
	})
	require.NoError(t, err)

	server1Err := make(chan error, 1)
	go func() {
		server1Err <- srv1.Run(t.Context())
	}()
	defer func() {
		srv1.RequestShutdown()
		<-server1Err
	}()
	srv1.WaitTillStarted()

	srv2, err := NewServer(DaemonFlags{
		WorkDir:    workDir,
		BurpMCPURL: mockMCP.URL(),
	})
	require.NoError(t, err)

	// Try to start second server - should fail to acquire lock
	err = srv2.Run(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "another service instance is running")
}

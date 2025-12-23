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

func TestServiceEndToEnd(t *testing.T) {
	t.Parallel()

	t.Run("client_health_check", func(t *testing.T) {
		workDir := t.TempDir()
		srv, err := NewServer(DaemonFlags{
			WorkDir:    workDir,
			BurpMCPURL: "http://test.burp:9876/sse",
		})
		require.NoError(t, err)

		serverErr := make(chan error, 1)
		go func() {
			serverErr <- srv.Run(t.Context())
		}()
		defer func() {
			srv.RequestShutdown()
			<-serverErr
		}()
		srv.WaitTillStarted()

		client := NewClient(workDir)

		t.Run("is_healthy_when_running", func(t *testing.T) {
			require.NoError(t, client.CheckHealth(t.Context()))
		})

		t.Run("health_returns_response", func(t *testing.T) {
			health, err := client.Health(t.Context())
			require.NoError(t, err)

			assert.Equal(t, Version, health.Version)
			assert.NotEmpty(t, health.StartedAt)
			assert.False(t, health.BurpConnected)
			assert.Equal(t, "http://test.burp:9876/sse", health.BurpMCPURL)
			assert.Nil(t, health.Metrics) // No metrics registered by default
		})
	})

	t.Run("client_status", func(t *testing.T) {
		workDir := t.TempDir()
		client := NewClient(workDir)

		t.Run("not_running", func(t *testing.T) {
			status, err := client.Status(t.Context())
			require.NoError(t, err)

			assert.False(t, status.Running)
			assert.Nil(t, status.Health)
			assert.Contains(t, status.SocketPath, ".sectool/service/socket")
		})

		t.Run("running", func(t *testing.T) {
			srv, err := NewServer(DaemonFlags{
				WorkDir:    workDir,
				BurpMCPURL: "http://127.0.0.1:9876/sse",
			})
			require.NoError(t, err)

			testCtx := t.Context()
			serverErr := make(chan error, 1)
			go func() {
				serverErr <- srv.Run(testCtx)
			}()
			defer func() {
				srv.RequestShutdown()
				<-serverErr
			}()
			srv.WaitTillStarted()

			status, err := client.Status(t.Context())
			require.NoError(t, err)

			assert.True(t, status.Running)
			assert.NotNil(t, status.Health)
			assert.Equal(t, os.Getpid(), status.PID)
		})
	})

	t.Run("client_stop", func(t *testing.T) {
		workDir := t.TempDir()

		srv, err := NewServer(DaemonFlags{
			WorkDir:    workDir,
			BurpMCPURL: "http://127.0.0.1:9876/sse",
		})
		require.NoError(t, err)

		serverErr := make(chan error, 1)
		go func() {
			serverErr <- srv.Run(t.Context())
		}()
		srv.WaitTillStarted()

		client := NewClient(workDir)

		resp, err := client.Stop(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "shutdown initiated", resp.Message)

		select {
		case err := <-serverErr:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("server did not shut down after stop request")
		}

		require.Error(t, client.CheckHealth(t.Context()))
	})

	t.Run("respects_client_timeout", func(t *testing.T) {
		workDir := t.TempDir()
		client := NewClient(workDir, WithTimeout(50*time.Millisecond))

		start := time.Now()
		_, err := client.Health(t.Context())
		elapsed := time.Since(start)

		require.Error(t, err)
		assert.Less(t, elapsed, 200*time.Millisecond)
	})

	t.Run("removes_stale_socket", func(t *testing.T) {
		workDir := t.TempDir()
		serviceDir := filepath.Join(workDir, ".sectool", "service")
		require.NoError(t, os.MkdirAll(serviceDir, 0755))

		// Create a regular file at socket path to simulate stale socket
		socketPath := filepath.Join(serviceDir, "socket")
		require.NoError(t, os.WriteFile(socketPath, []byte{}, 0600))
		assert.FileExists(t, socketPath)

		client := NewClient(workDir)
		client.cleanupStaleSocket()

		assert.NoFileExists(t, socketPath)
	})

	t.Run("bundle_cleanup_on_shutdown", func(t *testing.T) {
		workDir := t.TempDir()
		requestsDir := filepath.Join(workDir, ".sectool", "requests")

		bundle1 := filepath.Join(requestsDir, "abc123")
		bundle2 := filepath.Join(requestsDir, "xyz789")
		require.NoError(t, os.MkdirAll(bundle1, 0755))
		require.NoError(t, os.MkdirAll(bundle2, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(bundle1, "request.http"), []byte("GET / HTTP/1.1"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(bundle2, "request.http"), []byte("POST /api HTTP/1.1"), 0644))

		srv, err := NewServer(DaemonFlags{
			WorkDir:    workDir,
			BurpMCPURL: "http://127.0.0.1:9876/sse",
		})
		require.NoError(t, err)

		serverErr := make(chan error, 1)
		go func() {
			serverErr <- srv.Run(t.Context())
		}()
		srv.WaitTillStarted()

		assert.DirExists(t, bundle1)
		assert.DirExists(t, bundle2)

		srv.RequestShutdown()
		select {
		case err := <-serverErr:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("server did not shut down in time")
		}

		assert.NoDirExists(t, bundle1)
		assert.NoDirExists(t, bundle2)
	})

	t.Run("pid_file_validation", func(t *testing.T) {
		workDir := t.TempDir()
		serviceDir := filepath.Join(workDir, ".sectool", "service")
		require.NoError(t, os.MkdirAll(serviceDir, 0755))
		pidPath := filepath.Join(serviceDir, "pid")

		client := NewClient(workDir)

		t.Run("missing_pid_returns_zero", func(t *testing.T) {
			pid, exists := client.checkPIDFile()
			assert.Equal(t, 0, pid)
			assert.False(t, exists)
		})

		t.Run("invalid_pid_returns_zero", func(t *testing.T) {
			require.NoError(t, os.WriteFile(pidPath, []byte("not-a-number"), 0600))

			pid, exists := client.checkPIDFile()
			assert.Equal(t, 0, pid)
			assert.False(t, exists)
		})

		t.Run("reads_valid_pid", func(t *testing.T) {
			require.NoError(t, os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0600))

			pid, exists := client.checkPIDFile()
			assert.Equal(t, os.Getpid(), pid)
			assert.True(t, exists)
		})
	})
}

func TestClientErrorHandling(t *testing.T) {
	t.Parallel()

	workDir := t.TempDir()

	srv, err := NewServer(DaemonFlags{
		WorkDir:    workDir,
		BurpMCPURL: "http://127.0.0.1:9876/sse",
	})
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Run(t.Context())
	}()
	defer func() {
		srv.RequestShutdown()
		<-serverErr
	}()
	srv.WaitTillStarted()

	client := NewClient(workDir)

	t.Run("returns_api_error_from_server", func(t *testing.T) {
		_, err := client.doRequest(t.Context(), "POST", "/proxy/list", nil)

		require.Error(t, err)
		var apiErr *APIError
		require.ErrorAs(t, err, &apiErr)
		assert.Equal(t, ErrCodeInternal, apiErr.Code)
		assert.Contains(t, apiErr.Message, "not implemented")
	})
}

func TestRegisterHealthMetric(t *testing.T) {
	t.Parallel()

	workDir := t.TempDir()

	srv, err := NewServer(DaemonFlags{
		WorkDir:    workDir,
		BurpMCPURL: "http://127.0.0.1:9876/sse",
	})
	require.NoError(t, err)

	srv.RegisterHealthMetric("test_count", func() string { return "42" })
	srv.RegisterHealthMetric("test_status", func() string { return "active" })

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Run(t.Context())
	}()
	defer func() {
		srv.RequestShutdown()
		<-serverErr
	}()
	srv.WaitTillStarted()

	client := NewClient(workDir)
	health, err := client.Health(t.Context())
	require.NoError(t, err)

	require.NotNil(t, health.Metrics)
	assert.Equal(t, "42", health.Metrics["test_count"])
	assert.Equal(t, "active", health.Metrics["test_status"])
}

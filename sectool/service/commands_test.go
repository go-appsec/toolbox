package service

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTailLogs(t *testing.T) {
	t.Parallel()

	t.Run("fewer_lines_than_requested", func(t *testing.T) {
		logFile := filepath.Join(t.TempDir(), "test.log")
		require.NoError(t, os.WriteFile(logFile, []byte("line1\nline2\nline3\n"), 0644))

		err := tailLogs(logFile, 10)
		require.NoError(t, err)
	})

	t.Run("more_lines_than_requested", func(t *testing.T) {
		logFile := filepath.Join(t.TempDir(), "test.log")
		var content bytes.Buffer
		for i := 1; i <= 100; i++ {
			_, _ = fmt.Fprintf(&content, "line%d\n", i)
		}
		require.NoError(t, os.WriteFile(logFile, content.Bytes(), 0644))

		err := tailLogs(logFile, 5)
		require.NoError(t, err)
	})

	t.Run("empty_file", func(t *testing.T) {
		logFile := filepath.Join(t.TempDir(), "empty.log")
		require.NoError(t, os.WriteFile(logFile, []byte{}, 0644))

		err := tailLogs(logFile, 10)
		require.NoError(t, err)
	})

	t.Run("missing_file", func(t *testing.T) {
		err := tailLogs("/nonexistent/path/file.log", 10)
		require.Error(t, err)
	})
}

func TestFollowLogs(t *testing.T) {
	t.Parallel()

	t.Run("returns_on_context_cancellation", func(t *testing.T) {
		logFile := filepath.Join(t.TempDir(), "test.log")
		require.NoError(t, os.WriteFile(logFile, []byte("initial line\n"), 0644))

		ctx, cancel := context.WithCancel(t.Context())

		errCh := make(chan error, 1)
		go func() {
			errCh <- followLogs(ctx, logFile)
		}()

		// Give followLogs time to start and reach the polling loop
		time.Sleep(50 * time.Millisecond)
		cancel()

		select {
		case err := <-errCh:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(time.Second):
			t.Fatal("followLogs did not return after context cancellation")
		}
	})

	t.Run("missing_file", func(t *testing.T) {
		err := followLogs(t.Context(), "/nonexistent/path/file.log")
		require.Error(t, err)
	})
}

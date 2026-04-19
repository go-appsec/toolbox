package service

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

func TestInteractshBackend_EnsureClientForRedirectTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	backend := NewInteractshBackend("", "")
	t.Cleanup(func() { _ = backend.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)

	t.Run("creates_default_client", func(t *testing.T) {
		c, err := backend.ensureClientForRedirectTarget(ctx, "")
		require.NoError(t, err)
		assert.NotEmpty(t, c.CorrelationID())
		assert.NotEmpty(t, c.ServerHost())
		assert.True(t, c.IsPolling())
	})

	t.Run("returns_same_client", func(t *testing.T) {
		c1, err := backend.ensureClientForRedirectTarget(ctx, "")
		require.NoError(t, err)
		c2, err := backend.ensureClientForRedirectTarget(ctx, "")
		require.NoError(t, err)
		assert.Same(t, c1, c2)
	})

	t.Run("different_target_different_client", func(t *testing.T) {
		defaultClient, err := backend.ensureClientForRedirectTarget(ctx, "")
		require.NoError(t, err)

		redirectClient, err := backend.ensureClientForRedirectTarget(ctx, "https://example.com")
		require.NoError(t, err)

		assert.NotSame(t, defaultClient, redirectClient)
		assert.NotEqual(t, defaultClient.CorrelationID(), redirectClient.CorrelationID())
		assert.True(t, redirectClient.IsPolling())
	})

	t.Run("closed_backend_returns_error", func(t *testing.T) {
		b := NewInteractshBackend("", "")
		require.NoError(t, b.Close())

		_, err := b.ensureClientForRedirectTarget(ctx, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "closed")
	})
}

func TestInteractshBackend_ProbeRedirectSupport(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	t.Run("oast_pro_unsupported", func(t *testing.T) {
		backend := NewInteractshBackend("https://oast.pro", "")
		t.Cleanup(func() { _ = backend.Close() })

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		t.Cleanup(cancel)

		backend.ProbeRedirectSupport(ctx)
		assert.False(t, backend.SupportsRedirect())
	})

	t.Run("oastsrv_supported", func(t *testing.T) {
		backend := NewInteractshBackend("https://alpha.oastsrv.net", "")
		t.Cleanup(func() { _ = backend.Close() })

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		t.Cleanup(cancel)

		backend.ProbeRedirectSupport(ctx)
		assert.True(t, backend.SupportsRedirect())
	})
}

func TestNativeProxyIntegrationTest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	t.Run("request_fidelity", func(t *testing.T) {
		upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { _ = upstreamListener.Close() })
		upstreamAddr := upstreamListener.Addr().String()

		backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024,
			store.NewMemStorage(), store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		go func() { _ = backend.Serve() }()

		readyCtx, readyCancel := context.WithTimeout(t.Context(), 5*time.Second)
		t.Cleanup(readyCancel)
		require.NoError(t, backend.WaitReady(readyCtx))
		proxyAddr := backend.Addr()

		proxyFormURL := func(path string) string {
			return "http://" + upstreamAddr + path
		}
		hostHeader := "Host: " + upstreamAddr

		tests := []struct {
			name     string
			input    []byte
			expected []byte
		}{
			{
				name: "bare_lf_throughout",
				input: []byte("POST " + proxyFormURL("/target") + " HTTP/1.1\n" +
					"Host: placeholder\n" +
					"X-Custom: value\n" +
					"Content-Length: 5\n" +
					"\n" +
					"hello"),
				expected: []byte("POST /target HTTP/1.1\n" +
					hostHeader + "\n" +
					"X-Custom: value\n" +
					"Content-Length: 5\n" +
					"\n" +
					"hello"),
			},
			{
				name: "bare_cr_in_header",
				input: []byte("POST " + proxyFormURL("/target") + " HTTP/1.1\r\n" +
					"Host: placeholder\r\n" +
					"X-Desync: vector\r" + // bare CR
					"X-Normal: ok\r\n" +
					"Content-Length: 3\r\n" +
					"\r\n" +
					"abc"),
				expected: []byte("POST /target HTTP/1.1\r\n" +
					hostHeader + "\r\n" +
					"X-Desync: vector\r" +
					"X-Normal: ok\r\n" +
					"Content-Length: 3\r\n" +
					"\r\n" +
					"abc"),
			},
			{
				name: "mixed_terminators",
				input: []byte("POST " + proxyFormURL("/target") + " HTTP/1.1\r\n" +
					"Host: placeholder\n" + // bare LF on Host (will be rewritten)
					"X-Bare-CR: v\r" + // bare CR
					"X-Bare-LF: v\n" + // bare LF
					"Content-Length: 2\r\n" +
					"\n" + // bare-LF header-block end
					"xy"),
				expected: []byte("POST /target HTTP/1.1\r\n" +
					hostHeader + "\n" +
					"X-Bare-CR: v\r" +
					"X-Bare-LF: v\n" +
					"Content-Length: 2\r\n" +
					"\n" +
					"xy"),
			},
			{
				name: "header_whitespace_anomalies",
				input: []byte("GET " + proxyFormURL("/target") + " HTTP/1.1\r\n" +
					"Host: placeholder\r\n" +
					"X-Weird : trailing-space-on-name\r\n" +
					"X-Tab:\tvalue-after-tab\r\n" +
					"X-Many:    four-spaces\r\n" +
					"\r\n"),
				expected: []byte("GET /target HTTP/1.1\r\n" +
					hostHeader + "\r\n" +
					"X-Weird : trailing-space-on-name\r\n" +
					"X-Tab:\tvalue-after-tab\r\n" +
					"X-Many:    four-spaces\r\n" +
					"\r\n"),
			},
			{
				name: "obs_fold_header",
				input: []byte("GET " + proxyFormURL("/target") + " HTTP/1.1\r\n" +
					"Host: placeholder\r\n" +
					"X-Fold: first-line\r\n" +
					"\tsecond-line\r\n" +
					"X-After: marker\r\n" +
					"\r\n"),
				expected: []byte("GET /target HTTP/1.1\r\n" +
					hostHeader + "\r\n" +
					"X-Fold: first-line\r\n" +
					"\tsecond-line\r\n" +
					"X-After: marker\r\n" +
					"\r\n"),
			},
			{
				name: "chunked_with_extensions",
				input: []byte("POST " + proxyFormURL("/target") + " HTTP/1.1\r\n" +
					"Host: placeholder\r\n" +
					"Transfer-Encoding: chunked\r\n" +
					"\r\n" +
					"4;foo=bar\r\nwiki\r\n" +
					"3\r\npes\r\n" +
					"0\r\n\r\n"),
				expected: []byte("POST /target HTTP/1.1\r\n" +
					hostHeader + "\r\n" +
					"Transfer-Encoding: chunked\r\n" +
					"\r\n" +
					"4;foo=bar\r\nwiki\r\n" +
					"3\r\npes\r\n" +
					"0\r\n\r\n"),
			},
			{
				name: "chunked_mixed_terminators",
				input: []byte("POST " + proxyFormURL("/target") + " HTTP/1.1\r\n" +
					"Host: placeholder\r\n" +
					"Transfer-Encoding: chunked\r\n" +
					"\r\n" +
					"4\nwiki\r\n" + // size ends bare LF, data ends CRLF
					"3\r\npes\n" + // size ends CRLF, data ends bare LF
					"0\r\n\r\n"),
				expected: []byte("POST /target HTTP/1.1\r\n" +
					hostHeader + "\r\n" +
					"Transfer-Encoding: chunked\r\n" +
					"\r\n" +
					"4\nwiki\r\n" +
					"3\r\npes\n" +
					"0\r\n\r\n"),
			},
			{
				name: "chunked_with_trailers",
				input: []byte("POST " + proxyFormURL("/target") + " HTTP/1.1\r\n" +
					"Host: placeholder\r\n" +
					"Transfer-Encoding: chunked\r\n" +
					"\r\n" +
					"5\r\nhello\r\n" +
					"0\r\n" +
					"X-Checksum: abc\r\n" +
					"\r\n"),
				expected: []byte("POST /target HTTP/1.1\r\n" +
					hostHeader + "\r\n" +
					"Transfer-Encoding: chunked\r\n" +
					"\r\n" +
					"5\r\nhello\r\n" +
					"0\r\n" +
					"X-Checksum: abc\r\n" +
					"\r\n"),
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				receivedCh := make(chan []byte, 1)
				acceptErrCh := make(chan error, 1)

				go func() {
					conn, err := upstreamListener.Accept()
					if err != nil {
						acceptErrCh <- err
						return
					}
					defer func() { _ = conn.Close() }()

					var accumulated []byte
					buf := make([]byte, 65536)
					for {
						_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
						if n, err := conn.Read(buf); n > 0 {
							accumulated = append(accumulated, buf[:n]...)
						} else if err != nil {
							break // timeout or EOF
						}
					}
					// Minimal response lets the proxy finish its read-response phase cleanly;
					// response content is not asserted by this test.
					_, _ = conn.Write([]byte("HTTP/1.1 204 No Content\r\n\r\n"))
					receivedCh <- accumulated
				}()

				clientConn, err := net.Dial("tcp", proxyAddr)
				require.NoError(t, err)
				defer func() { _ = clientConn.Close() }()

				_, err = clientConn.Write(tt.input)
				require.NoError(t, err)

				select {
				case received := <-receivedCh:
					if !assert.Equal(t, string(tt.expected), string(received)) {
						t.Logf("input: %q", tt.input)
					}
				case err := <-acceptErrCh:
					if !errors.Is(err, net.ErrClosed) {
						t.Fatalf("upstream accept: %v", err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("timed out waiting for upstream to receive request")
				}

				// Drain the synthetic 204 response so the proxy's writeback doesn't race
				// the deferred client Close during the next subtest's setup.
				_ = clientConn.SetReadDeadline(time.Now().Add(1 * time.Second))
				_, _ = io.Copy(io.Discard, clientConn)
			})
		}
	})
}

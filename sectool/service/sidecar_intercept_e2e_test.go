//go:build unix

package service

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"path/filepath"
	"strings"
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

// echoHandler is a stream sidecar that echoes every delivered chunk back on the
// same stream and records the exchange as a flow. It claims a probe connection
// when the opening bytes carry probeMarker.
type echoHandler struct {
	sidecar.BaseHandler
	conn        *sidecar.Conn
	probeMarker []byte
	opened      chan string
}

func (h *echoHandler) OnShutdown(int) {}

func (h *echoHandler) OnStreamOpen(p wire.StreamOpenParams) ([]wire.StreamWrite, error) {
	select {
	case h.opened <- p.StreamID:
	default:
	}
	return nil, nil
}

func (h *echoHandler) OnStreamDeliver(p wire.StreamWriteParams) ([]wire.StreamWrite, error) {
	_, _ = h.conn.PushFlow(context.Background(), wire.Flow{
		ProtocolTag: "echo/1",
		Direction:   "client_to_server",
		Request:     &wire.FlowMessage{Method: "MSG", Path: "/echo", Body: p.Data},
	})
	return []wire.StreamWrite{{StreamID: p.StreamID, Data: p.Data}}, nil
}

func (h *echoHandler) OnStreamEnded(wire.StreamEndedParams) {}

func (h *echoHandler) OnClaimProbe(p wire.ClaimProbeParams) (bool, error) {
	return bytes.HasPrefix(p.Data, h.probeMarker), nil
}

type interceptHarness struct {
	proxyAddr string
	mcp       *mcpclient.Client
	sc        *sidecar.Conn
	echo      *echoHandler
}

// startIntercept brings up a native backend + MCP server + sidecar listener and
// connects an echo sidecar declaring caps.
func startIntercept(t *testing.T, name string, caps wire.Capabilities, probeMarker []byte) *interceptHarness {
	t.Helper()
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
	require.NoError(t, backend.WaitReady(t.Context()))
	t.Cleanup(func() {
		srv.RequestShutdown()
		<-serverErr
	})

	mcpClient, err := mcpclient.Connect(t.Context(), "http://"+srv.mcpServer.Addr()+"/mcp")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mcpClient.Close() })

	sc, err := sidecar.Dial(socket, sidecar.Registration{
		Name:            name,
		Protocols:       []string{"echo/1"},
		Capabilities:    caps,
		ProtocolVersion: wire.ProtocolVersion{Major: wire.VersionMajor, Minor: wire.VersionMinor},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })

	echo := &echoHandler{conn: sc, probeMarker: probeMarker, opened: make(chan string, 4)}
	go func() { _ = sc.Serve(t.Context(), echo) }()
	return &interceptHarness{proxyAddr: backend.Addr(), mcp: mcpClient, sc: sc, echo: echo}
}

// roundTrip writes msg to conn and reads exactly len(msg) bytes back.
func roundTrip(t *testing.T, conn net.Conn, msg []byte) []byte {
	t.Helper()
	_, err := conn.Write(msg)
	require.NoError(t, err)
	buf := make([]byte, len(msg))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	return buf
}

// magic returns the base64 of a magic-byte prefix, as the wire form expects.
func magic(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestSidecarRawEarlyClaimE2E(t *testing.T) {
	h := startIntercept(t, "echo-raw",
		wire.Capabilities{EarlyClaim: &wire.EarlyClaim{MagicBytesPrefix: magic("ECHO")}}, nil)
	ctx := t.Context()

	conn, err := net.Dial("tcp", h.proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// Bytes round-trip through the sidecar over a real TCP connection.
	got := roundTrip(t, conn, []byte("ECHO hello world"))
	assert.Equal(t, "ECHO hello world", string(got))

	// A second write echoes back in order on the same stream.
	got = roundTrip(t, conn, []byte("ECHO again"))
	assert.Equal(t, "ECHO again", string(got))

	// The exchange is captured as a flow attributed to the sidecar.
	require.Eventually(t, func() bool {
		resp, perr := h.mcp.ProxyPoll(ctx, mcpclient.ProxyPollOpts{OutputMode: "flows", Adapter: "echo-raw", Limit: 100})
		return perr == nil && len(resp.Flows) > 0
	}, 5*time.Second, 20*time.Millisecond)
}

func TestSidecarRawEarlyClaimFallthrough(t *testing.T) {
	// A connection whose opening bytes do not match the magic prefix falls through
	// to the HTTP adapter unchanged.
	h := startIntercept(t, "echo-raw-ft",
		wire.Capabilities{EarlyClaim: &wire.EarlyClaim{MagicBytesPrefix: magic("ECHO")}}, nil)

	conn, err := net.Dial("tcp", h.proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.Write([]byte("GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n"))
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(line, "HTTP/"), "expected HTTP response, got %q", line)
}

func TestSidecarTLSTerminateEarlyClaimE2E(t *testing.T) {
	h := startIntercept(t, "echo-tls", wire.Capabilities{EarlyClaim: &wire.EarlyClaim{
		PortRange: wire.PortRange{Low: 443, High: 443},
		TLS:       &wire.TLSClaim{Terminate: true, SNIMatch: "echo.test"},
	}}, nil)

	conn, err := net.Dial("tcp", h.proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// Establish the CONNECT tunnel, then TLS. sectool terminates TLS with its fake
	// CA and hands the sidecar the decrypted bytes; the CA key never leaves sectool.
	_, err = conn.Write([]byte("CONNECT echo.test:443 HTTP/1.1\r\nHost: echo.test:443\r\n\r\n"))
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	for {
		line, rerr := br.ReadString('\n')
		require.NoError(t, rerr)
		if line == "\r\n" {
			break
		}
	}

	tlsConn := tls.Client(conn, &tls.Config{ServerName: "echo.test", InsecureSkipVerify: true})
	require.NoError(t, tlsConn.HandshakeContext(t.Context()))

	got := roundTrip(t, tlsConn, []byte("hello over tls"))
	assert.Equal(t, "hello over tls", string(got))
}

func TestSidecarProbeEarlyClaimE2E(t *testing.T) {
	// Marker must not start with 'P'/'C' so the accept peek stays narrow.
	h := startIntercept(t, "echo-probe",
		wire.Capabilities{EarlyClaim: &wire.EarlyClaim{Probe: true, ProbeMaxBytes: 64}}, []byte("XPROBE"))

	t.Run("probe_claims", func(t *testing.T) {
		conn, err := net.Dial("tcp", h.proxyAddr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		got := roundTrip(t, conn, []byte("XPROBE data here"))
		assert.Equal(t, "XPROBE data here", string(got))
	})

	t.Run("probe_declines_falls_through", func(t *testing.T) {
		conn, err := net.Dial("tcp", h.proxyAddr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		_, err = conn.Write([]byte("GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n"))
		require.NoError(t, err)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, rerr := bufio.NewReader(conn).ReadString('\n')
		require.NoError(t, rerr)
		assert.True(t, strings.HasPrefix(line, "HTTP/"))
	})
}

func TestSidecarProactiveStreamOutput(t *testing.T) {
	// Proactive stream_write (keepalive-style output) and sidecar-initiated
	// close_stream both reach the client socket outside an event Response.
	h := startIntercept(t, "echo-proactive",
		wire.Capabilities{EarlyClaim: &wire.EarlyClaim{MagicBytesPrefix: magic("ECHO")}}, nil)

	conn, err := net.Dial("tcp", h.proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	assert.Equal(t, "ECHO open", string(roundTrip(t, conn, []byte("ECHO open"))))
	var id string
	select {
	case id = <-h.echo.opened:
	case <-time.After(2 * time.Second):
		t.Fatal("stream never opened")
	}

	require.NoError(t, h.sc.StreamWrite(id, []byte("PING")))
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "PING", string(buf))

	require.NoError(t, h.sc.CloseStream(id, "done"))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(make([]byte, 16))
	require.ErrorIs(t, err, io.EOF)
}

func TestSidecarDeathTearsDownStream(t *testing.T) {
	h := startIntercept(t, "echo-teardown",
		wire.Capabilities{EarlyClaim: &wire.EarlyClaim{MagicBytesPrefix: magic("ECHO")}}, nil)

	conn, err := net.Dial("tcp", h.proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// Open the stream and confirm it is live.
	assert.Equal(t, "ECHO x", string(roundTrip(t, conn, []byte("ECHO x"))))
	select {
	case <-h.echo.opened:
	case <-time.After(2 * time.Second):
		t.Fatal("stream never opened")
	}

	// On sidecar disconnect the claimed client socket is closed, not orphaned
	require.NoError(t, h.sc.Close())
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(make([]byte, 16))
	require.ErrorIs(t, err, io.EOF)
}

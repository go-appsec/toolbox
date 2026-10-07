//go:build unix

package service

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/protocol"
	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// echoHandler is a stream sidecar that echoes every delivered chunk back on the
// same stream and records the exchange as a flow. It claims a probe connection
// when the opening bytes carry probeMarker.
type echoHandler struct {
	sidecar.BaseHandler
	t           *testing.T
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
	_, _, _ = h.conn.PushFlow(h.t.Context(), wire.Flow{
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
	sb := startSidecarBackend(t, scsidecar.Config{})
	sc := sb.dial(t, sidecar.Registration{
		Name:         name,
		Protocols:    []string{"echo/1"},
		Capabilities: caps,
	})

	echo := &echoHandler{t: t, conn: sc, probeMarker: probeMarker, opened: make(chan string, 4)}
	go func() { _ = sc.Serve(t.Context(), echo) }()
	return &interceptHarness{proxyAddr: sb.proxyAddr(), mcp: sb.mcp, sc: sc, echo: echo}
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
	t.Parallel()

	h := startIntercept(t, "echo-raw",
		wire.Capabilities{EarlyClaims: []wire.EarlyClaim{{MagicBytesPrefix: magic("ECHO")}}}, nil)

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", h.proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// Bytes round-trip through the sidecar over a real TCP connection.
	got := roundTrip(t, conn, []byte("ECHO hello world"))
	assert.Equal(t, "ECHO hello world", string(got))

	// A second write echoes back in order on the same stream.
	got = roundTrip(t, conn, []byte("ECHO again"))
	assert.Equal(t, "ECHO again", string(got))

	// The exchange is captured as flows attributed to the sidecar, at the echo path.
	var flows []protocol.FlowEntry
	require.Eventually(t, func() bool {
		resp, perr := h.mcp.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Adapter: "echo-raw", Limit: 100})
		if perr != nil || len(resp.Flows) == 0 {
			return false
		}
		flows = resp.Flows
		return true
	}, 5*time.Second, 20*time.Millisecond)
	assert.True(t, slices.ContainsFunc(flows, func(f protocol.FlowEntry) bool {
		return f.Path == "/echo" && f.Method == "MSG"
	}))
}

func TestSidecarRawEarlyClaimFallthrough(t *testing.T) {
	t.Parallel()

	// A connection whose opening bytes do not match the magic prefix falls through
	// to the HTTP adapter unchanged.
	h := startIntercept(t, "echo-raw-ft",
		wire.Capabilities{EarlyClaims: []wire.EarlyClaim{{MagicBytesPrefix: magic("ECHO")}}}, nil)

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", h.proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	assertHTTPFallthrough(t, conn)
}

func TestSidecarTLSTerminateEarlyClaimE2E(t *testing.T) {
	t.Parallel()

	h := startIntercept(t, "echo-tls", wire.Capabilities{EarlyClaims: []wire.EarlyClaim{{
		PortRange: wire.PortRange{Low: 443, High: 443},
		TLS:       &wire.TLSClaim{Terminate: true, SNIMatch: "echo.test"},
	}}}, nil)

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", h.proxyAddr)
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
	t.Parallel()

	// Marker must not start with 'P'/'C' so the accept peek stays narrow.
	h := startIntercept(t, "echo-probe",
		wire.Capabilities{EarlyClaims: []wire.EarlyClaim{{Probe: true, ProbeMaxBytes: 64}}}, []byte("XPROBE"))

	t.Run("probe_claims", func(t *testing.T) {
		var d net.Dialer
		conn, err := d.DialContext(t.Context(), "tcp", h.proxyAddr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		got := roundTrip(t, conn, []byte("XPROBE data here"))
		assert.Equal(t, "XPROBE data here", string(got))
	})

	t.Run("probe_declines_falls_through", func(t *testing.T) {
		var d net.Dialer
		conn, err := d.DialContext(t.Context(), "tcp", h.proxyAddr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		assertHTTPFallthrough(t, conn)
	})
}

func TestSidecarProactiveStreamOutput(t *testing.T) {
	t.Parallel()

	// Proactive stream_write (keepalive-style output) and sidecar-initiated
	// close_stream both reach the client socket outside an event Response.
	h := startIntercept(t, "echo-proactive",
		wire.Capabilities{EarlyClaims: []wire.EarlyClaim{{MagicBytesPrefix: magic("ECHO")}}}, nil)

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", h.proxyAddr)
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

	require.NoError(t, h.sc.CloseStream(id, "done", false))
	assertClientClosed(t, conn)
}

func TestSidecarDeathTearsDownStream(t *testing.T) {
	t.Parallel()

	h := startIntercept(t, "echo-teardown",
		wire.Capabilities{EarlyClaims: []wire.EarlyClaim{{MagicBytesPrefix: magic("ECHO")}}}, nil)

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", h.proxyAddr)
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
	assertClientClosed(t, conn)
}

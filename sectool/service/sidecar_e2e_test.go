//go:build unix

package service

import (
	"bufio"
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

// sidecarBackend is a live native backend + MCP server with the sidecar listener
// enabled, plus a connected MCP client. Tests dial their sidecar(s) against socket.
type sidecarBackend struct {
	backend *NativeProxyBackend
	srv     *Server
	mcp     *mcpclient.Client
	socket  string
}

// startSidecarProxy boots a native backend + MCP server with sidecars enabled over a
// temp UDS (cfg.Socket is defaulted when empty), and waits for readiness. Native
// origination is wired for invoke_adapter. An optional config path overrides the
// default (empty) config, e.g. to set a domain allowlist. No MCP client is connected
// yet — call connectMCP (or use startSidecarBackend) once any sidecars are registered.
func startSidecarProxy(t *testing.T, cfg scsidecar.Config, configPath ...string) *sidecarBackend {
	t.Helper()
	if cfg.Socket == "" {
		cfg.Socket = filepath.Join(t.TempDir(), "sidecar.sock")
	}
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if len(configPath) > 0 && configPath[0] != "" {
		cfgPath = configPath[0]
	}

	backend, err := NewNativeProxyBackend(t.Context(), 0, t.TempDir(), 10*1024*1024, store.MemProvider, proxy.TimeoutConfig{}, false)
	require.NoError(t, err)

	srv, err := NewServerWithStorageDir(MCPServerFlags{
		MCPPort:      -1,
		WorkflowMode: protocol.WorkflowModeNone,
		ConfigPath:   cfgPath,
	}, t.TempDir(), backend, newMockOastBackend(), newMockCrawlerBackend())
	require.NoError(t, err)
	srv.SetQuietLogging()

	cfg.NativeHTTPSend = srv.OriginateNative
	require.NoError(t, backend.EnableSidecars(t.Context(), cfg, srv, srv.replayHistoryStore))

	go func() { _ = srv.Run(t.Context()) }()
	srv.WaitTillStarted()
	require.NoError(t, backend.WaitReady(t.Context()))
	t.Cleanup(func() { srv.RequestShutdown() })

	return &sidecarBackend{backend: backend, srv: srv, socket: cfg.Socket}
}

// connectMCP connects (and stores) an MCP client to the server, registering close.
func (h *sidecarBackend) connectMCP(t *testing.T) *mcpclient.Client {
	t.Helper()
	mcpClient, err := mcpclient.Connect(t.Context(), "http://"+h.srv.mcpServer.Addr()+"/mcp")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mcpClient.Close() })
	h.mcp = mcpClient
	return mcpClient
}

// startSidecarBackend is startSidecarProxy followed by connectMCP — the common path
// for tests that don't need to register a sidecar before the client connects.
func startSidecarBackend(t *testing.T, cfg scsidecar.Config, configPath ...string) *sidecarBackend {
	t.Helper()
	h := startSidecarProxy(t, cfg, configPath...)
	h.connectMCP(t)
	return h
}

// proxyAddr is the native proxy's listen address.
func (h *sidecarBackend) proxyAddr() string { return h.backend.Addr() }

// dial connects a sidecar against the harness socket, defaulting the protocol
// version, and registers Close as a cleanup. The caller Serves its own handler.
func (h *sidecarBackend) dial(t *testing.T, reg sidecar.Registration) *sidecar.Conn {
	t.Helper()
	if reg.ProtocolVersion == (wire.ProtocolVersion{}) {
		reg.ProtocolVersion = wire.ProtocolVersion{Major: wire.VersionMajor, Minor: wire.VersionMinor}
	}
	conn, err := sidecar.Dial(t.Context(), h.socket, reg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// assertClientClosed asserts the proxy has closed the client connection (EOF).
func assertClientClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := conn.Read(make([]byte, 16))
	require.ErrorIs(t, err, io.EOF)
}

// assertHTTPFallthrough writes a plain HTTP request and asserts the response comes
// from the built-in HTTP adapter (status line begins with "HTTP/").
func assertHTTPFallthrough(t *testing.T, conn net.Conn) {
	t.Helper()
	_, err := conn.Write([]byte("GET http://127.0.0.1:9/ HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n"))
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(line, "HTTP/"), "expected HTTP response, got %q", line)
}

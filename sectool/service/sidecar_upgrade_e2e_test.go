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

// upgradeHandler is a sidecar that echoes post-upgrade bytes and records the
// stream_open params it received, so a test can assert the upgrade request context.
type upgradeHandler struct {
	sidecar.BaseHandler
	opened chan wire.StreamOpenParams
}

func (h *upgradeHandler) OnShutdown(int) {}

func (h *upgradeHandler) OnStreamOpen(p wire.StreamOpenParams) ([]wire.StreamWrite, error) {
	select {
	case h.opened <- p:
	default:
	}
	return nil, nil
}

func (h *upgradeHandler) OnStreamDeliver(p wire.StreamWriteParams) ([]wire.StreamWrite, error) {
	return []wire.StreamWrite{{StreamID: p.StreamID, Data: p.Data}}, nil
}

func (h *upgradeHandler) OnStreamEnded(wire.StreamEndedParams) {}

type upgradeHarness struct {
	proxyAddr string
	mcp       *mcpclient.Client
	opened    chan wire.StreamOpenParams
}

// startUpgrade brings up a native backend + MCP server + sidecar listener and
// connects an upgrade sidecar declaring caps.
func startUpgrade(t *testing.T, name string, caps wire.Capabilities) *upgradeHarness {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "sidecar.sock")
	backend, err := NewNativeProxyBackend(0, t.TempDir(), 10*1024*1024, store.MemProvider, proxy.TimeoutConfig{}, false)
	require.NoError(t, err)

	srv, err := NewServer(MCPServerFlags{
		MCPPort:      0,
		WorkflowMode: protocol.WorkflowModeNone,
		ConfigPath:   filepath.Join(t.TempDir(), "config.json"),
	}, backend, newMockOastBackend(), newMockCrawlerBackend())
	require.NoError(t, err)
	srv.SetQuietLogging()

	require.NoError(t, backend.EnableSidecars(scsidecar.Config{Socket: socket, NativeProxyPort: 0}, srv, srv.replayHistoryStore))

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

	sc, err := sidecar.Dial(t.Context(), socket, sidecar.Registration{
		Name:            name,
		Protocols:       []string{"custom/1"},
		Capabilities:    caps,
		ProtocolVersion: wire.ProtocolVersion{Major: wire.VersionMajor, Minor: wire.VersionMinor},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })

	h := &upgradeHandler{opened: make(chan wire.StreamOpenParams, 4)}
	go func() { _ = sc.Serve(t.Context(), h) }()
	return &upgradeHarness{proxyAddr: backend.Addr(), mcp: mcpClient, opened: h.opened}
}

// readHeadersUntilBlank reads the status line and discards the rest of an HTTP
// header block, returning the status line.
func readHeadersUntilBlank(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	status, err := br.ReadString('\n')
	require.NoError(t, err)
	for {
		line, rerr := br.ReadString('\n')
		require.NoError(t, rerr)
		if line == "\r\n" {
			return status
		}
	}
}

func headerValue(hs []wire.Header, name string) string {
	for _, h := range hs {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func TestSidecarUpgradeClaimHTTP101E2E(t *testing.T) {
	uc := &wire.UpgradeClaim{HostPattern: "ctrl.example.com", PathPattern: "/control", UpgradeSignal: "http_101", MethodSet: []string{"POST"}}
	h := startUpgrade(t, "upgrade-sidecar", wire.Capabilities{UpgradeClaims: []wire.UpgradeClaim{*uc}})
	ctx := t.Context()

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", h.proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.Write([]byte("POST http://ctrl.example.com/control HTTP/1.1\r\nHost: ctrl.example.com\r\n" +
		"Upgrade: custom-control-protocol\r\nConnection: Upgrade\r\n\r\n"))
	require.NoError(t, err)

	// sectool synthesizes the 101, echoing the custom upgrade token.
	br := bufio.NewReader(conn)
	status := readHeadersUntilBlank(t, br)
	assert.True(t, strings.HasPrefix(status, "HTTP/1.1 101"), status)

	// stream_open carried the captured triggering request's flow_id and headers.
	var open wire.StreamOpenParams
	select {
	case open = <-h.opened:
	case <-time.After(2 * time.Second):
		t.Fatal("stream never opened")
	}
	assert.NotEmpty(t, open.RequestFlowID)
	assert.Equal(t, "custom-control-protocol", headerValue(open.RequestHeaders, "Upgrade"))

	// Post-upgrade bytes route to the sidecar and echo back.
	_, err = conn.Write([]byte("noise-handshake"))
	require.NoError(t, err)
	buf := make([]byte, len("noise-handshake"))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(br, buf)
	require.NoError(t, err)
	assert.Equal(t, "noise-handshake", string(buf))

	// The triggering request is captured as a normal flow visible in history.
	resp, perr := h.mcp.ProxyPoll(ctx, mcpclient.ProxyPollOpts{OutputMode: "flows", Adapter: "upgrade-sidecar", Limit: 100})
	require.NoError(t, perr)
	assert.Contains(t, flowIDs(resp.Flows), open.RequestFlowID)
}

func TestSidecarUpgradeClaimConnectE2E(t *testing.T) {
	uc := &wire.UpgradeClaim{HostPattern: "tunnel.test", UpgradeSignal: "connect"}
	h := startUpgrade(t, "connect-upgrade", wire.Capabilities{UpgradeClaims: []wire.UpgradeClaim{*uc}})
	ctx := t.Context()

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", h.proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.Write([]byte("CONNECT tunnel.test:443 HTTP/1.1\r\nHost: tunnel.test:443\r\n\r\n"))
	require.NoError(t, err)

	// The CONNECT 200 is sent by sectool; the sidecar then owns the raw tunnel.
	br := bufio.NewReader(conn)
	status := readHeadersUntilBlank(t, br)
	assert.True(t, strings.HasPrefix(status, "HTTP/1.1 200"), status)

	var open wire.StreamOpenParams
	select {
	case open = <-h.opened:
	case <-time.After(2 * time.Second):
		t.Fatal("stream never opened")
	}
	assert.NotEmpty(t, open.RequestFlowID)
	assert.Empty(t, open.Path)

	_, err = conn.Write([]byte("raw-proto-bytes"))
	require.NoError(t, err)
	buf := make([]byte, len("raw-proto-bytes"))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.ReadFull(br, buf)
	require.NoError(t, err)
	assert.Equal(t, "raw-proto-bytes", string(buf))

	// The CONNECT trigger is captured as a flow attributed to the sidecar.
	resp, perr := h.mcp.ProxyPoll(ctx, mcpclient.ProxyPollOpts{OutputMode: "flows", Adapter: "connect-upgrade", Limit: 100})
	require.NoError(t, perr)
	assert.Contains(t, flowIDs(resp.Flows), open.RequestFlowID)
}

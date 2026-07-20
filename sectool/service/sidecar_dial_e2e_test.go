//go:build unix

package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"strconv"
	"sync"
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

// forwardHandler is a sidecar that, on each claimed client stream, dials an
// upstream via dial_upstream and proxies bytes between the two streams.
type forwardHandler struct {
	sidecar.BaseHandler
	conn   *sidecar.Conn
	dialFn func(*forwardHandler, wire.StreamOpenParams) (wire.DialUpstreamParams, error)

	mu      sync.Mutex
	pair    map[string]string
	dialErr chan error
	opened  chan string
}

func (h *forwardHandler) OnShutdown(int) {}

func (h *forwardHandler) OnStreamOpen(p wire.StreamOpenParams) ([]wire.StreamWrite, error) {
	params, err := h.dialFn(h, p)
	if err == nil {
		var up string
		if up, err = h.conn.DialUpstream(context.Background(), params); err == nil {
			h.mu.Lock()
			h.pair[p.StreamID] = up
			h.pair[up] = p.StreamID
			h.mu.Unlock()
			select {
			case h.opened <- p.StreamID:
			default:
			}
			return nil, nil
		}
	}
	select {
	case h.dialErr <- err:
	default:
	}
	return nil, err
}

func (h *forwardHandler) OnStreamDeliver(p wire.StreamWriteParams) ([]wire.StreamWrite, error) {
	h.mu.Lock()
	dst := h.pair[p.StreamID]
	h.mu.Unlock()
	if dst == "" {
		return nil, nil
	}
	return sidecar.Forward(dst, p.Data), nil
}

func (h *forwardHandler) OnStreamEnded(p wire.StreamEndedParams) {
	h.mu.Lock()
	dst := h.pair[p.StreamID]
	h.mu.Unlock()
	if dst != "" {
		_ = h.conn.CloseStream(dst, "peer closed")
	}
}

type forwardHarness struct {
	proxyAddr string
	mcp       *mcpclient.Client
	sc        *sidecar.Conn
	fwd       *forwardHandler
}

// startForward brings up a native backend + MCP server + sidecar listener and
// connects a forwarding sidecar. scope gates dial_upstream destinations (nil
// allows any).
func startForward(t *testing.T, name string, caps wire.Capabilities, scope func(string) (bool, string),
	dialFn func(*forwardHandler, wire.StreamOpenParams) (wire.DialUpstreamParams, error)) *forwardHarness {
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

	require.NoError(t, backend.EnableSidecars(scsidecar.Config{
		Socket:          socket,
		NativeProxyPort: 0,
		ScopeCheck:      scope,
	}, srv, srv.replayHistoryStore))

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
		Protocols:       []string{"forward/1"},
		Capabilities:    caps,
		ProtocolVersion: wire.ProtocolVersion{Major: wire.VersionMajor, Minor: wire.VersionMinor},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })

	fwd := &forwardHandler{conn: sc, dialFn: dialFn, pair: map[string]string{},
		dialErr: make(chan error, 4), opened: make(chan string, 4)}
	go func() { _ = sc.Serve(t.Context(), fwd) }()
	return &forwardHarness{proxyAddr: backend.Addr(), mcp: mcpClient, sc: sc, fwd: fwd}
}

// startEchoServer runs a TCP echo server, optionally over TLS, and returns its
// host and port.
func startEchoServer(t *testing.T, cert *tls.Certificate) (string, int) {
	t.Helper()
	var ln net.Listener
	var err error
	if cert != nil {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*cert}})
	} else {
		var lc net.ListenConfig
		ln, err = lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return host, port
}

// selfSignedCert builds a throwaway certificate for the TLS upstream test.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "echo.upstream"},
		DNSNames:     []string{"echo.upstream"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// hasDialAudit reports whether a dial_upstream audit flow was recorded for the
// adapter.
func hasDialAudit(t *testing.T, h *forwardHarness, adapter string) bool {
	t.Helper()
	resp, err := h.mcp.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
		OutputMode: "flows", Adapter: adapter, ProtocolTag: "dial_upstream", Limit: 100,
	})
	return err == nil && len(resp.Flows) > 0 && resp.Flows[0].Method == "DIAL"
}

func TestSidecarDialUpstreamForwardE2E(t *testing.T) {
	ehost, eport := startEchoServer(t, nil)
	h := startForward(t, "fwd-plain",
		wire.Capabilities{EarlyClaims: []wire.EarlyClaim{{MagicBytesPrefix: magic("FWD")}}}, nil,
		func(*forwardHandler, wire.StreamOpenParams) (wire.DialUpstreamParams, error) {
			return wire.DialUpstreamParams{Host: ehost, Port: eport}, nil
		})

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", h.proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// Bytes proxy client -> upstream -> client through sectool-owned sockets.
	assert.Equal(t, "FWD hello", string(roundTrip(t, conn, []byte("FWD hello"))))
	assert.Equal(t, "FWD again", string(roundTrip(t, conn, []byte("FWD again"))))

	// The dial is recorded in history for audit.
	require.Eventually(t, func() bool { return hasDialAudit(t, h, "fwd-plain") },
		5*time.Second, 20*time.Millisecond)
}

func TestSidecarDialUpstreamOutOfScope(t *testing.T) {
	ehost, eport := startEchoServer(t, nil)
	// Scope policy rejects the upstream host; the sidecar cannot reach it.
	h := startForward(t, "fwd-scope",
		wire.Capabilities{EarlyClaims: []wire.EarlyClaim{{MagicBytesPrefix: magic("FWD")}}},
		func(host string) (bool, string) { return host != ehost, "host out of scope" },
		func(*forwardHandler, wire.StreamOpenParams) (wire.DialUpstreamParams, error) {
			return wire.DialUpstreamParams{Host: ehost, Port: eport}, nil
		})

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", h.proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.Write([]byte("FWD blocked"))
	require.NoError(t, err)

	var dialErr error
	require.Eventually(t, func() bool {
		select {
		case dialErr = <-h.fwd.dialErr:
			return true
		default:
			return false
		}
	}, 5*time.Second, 20*time.Millisecond, "dial never attempted")
	var werr *wire.Error
	require.ErrorAs(t, dialErr, &werr)
	assert.Equal(t, wire.CodeDialScopeRejected, werr.Code)

	// The rejected stream is torn down (client socket is closed) not left to hit the deadline
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(make([]byte, 16))
	require.ErrorIs(t, err, io.EOF)
}

func TestSidecarDialUpstreamTLS(t *testing.T) {
	cert := selfSignedCert(t)
	ehost, eport := startEchoServer(t, &cert)
	h := startForward(t, "fwd-tls",
		wire.Capabilities{EarlyClaims: []wire.EarlyClaim{{MagicBytesPrefix: magic("FWD")}}}, nil,
		func(*forwardHandler, wire.StreamOpenParams) (wire.DialUpstreamParams, error) {
			return wire.DialUpstreamParams{Host: ehost, Port: eport,
				TLS: &wire.DialUpstreamTLS{Enabled: true, SNI: "echo.upstream", SkipVerify: true}}, nil
		})

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", h.proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// sectool terminates TLS toward the upstream and bridges cleartext.
	assert.Equal(t, "FWD over tls", string(roundTrip(t, conn, []byte("FWD over tls"))))
}

func TestSidecarDialUpstreamDefaultDest(t *testing.T) {
	ehost, eport := startEchoServer(t, nil)
	// dial_upstream with only parent_flow_id resolves the destination from the
	// parent flow the sidecar recorded.
	h := startForward(t, "fwd-default",
		wire.Capabilities{EarlyClaims: []wire.EarlyClaim{{MagicBytesPrefix: magic("FWD")}}}, nil,
		func(fh *forwardHandler, _ wire.StreamOpenParams) (wire.DialUpstreamParams, error) {
			fid, perr := fh.conn.PushFlow(context.Background(), wire.Flow{
				ProtocolTag: "session/1",
				Direction:   "bidirectional",
				Scheme:      "http",
				Port:        eport,
				Request: &wire.FlowMessage{Method: "TUNNEL", Path: "/sess",
					Headers: []wire.Header{{Name: "Host", Value: ehost}}},
			})
			if perr != nil {
				return wire.DialUpstreamParams{}, perr
			}
			return wire.DialUpstreamParams{ParentFlowID: fid}, nil
		})

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", h.proxyAddr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	assert.Equal(t, "FWD defaulted", string(roundTrip(t, conn, []byte("FWD defaulted"))))
}

package sidecar

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// localAddrConn is a net.Conn whose LocalAddr reports a fixed TCP port.
type localAddrConn struct {
	net.Conn
	port int
}

func (c localAddrConn) LocalAddr() net.Addr  { return &net.TCPAddr{Port: c.port} }
func (c localAddrConn) RemoteAddr() net.Addr { return &net.TCPAddr{Port: 1} }

func earlyCtx(localPort int, opening []byte) *protocol.EarlyClaimCtx {
	return &protocol.EarlyClaimCtx{
		ClientConn:   localAddrConn{port: localPort},
		ClientReader: bufio.NewReader(bytes.NewReader(opening)),
	}
}

func newTestBridge(ec *wire.EarlyClaim, healthy bool) *bridge {
	rec := &Record{Name: "sc", Capabilities: wire.Capabilities{EarlyClaim: ec}}
	rec.healthy.Store(healthy)
	return newBridge(rec, nil)
}

func newUpgradeBridge(uc *wire.UpgradeClaim, healthy bool) *bridge {
	rec := &Record{Name: "sc", Capabilities: wire.Capabilities{UpgradeClaim: uc}}
	rec.healthy.Store(healthy)
	return newBridge(rec, nil)
}

func upgradeCtx(signal, method, host, path, upgradeHdr string) *protocol.UpgradeClaimCtx {
	req := &types.RawHTTP1Request{Method: method, Path: path, Version: "HTTP/1.1"}
	if upgradeHdr != "" {
		req.Headers = types.Headers{{Name: "Upgrade", Value: upgradeHdr}}
	}
	return &protocol.UpgradeClaimCtx{Req: req, Target: &types.Target{Hostname: host, Port: 443}, Signal: signal}
}

func TestBridgeClaimEarly(t *testing.T) {
	t.Parallel()

	mqtt := []byte{0x10, 0x20} // CONNECT control packet prefix
	magic := wire.EarlyClaim{
		PortRange:        wire.PortRange{Low: 1883, High: 1883},
		MagicBytesPrefix: base64.StdEncoding.EncodeToString(mqtt),
	}

	t.Run("port_and_magic_match", func(t *testing.T) {
		b := newTestBridge(&magic, true)
		assert.True(t, b.ClaimEarly(earlyCtx(1883, mqtt)))
	})
	t.Run("port_out_of_range", func(t *testing.T) {
		b := newTestBridge(&magic, true)
		assert.False(t, b.ClaimEarly(earlyCtx(9999, mqtt)))
	})
	t.Run("magic_mismatch", func(t *testing.T) {
		b := newTestBridge(&magic, true)
		assert.False(t, b.ClaimEarly(earlyCtx(1883, []byte("GET /"))))
	})
	t.Run("unhealthy_declines", func(t *testing.T) {
		b := newTestBridge(&magic, false)
		assert.False(t, b.ClaimEarly(earlyCtx(1883, mqtt)))
	})
	t.Run("unset_range_matches_any_port", func(t *testing.T) {
		b := newTestBridge(&wire.EarlyClaim{}, true)
		assert.True(t, b.ClaimEarly(earlyCtx(40000, nil)))
	})
}

func TestBridgeClaimTLS(t *testing.T) {
	t.Parallel()

	ec := &wire.EarlyClaim{
		PortRange: wire.PortRange{Low: 443, High: 443},
		TLS:       &wire.TLSClaim{Terminate: true, SNIMatch: "ctrl.example.com"},
	}

	t.Run("sni_and_port_match", func(t *testing.T) {
		assert.True(t, newTestBridge(ec, true).ClaimTLS("ctrl.example.com", "ctrl.example.com", 443))
	})
	t.Run("sni_mismatch", func(t *testing.T) {
		assert.False(t, newTestBridge(ec, true).ClaimTLS("other.example.com", "other.example.com", 443))
	})
	t.Run("port_mismatch", func(t *testing.T) {
		assert.False(t, newTestBridge(ec, true).ClaimTLS("ctrl.example.com", "ctrl.example.com", 8443))
	})
	t.Run("non_terminating_claim_declines", func(t *testing.T) {
		raw := &wire.EarlyClaim{PortRange: wire.PortRange{Low: 443, High: 443}}
		assert.False(t, newTestBridge(raw, true).ClaimTLS("ctrl.example.com", "ctrl.example.com", 443))
	})
}

func TestBridgeClaimUpgrade(t *testing.T) {
	t.Parallel()

	t.Run("http_101_host_path_method_match", func(t *testing.T) {
		uc := &wire.UpgradeClaim{HostPattern: "ctrl.example.com", PathPattern: "/control", UpgradeSignal: "http_101", MethodSet: []string{"POST"}}
		b := newUpgradeBridge(uc, true)
		assert.True(t, b.ClaimUpgrade(upgradeCtx("http_101", "POST", "ctrl.example.com", "/control", "custom-control-protocol")))
	})
	t.Run("http_101_requires_upgrade_header", func(t *testing.T) {
		uc := &wire.UpgradeClaim{PathPattern: "/control", UpgradeSignal: "http_101"}
		b := newUpgradeBridge(uc, true)
		assert.False(t, b.ClaimUpgrade(upgradeCtx("http_101", "POST", "ctrl.example.com", "/control", "")))
	})
	t.Run("path_matched_ignoring_query", func(t *testing.T) {
		uc := &wire.UpgradeClaim{PathPattern: "/ws/*", UpgradeSignal: "http_101"}
		b := newUpgradeBridge(uc, true)
		assert.True(t, b.ClaimUpgrade(upgradeCtx("http_101", "GET", "h", "/ws/chat?token=1", "websocket")))
	})
	t.Run("method_not_in_set", func(t *testing.T) {
		uc := &wire.UpgradeClaim{PathPattern: "/control", UpgradeSignal: "http_101", MethodSet: []string{"POST"}}
		b := newUpgradeBridge(uc, true)
		assert.False(t, b.ClaimUpgrade(upgradeCtx("http_101", "GET", "h", "/control", "x")))
	})
	t.Run("host_mismatch", func(t *testing.T) {
		uc := &wire.UpgradeClaim{HostPattern: "ctrl.example.com", UpgradeSignal: "http_101"}
		b := newUpgradeBridge(uc, true)
		assert.False(t, b.ClaimUpgrade(upgradeCtx("http_101", "GET", "other.example.com", "/x", "websocket")))
	})
	t.Run("signal_mismatch", func(t *testing.T) {
		uc := &wire.UpgradeClaim{UpgradeSignal: "connect"}
		b := newUpgradeBridge(uc, true)
		assert.False(t, b.ClaimUpgrade(upgradeCtx("http_101", "GET", "h", "/x", "websocket")))
	})
	t.Run("connect_signal_match", func(t *testing.T) {
		uc := &wire.UpgradeClaim{HostPattern: "ctrl.example.com", UpgradeSignal: "connect"}
		b := newUpgradeBridge(uc, true)
		assert.True(t, b.ClaimUpgrade(upgradeCtx("connect", "CONNECT", "ctrl.example.com", "ctrl.example.com:443", "")))
	})
	t.Run("unhealthy_declines", func(t *testing.T) {
		uc := &wire.UpgradeClaim{PathPattern: "/control", UpgradeSignal: "http_101"}
		b := newUpgradeBridge(uc, false)
		assert.False(t, b.ClaimUpgrade(upgradeCtx("http_101", "POST", "h", "/control", "x")))
	})
}

func TestStreamWrite(t *testing.T) {
	t.Parallel()

	t.Run("unknown_stream", func(t *testing.T) {
		err := newStreamSet().streamWrite("missing", []byte("x"))
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeUnknownStream, err.Code)
	})
}

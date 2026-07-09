package sidecar

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// probeTimeout bounds a claim_probe round-trip during connection claiming.
const probeTimeout = 5 * time.Second

// bridge fronts a registered sidecar as an in-process adapter, routing matching
// proxy connections to the sidecar through its claim seams.
type bridge struct {
	rec     *Record
	streams *streamSet
	flows   FlowSink
}

func newBridge(rec *Record, flows FlowSink) *bridge {
	return &bridge{rec: rec, streams: newStreamSet(), flows: flows}
}

func (b *bridge) Name() string { return b.rec.Name }

// ClaimEarly reports whether any early_claim matches the accepted stream.
func (b *bridge) ClaimEarly(c *protocol.EarlyClaimCtx) bool {
	if !b.rec.Healthy() {
		return false
	}
	for i := range b.rec.Capabilities.EarlyClaims {
		ec := &b.rec.Capabilities.EarlyClaims[i]
		// raw accept: gate on local port (TLS re-entry already gated on SNI/host/port)
		if !c.TLSTerminated && !portInRange(localPort(c.ClientConn), ec.PortRange) {
			continue
		}
		if ec.MagicBytesPrefix != "" {
			prefix, err := base64.StdEncoding.DecodeString(ec.MagicBytesPrefix)
			if err != nil || len(prefix) == 0 || !matchPrefix(c, prefix) {
				continue
			}
		}
		if ec.Probe {
			if b.runProbe(c, ec) {
				return true
			}
			continue
		}
		return true
	}
	return false
}

// ServeEarly drives the claimed connection as a byte stream.
func (b *bridge) ServeEarly(ctx context.Context, c *protocol.EarlyClaimCtx) {
	b.streams.serveClient(ctx, b.rec, c)
}

// ClaimTLS reports whether any TLS-terminating early_claim gates this connection
// before termination on SNI and CONNECT target.
func (b *bridge) ClaimTLS(sni, host string, port int) bool {
	if !b.rec.Healthy() {
		return false
	}
	for i := range b.rec.Capabilities.EarlyClaims {
		ec := &b.rec.Capabilities.EarlyClaims[i]
		if ec.TLS == nil || !ec.TLS.Terminate {
			continue
		} else if !portInRange(port, ec.PortRange) {
			continue
		} else if ec.TLS.SNIMatch != "" && ec.TLS.SNIMatch != sni {
			continue
		} else if ec.HostMatch != "" && ec.HostMatch != host {
			continue
		}
		return true
	}
	return false
}

// ClaimUpgrade matches any of the sidecar's upgrade_claims against a parsed HTTP
// upgrade request or an established CONNECT tunnel.
func (b *bridge) ClaimUpgrade(c *protocol.UpgradeClaimCtx) bool {
	if !b.rec.Healthy() {
		return false
	}
	for i := range b.rec.Capabilities.UpgradeClaims {
		if matchUpgrade(&b.rec.Capabilities.UpgradeClaims[i], c) {
			return true
		}
	}
	return false
}

// ServeUpgrade captures the triggering request, synthesizes the upgrade response,
// and hands the post-upgrade bytes to the sidecar as a stream.
func (b *bridge) ServeUpgrade(ctx context.Context, c *protocol.UpgradeClaimCtx, conns protocol.UpgradeConns) {
	// sidecar drives its own upstream via dial_upstream; release any proxy pre-dial
	if conns.UpstreamConn != nil {
		_ = conns.UpstreamConn.Close()
	}
	resp := upgradeResponse(c)
	flowID := b.captureUpgrade(c, resp)
	// connect 200 already sent by the CONNECT handler; only http_101 needs sending
	if c.Signal != "connect" {
		var buf bytes.Buffer
		if _, err := conns.ClientConn.Write(resp.SerializeRaw(&buf)); err != nil {
			return
		}
	}
	host, path := upgradeInfo(c)
	b.streams.serveUpgrade(ctx, b.rec, conns, flowID, wireHeaders(c.Req.Headers), host, path)
}

// captureUpgrade records the triggering request (with the synthesized response) as
// a normal flow, returning its flow_id or "" when the capture filter excludes it.
func (b *bridge) captureUpgrade(c *protocol.UpgradeClaimCtx, resp *types.RawHTTP1Response) string {
	var port int
	scheme := types.SchemeHTTP
	if c.Target != nil {
		port, scheme = c.Target.Port, c.Target.Scheme()
	}
	now := time.Now()
	flow := &types.Flow{
		Adapter:           b.rec.Name,
		ProtocolTag:       types.ProtocolHTTP11,
		Scheme:            scheme,
		Port:              port,
		Request:           types.RequestToMessage(c.Req),
		Response:          types.ResponseToMessage(resp),
		StartedAt:         now,
		CompletedAt:       now,
		SidecarInstanceID: b.rec.InstanceID,
	}
	if !b.flows.ShouldCapture(flow) {
		return ""
	}
	return b.flows.Store(flow)
}

// shutdown closes the sidecar's active client streams; called when the sidecar
// connection drops so no claimed socket is orphaned.
func (b *bridge) shutdown() { b.streams.closeAll() }

// runProbe asks the sidecar whether the buffered opening bytes are its protocol.
func (b *bridge) runProbe(c *protocol.EarlyClaimCtx, ec *wire.EarlyClaim) bool {
	var host string
	var port int
	if c.Target != nil {
		host, port = c.Target.Hostname, c.Target.Port
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	var res wire.ClaimProbeResult
	if err := b.rec.peer.Call(ctx, wire.MethodClaimProbe, wire.ClaimProbeParams{
		Host:     host,
		Port:     port,
		PeerAddr: c.ClientConn.RemoteAddr().String(),
		Data:     openingBytes(c, ec.ProbeMaxBytes),
	}, &res); err != nil {
		return false
	}
	return res.Claim
}

// matchUpgrade reports whether an upgrade claim matches the request: same signal
// (defaulting http_101, which also requires an Upgrade header), method, and
// host/path patterns.
func matchUpgrade(uc *wire.UpgradeClaim, c *protocol.UpgradeClaimCtx) bool {
	signal := uc.UpgradeSignal
	if signal == "" {
		signal = "http_101"
	}
	if signal != c.Signal {
		return false
	}
	if signal == "http_101" && c.Req.GetHeader("Upgrade") == "" {
		return false
	}
	if len(uc.MethodSet) > 0 && !slices.Contains(uc.MethodSet, c.Req.Method) {
		return false
	}
	var host string
	if c.Target != nil {
		host = c.Target.Hostname
	}
	return patternMatch(uc.HostPattern, host) && patternMatch(uc.PathPattern, upgradePath(c))
}

// upgradeResponse builds the response sectool synthesizes for the claim: a 101 or
// a 200 for a connect tunnel.
func upgradeResponse(c *protocol.UpgradeClaimCtx) *types.RawHTTP1Response {
	if c.Signal == "connect" {
		return &types.RawHTTP1Response{Version: "HTTP/1.1", StatusCode: 200, StatusText: "Connection Established"}
	}
	return &types.RawHTTP1Response{
		Version:    "HTTP/1.1",
		StatusCode: 101,
		StatusText: "Switching Protocols",
		Headers: types.Headers{
			{Name: "Upgrade", Value: c.Req.GetHeader("Upgrade")},
			{Name: "Connection", Value: "Upgrade"},
		},
	}
}

// upgradeInfo derives the stream_open host/path from the triggering request.
func upgradeInfo(c *protocol.UpgradeClaimCtx) (host, path string) {
	if c.Target != nil {
		host = c.Target.Hostname
	}
	return host, upgradePath(c)
}

// upgradePath is the request path used for claim matching and stream_open.
func upgradePath(c *protocol.UpgradeClaimCtx) string {
	if c.Signal == "connect" {
		return ""
	}
	p, _, _ := strings.Cut(c.Req.Path, "?")
	return p
}

// wireHeaders converts parsed request headers to the wire shape for stream_open.
func wireHeaders(hs types.Headers) []wire.Header {
	if len(hs) == 0 {
		return nil
	}
	out := make([]wire.Header, len(hs))
	for i, h := range hs {
		out[i] = wire.Header{Name: h.Name, Value: h.Value}
	}
	return out
}

// matchPrefix reports whether the stream's opening bytes start with prefix,
// without consuming them.
func matchPrefix(c *protocol.EarlyClaimCtx, prefix []byte) bool {
	got, err := c.ClientReader.Peek(len(prefix))
	return err == nil && bytes.Equal(got, prefix)
}

// openingBytes peeks up to max buffered bytes without consuming them, blocking
// only for the first byte.
func openingBytes(c *protocol.EarlyClaimCtx, max int) []byte {
	if max <= 0 {
		max = 1
	}
	if _, err := c.ClientReader.Peek(1); err != nil {
		return nil
	}
	n := min(max, c.ClientReader.Buffered())
	b, _ := c.ClientReader.Peek(n)
	return b
}

// portInRange reports whether p falls in r; an unset range matches any port.
func portInRange(p int, r wire.PortRange) bool {
	if r.Low == 0 && r.High == 0 {
		return true
	}
	return p >= r.Low && p <= r.High
}

func localPort(c net.Conn) int {
	if a, ok := c.LocalAddr().(*net.TCPAddr); ok {
		return a.Port
	}
	return 0
}

// a bridge fulfills both proxy claim seams: TLSEarlyAdapter and UpgradeAdapter
var _ protocol.TLSEarlyAdapter = (*bridge)(nil)
var _ protocol.UpgradeAdapter = (*bridge)(nil)

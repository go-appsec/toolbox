package sidecar

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// probeTimeout bounds a claim_probe round-trip during connection claiming.
const probeTimeout = 5 * time.Second

// versionHTTP11 is the HTTP/1.1 protocol token used when synthesizing messages.
const versionHTTP11 = "HTTP/1.1"

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
	for i := range b.rec.early {
		ec := &b.rec.early[i]
		if !ec.matchScope(c) {
			continue
		} else if len(ec.prefix) > 0 && !matchPrefix(c, ec.prefix) {
			continue
		}
		if ec.probe {
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
// before termination on SNI and CONNECT target, returning the matched claim's
// additive cert spec (nil when the claim declares none).
func (b *bridge) ClaimTLS(sni, host string, port int) (*types.CertSpec, bool) {
	if !b.rec.Healthy() {
		return nil, false
	}
	for i := range b.rec.early {
		if ec := &b.rec.early[i]; ec.matchTLS(sni, host, port) {
			return ec.cert, true
		}
	}
	return nil, false
}

// ClaimUpgrade matches any of the sidecar's upgrade_claims against a parsed HTTP
// upgrade request or an established CONNECT tunnel.
func (b *bridge) ClaimUpgrade(c *protocol.UpgradeClaimCtx) bool {
	if !b.rec.Healthy() {
		return false
	}
	return slices.ContainsFunc(b.rec.upgrade, func(uc upgradeClaim) bool { return uc.match(c) })
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
func (b *bridge) runProbe(c *protocol.EarlyClaimCtx, ec *earlyClaim) bool {
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
		Data:     openingBytes(c, ec.probeMax),
	}, &res); err != nil {
		return false
	}
	return res.Claim
}

// upgradeResponse builds the response sectool synthesizes for the claim: a 101 or
// a 200 for a connect tunnel.
func upgradeResponse(c *protocol.UpgradeClaimCtx) *types.RawHTTP1Response {
	if c.Signal == signalConnect {
		return &types.RawHTTP1Response{Version: versionHTTP11, StatusCode: 200, StatusText: "Connection Established"}
	}
	return &types.RawHTTP1Response{
		Version:    versionHTTP11,
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

// a bridge fulfills both proxy claim seams: TLSEarlyAdapter and UpgradeAdapter
var _ protocol.TLSEarlyAdapter = (*bridge)(nil)
var _ protocol.UpgradeAdapter = (*bridge)(nil)

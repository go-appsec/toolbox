package proxy

import (
	"context"
	"crypto/tls"
	"log"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
)

// http1Adapter wraps the HTTP/1.1 handler; unconditional fallthrough, registered last.
type http1Adapter struct{ h *http1Handler }

func (http1Adapter) Name() string                            { return types.ProtocolHTTP11 }
func (http1Adapter) ClaimEarly(*protocol.EarlyClaimCtx) bool { return true }

func (a http1Adapter) ServeEarly(ctx context.Context, c *protocol.EarlyClaimCtx) {
	if c.TLSTerminated {
		a.h.HandleTLS(ctx, c.ClientConn, c.UpstreamConn, c.ClientReader, c.UpstreamReader, c.Target)
	} else {
		a.h.Handle(ctx, c.ClientConn, c.ClientReader)
	}
}

// http2Adapter wraps the HTTP/2 handler; claims the ALPN-h2 post-CONNECT stream.
type http2Adapter struct{ h *http2Handler }

func (http2Adapter) Name() string { return types.ProtocolH2 }

func (http2Adapter) ClaimEarly(c *protocol.EarlyClaimCtx) bool {
	return c.TLSTerminated && c.ALPN == alpnH2
}

func (a http2Adapter) ServeEarly(ctx context.Context, c *protocol.EarlyClaimCtx) {
	clientTLS, ok1 := c.ClientConn.(*tls.Conn)
	upstreamTLS, ok2 := c.UpstreamConn.(*tls.Conn)
	if ok1 && ok2 {
		a.h.Handle(ctx, clientTLS, upstreamTLS)
	} else {
		log.Printf("proxy: HTTP/2 handler not available or invalid connection types")
	}
}

// wsAdapter wraps the WebSocket handler; claims connections whose request was a WS handshake.
type wsAdapter struct{ h *webSocketHandler }

func (wsAdapter) Name() string { return types.ProtocolTagWS }

func (wsAdapter) ClaimUpgrade(c *protocol.UpgradeClaimCtx) bool {
	return isWebSocketUpgrade(c.Req)
}

func (a wsAdapter) ServeUpgrade(ctx context.Context, c *protocol.UpgradeClaimCtx, conns protocol.UpgradeConns) {
	if conns.UpstreamConn != nil {
		// TLS path: reuse upstream to avoid a race window
		a.h.HandleTLSWithUpstream(ctx, conns.ClientConn, conns.ClientReader, conns.UpstreamConn, conns.UpstreamReader, c.Req, c.Target)
	} else {
		a.h.Handle(ctx, conns.ClientConn, conns.ClientReader, c.Req, c.Target)
	}
}

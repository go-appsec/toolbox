package protocol

import (
	"bufio"
	"context"
	"net"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
)

// EarlyClaimCtx is the byte stream offered to early adapters at accept time:
// a raw TCP connection, or a TLS-decrypted post-CONNECT stream when TLSTerminated.
type EarlyClaimCtx struct {
	// Peek holds the opening bytes from ClientReader; nil for a post-CONNECT stream.
	Peek []byte
	// TLSTerminated is true for a decrypted post-CONNECT stream.
	TLSTerminated bool
	// ALPN is the negotiated protocol ("h2"/"http/1.1"/""); empty at raw accept.
	ALPN string
	// Target is the fixed upstream for a post-CONNECT stream; nil at raw accept.
	Target *types.Target

	ClientConn   net.Conn
	ClientReader *bufio.Reader

	// UpstreamConn and UpstreamReader are pre-dialed for a post-CONNECT stream; nil at raw accept.
	UpstreamConn   net.Conn
	UpstreamReader *bufio.Reader
}

// UpgradeClaimCtx is the parsed HTTP/1.x request offered to upgrade adapters.
type UpgradeClaimCtx struct {
	Req    *types.RawHTTP1Request
	Target *types.Target
	// Signal is the upgrade signal driving this claim: "http_101" after a parsed
	// upgrade request, or "connect" after a CONNECT tunnel is established.
	Signal string
}

// UpgradeConns are the connections handed to an upgrade adapter when it serves.
type UpgradeConns struct {
	ClientConn   net.Conn
	ClientReader *bufio.Reader
	// UpstreamConn and UpstreamReader are non-nil on the TLS path (reusing the
	// existing upstream) and nil on the plain path (the adapter dials its own).
	UpstreamConn   net.Conn
	UpstreamReader *bufio.Reader
}

// EarlyAdapter claims and serves a freshly accepted byte stream.
type EarlyAdapter interface {
	Name() string
	// ClaimEarly reports whether this adapter takes the connection.
	ClaimEarly(c *EarlyClaimCtx) bool
	// ServeEarly drives the connection; called only when ClaimEarly returned true.
	ServeEarly(ctx context.Context, c *EarlyClaimCtx)
}

// TLSEarlyAdapter gates a TLS connection before termination, by the ClientHello
// SNI and the CONNECT target. Implemented by sidecar bridges whose early claim
// sets tls.terminate; the connect handler MITMs a matched connection with the
// fake CA and re-offers the decrypted stream through ServeEarly.
type TLSEarlyAdapter interface {
	EarlyAdapter
	ClaimTLS(sni, host string, port int) bool
}

// UpgradeAdapter claims and serves a connection after an HTTP/1.x upgrade signal.
type UpgradeAdapter interface {
	Name() string
	// ClaimUpgrade reports whether this adapter takes the upgraded connection.
	ClaimUpgrade(c *UpgradeClaimCtx) bool
	// ServeUpgrade drives the connection; called only when ClaimUpgrade returned true.
	ServeUpgrade(ctx context.Context, c *UpgradeClaimCtx, conns UpgradeConns)
}

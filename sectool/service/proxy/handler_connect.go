package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
)

// ALPN protocol identifiers (RFC 7301): on-the-wire tokens exchanged during TLS negotiation
const (
	alpnH2    = "h2"
	alpnHTTP1 = "http/1.1"
)

// connectHandler handles CONNECT requests for HTTPS MITM interception.
type connectHandler struct {
	certManager  *CertManager
	http1Handler *http1Handler
	http2Handler *http2Handler
	reg          *protocol.Registry
	history      *HistoryStore
	maxBodyBytes int

	// Server capability cache: host:port -> negotiated protocol; avoids repeated probe latency
	// TODO - Consider a 30-minute TTL on cache entries for long-running sessions
	capsMu     sync.RWMutex
	serverCaps map[string]string

	timeouts TimeoutConfig
}

// newConnectHandler creates a new CONNECT handler.
func newConnectHandler(certManager *CertManager, http1Handler *http1Handler, http2Handler *http2Handler, history *HistoryStore, maxBodyBytes int, timeouts TimeoutConfig) *connectHandler {
	return &connectHandler{
		certManager:  certManager,
		http1Handler: http1Handler,
		http2Handler: http2Handler,
		history:      history,
		maxBodyBytes: maxBodyBytes,
		serverCaps:   make(map[string]string),
		timeouts:     timeouts,
	}
}

// SetRuleApplier propagates the rule applier to child handlers.
func (h *connectHandler) SetRuleApplier(applier types.RuleApplier) {
	h.http1Handler.ruleApplier = applier
	if h.http2Handler != nil {
		h.http2Handler.SetRuleApplier(applier)
	}
}

// Handle processes a CONNECT request for HTTPS tunneling with MITM.
func (h *connectHandler) Handle(ctx context.Context, clientConn net.Conn, clientReader *bufio.Reader) {
	target, err := h.parseConnectRequest(clientReader)
	if err != nil {
		log.Printf("proxy: failed to parse CONNECT request: %v", err)
		h.sendConnectError(clientConn, 400, "Bad Request")
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		log.Printf("proxy: failed to send CONNECT response: %v", err)
		return
	}

	// Connect-signal sidecar may claim the established tunnel before TLS, taking the raw post-CONNECT bytes
	hostPort := net.JoinHostPort(target.Hostname, strconv.Itoa(target.Port))
	uc := &protocol.UpgradeClaimCtx{
		Req: &types.RawHTTP1Request{
			Method:  "CONNECT",
			Path:    hostPort,
			Version: "HTTP/1.1",
			Headers: []types.Header{{Name: "Host", Value: hostPort}},
		},
		Target: target,
		Signal: "connect",
	}
	if a, ok := h.reg.ClaimUpgrade(uc); ok {
		a.ServeUpgrade(ctx, uc, protocol.UpgradeConns{ClientConn: clientConn, ClientReader: clientReader})
		return
	}

	h.handleTLS(ctx, clientConn, clientReader, target)
}

// readerConn reads through the reader and delegates writes/deadlines to the embedded conn.
type readerConn struct {
	net.Conn

	r io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// parseConnectRequest parses "CONNECT host:port HTTP/1.1" and reads remaining headers.
func (h *connectHandler) parseConnectRequest(reader *bufio.Reader) (*types.Target, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read request line: %w", err)
	}
	line = strings.TrimSpace(line)

	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 || parts[0] != "CONNECT" {
		return nil, errors.New("invalid CONNECT request line")
	}

	hostPort := parts[1]

	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
		portStr = "443"
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %s", portStr)
	}

	// discard remaining headers until empty line
	for {
		headerLine, readErr := reader.ReadString('\n')
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("read headers: %w", readErr)
		}
		if strings.TrimSpace(headerLine) == "" {
			break
		}
	}

	return &types.Target{
		Hostname:  host,
		Port:      port,
		UsesHTTPS: true,
	}, nil
}

// handleTLS performs the client TLS handshake and routes the decrypted
// post-CONNECT stream by negotiated protocol. Upstream protocol probing is
// deferred until the client hello is seen so the presented ALPN can be matched.
func (h *connectHandler) handleTLS(ctx context.Context, clientConn net.Conn, clientReader *bufio.Reader, target *types.Target) {
	targetAddr := fmt.Sprintf("%s:%d", target.Hostname, target.Port)

	// Variables to capture from GetConfigForClient callback
	var upstreamConn net.Conn
	var negotiatedProto string
	var probeErr error
	var sni string
	// tlsBridge set when a sidecar claims by SNI/target: sectool terminates TLS with
	// the fake CA and hands it the decrypted stream, no upstream dial
	var tlsBridge protocol.TLSEarlyAdapter

	// Create TLS config with GetConfigForClient for delayed protocol probing
	tlsConfig := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// Capture SNI
			sni = hello.ServerName
			if sni == "" {
				sni = target.Hostname
			}

			// Log potential domain fronting
			if sni != target.Hostname {
				log.Printf("proxy: SNI mismatch - CONNECT target=%s, SNI=%s (possible domain fronting)", target.Hostname, sni)
			}

			// A sidecar tls.terminate claim takes precedence: skip the upstream dial
			if b, spec, ok := h.reg.MatchTLS(sni, target.Hostname, target.Port); ok {
				tlsBridge = b
				cert, certErr := h.certManager.GetCertificate(sni, spec)
				if certErr != nil {
					return nil, certErr
				}
				return &tls.Config{Certificates: []tls.Certificate{*cert}}, nil
			}

			// Probe or use cached protocol
			upstreamConn, negotiatedProto, probeErr = h.probeOrConnect(ctx, targetAddr, sni, hello.SupportedProtos)
			if probeErr != nil {
				return nil, probeErr
			}

			// Mint for SNI, mirroring the upstream leaf's SANs
			cert, certErr := h.certManager.GetCertificate(sni, upstreamMirrorSpec(upstreamConn))
			if certErr != nil {
				if upstreamConn != nil {
					_ = upstreamConn.Close()
				}
				return nil, certErr
			}

			// Return config with only the negotiated protocol
			var nextProtos []string
			if negotiatedProto != "" {
				nextProtos = []string{negotiatedProto}
			}

			return &tls.Config{
				Certificates: []tls.Certificate{*cert},
				NextProtos:   nextProtos,
			}, nil
		},
	}

	// Read through clientReader so bytes past the CONNECT feed the handshake instead droping
	clientTLS := tls.Server(&readerConn{Conn: clientConn, r: clientReader}, tlsConfig)

	// Perform handshake (this triggers GetConfigForClient)
	if err := clientTLS.HandshakeContext(ctx); err != nil {
		if !isConnClosedErr(err) {
			log.Printf("proxy: TLS handshake failed: %v", err)
		}
		if upstreamConn != nil {
			_ = upstreamConn.Close()
		}
		return
	}

	// Sidecar claimed the connection: hand it the decrypted stream; decrypted matchers
	// may still decline, then we dial upstream and fall through to the HTTP path
	if tlsBridge != nil {
		c := &protocol.EarlyClaimCtx{
			TLSTerminated: true,
			Target:        target,
			ClientConn:    clientTLS,
			ClientReader:  bufio.NewReader(clientTLS),
		}
		if tlsBridge.ClaimEarly(c) {
			tlsBridge.ServeEarly(ctx, c)
			_ = clientTLS.Close()
			return
		}
		// Client handshake completed with no ALPN (claim cert offered none), so client
		// speaks HTTP/1.1; dial upstream with no ALPN too to avoid an h2/h1 split
		var err error
		if upstreamConn, negotiatedProto, err = h.probeOrConnect(ctx, targetAddr, sni, nil); err != nil {
			log.Printf("proxy: upstream probe failed: %v", err)
			_ = clientTLS.Close()
			return
		}
		h.routeByClientProto(ctx, clientTLS, upstreamConn, negotiatedProto, targetAddr, sni, target)
		return
	}

	if probeErr != nil || upstreamConn == nil {
		log.Printf("proxy: upstream probe failed: %v", probeErr)
		_ = clientTLS.Close()
		return
	}

	// Route based on negotiated protocol
	h.routeByClientProto(ctx, clientTLS, upstreamConn, negotiatedProto, targetAddr, sni, target)
}

// routeByClientProto re-dials upstream to match the client's negotiated ALPN when it
// diverges from the upstream negotiation, then routes the decrypted stream.
func (h *connectHandler) routeByClientProto(ctx context.Context, clientTLS *tls.Conn, upstreamConn net.Conn, negotiatedProto, targetAddr, sni string, target *types.Target) {
	clientProto := clientTLS.ConnectionState().NegotiatedProtocol
	if negotiatedProto == alpnH2 && clientProto != alpnH2 {
		// upstream/cache said h2 but the client offered no h2 (e.g. no ALPN); re-dial
		// upstream without forcing h2 so both sides speak HTTP/1.1, bypassing the cache
		newUp, err := h.dialUpstream(ctx, targetAddr, sni, nil)
		if err != nil {
			log.Printf("proxy: upstream re-dial for client proto %q failed: %v", clientProto, err)
			_ = clientTLS.Close()
			_ = upstreamConn.Close()
			return
		}
		_ = upstreamConn.Close()
		upstreamConn = newUp
		negotiatedProto = clientProto // "" routes to the http1 fallthrough adapter
	}
	h.routeByProtocol(ctx, clientTLS, upstreamConn, negotiatedProto, target)
}

// probeOrConnect returns an open upstream connection with the appropriate protocol.
// Uses cached protocol if available, otherwise probes the server.
func (h *connectHandler) probeOrConnect(ctx context.Context, targetAddr, sni string, clientALPN []string) (net.Conn, string, error) {
	// Check cache
	h.capsMu.RLock()
	cachedProto, cached := h.serverCaps[targetAddr]
	h.capsMu.RUnlock()

	if cached {
		// Connect with cached protocol preference
		conn, err := h.dialUpstream(ctx, targetAddr, sni, []string{cachedProto})
		if err != nil {
			// Cache might be stale, invalidate and retry with full probe
			h.capsMu.Lock()
			delete(h.serverCaps, targetAddr)
			h.capsMu.Unlock()
		} else {
			return conn, cachedProto, nil
		}
	}

	return h.probeUpstream(ctx, targetAddr, sni, clientALPN)
}

// probeUpstream connects to the server and discovers its protocol capabilities.
func (h *connectHandler) probeUpstream(ctx context.Context, targetAddr, sni string, clientALPN []string) (net.Conn, string, error) {
	conn, err := h.dialUpstream(ctx, targetAddr, sni, clientALPN)
	if err != nil {
		return nil, "", err
	}

	// Determine negotiated protocol
	var negotiatedProto string
	if tlsConn, ok := conn.(*tls.Conn); ok {
		negotiatedProto = tlsConn.ConnectionState().NegotiatedProtocol
	}

	// Default to HTTP/1.1 if no ALPN negotiated
	if negotiatedProto == "" {
		negotiatedProto = alpnHTTP1
	}

	// Cache the result
	h.capsMu.Lock()
	h.serverCaps[targetAddr] = negotiatedProto
	h.capsMu.Unlock()

	return conn, negotiatedProto, nil
}

// dialUpstream establishes a TLS connection to the upstream server.
func (h *connectHandler) dialUpstream(ctx context.Context, targetAddr, sni string, alpn []string) (net.Conn, error) {
	tlsDialer := &tls.Dialer{
		NetDialer: &net.Dialer{
			Timeout: h.timeouts.DialTimeout,
		},
		Config: &tls.Config{
			ServerName:         sni,
			InsecureSkipVerify: true, // Required for security testing
			MinVersion:         tls.VersionTLS10,
			NextProtos:         alpn,
		},
	}

	return tlsDialer.DialContext(ctx, "tcp", targetAddr)
}

// routeByProtocol feeds the decrypted post-CONNECT stream through the early-claim
// seam, keyed on the negotiated ALPN (h2 -> HTTP/2 adapter, else HTTP/1.1 fallthrough).
func (h *connectHandler) routeByProtocol(ctx context.Context, clientTLS, upstreamConn net.Conn, alpn string, target *types.Target) {
	defer func() {
		_ = clientTLS.Close()
		_ = upstreamConn.Close()
	}()

	h.reg.DispatchEarly(ctx, &protocol.EarlyClaimCtx{
		TLSTerminated:  true,
		ALPN:           alpn,
		Target:         target,
		ClientConn:     clientTLS,
		ClientReader:   bufio.NewReader(clientTLS),
		UpstreamConn:   upstreamConn,
		UpstreamReader: bufio.NewReader(upstreamConn),
	})
}

// upstreamMirrorSpec builds an additive cert spec from the upstream leaf's SANs
// (and CommonName). Returns nil when conn is not TLS or presents no peer cert.
func upstreamMirrorSpec(conn net.Conn) *types.CertSpec {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}
	peers := tc.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return nil
	}

	leaf := peers[0]
	spec := &types.CertSpec{
		DNSNames:    leaf.DNSNames,
		IPAddresses: leaf.IPAddresses,
		URIs:        leaf.URIs,
		Emails:      leaf.EmailAddresses,
		CommonName:  leaf.Subject.CommonName,
	}
	if spec.Empty() {
		return nil
	}
	return spec
}

// sendConnectError writes an HTTP error response for CONNECT failures.
func (h *connectHandler) sendConnectError(conn net.Conn, code int, message string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s\n",
		code, message, message)
	_, _ = conn.Write([]byte(resp))
}

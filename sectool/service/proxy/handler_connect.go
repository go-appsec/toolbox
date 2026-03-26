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
)

// connectHandler handles CONNECT requests for HTTPS MITM interception.
type connectHandler struct {
	certManager  *CertManager
	http1Handler *http1Handler
	http2Handler *http2Handler
	history      *HistoryStore
	maxBodyBytes int

	// Server capability cache: host:port -> negotiated protocol ("h2" or "http/1.1")
	// Avoids repeated probe latency for the same server
	// TODO - Consider adding a 30-minute TTL on cache entries for long-running sessions
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
func (h *connectHandler) SetRuleApplier(applier RuleApplier) {
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

	h.handleTLS(ctx, clientConn, target)
}

// parseConnectRequest parses "CONNECT host:port HTTP/1.1" and reads remaining headers.
func (h *connectHandler) parseConnectRequest(reader *bufio.Reader) (*Target, error) {
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

	// Read and discard remaining headers until empty line
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

	return &Target{
		Hostname:  host,
		Port:      port,
		UsesHTTPS: true,
	}, nil
}

// handleTLS performs TLS handshake with delayed protocol probing.
// The probe happens inside GetConfigForClient to ensure protocol matching.
func (h *connectHandler) handleTLS(ctx context.Context, clientConn net.Conn, target *Target) {
	targetAddr := fmt.Sprintf("%s:%d", target.Hostname, target.Port)

	// Variables to capture from GetConfigForClient callback
	var upstreamConn net.Conn
	var negotiatedProto string
	var probeErr error

	// Create TLS config with GetConfigForClient for delayed protocol probing
	tlsConfig := &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			// Capture SNI
			sni := hello.ServerName
			if sni == "" {
				sni = target.Hostname
			}

			// Log potential domain fronting
			if sni != target.Hostname {
				log.Printf("proxy: SNI mismatch - CONNECT target=%s, SNI=%s (possible domain fronting)", target.Hostname, sni)
			}

			// Probe or use cached protocol
			upstreamConn, negotiatedProto, probeErr = h.probeOrConnect(ctx, targetAddr, sni, hello.SupportedProtos)
			if probeErr != nil {
				return nil, probeErr
			}

			// Get certificate for SNI
			cert, certErr := h.certManager.GetCertificate(sni)
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

	// Wrap client connection in TLS
	clientTLS := tls.Server(clientConn, tlsConfig)

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

	if probeErr != nil || upstreamConn == nil {
		log.Printf("proxy: upstream probe failed: %v", probeErr)
		_ = clientTLS.Close()
		return
	}

	// Route based on negotiated protocol
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
		negotiatedProto = "http/1.1"
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

// routeByProtocol routes the connection to the appropriate protocol handler.
func (h *connectHandler) routeByProtocol(ctx context.Context, clientTLS, upstreamConn net.Conn, protocol string, target *Target) {
	defer func() {
		_ = clientTLS.Close()
		_ = upstreamConn.Close()
	}()

	switch protocol {
	case "h2":
		// HTTP/2 MITM
		clientTLSConn, ok1 := clientTLS.(*tls.Conn)
		upstreamTLSConn, ok2 := upstreamConn.(*tls.Conn)
		if ok1 && ok2 && h.http2Handler != nil {
			h.http2Handler.Handle(ctx, clientTLSConn, upstreamTLSConn)
		} else {
			log.Printf("proxy: HTTP/2 handler not available or invalid connection types")
		}

	default:
		// HTTP/1.1 or no ALPN
		clientReader := bufio.NewReader(clientTLS)
		upstreamReader := bufio.NewReader(upstreamConn)
		h.http1Handler.HandleTLS(ctx, clientTLS, upstreamConn, clientReader, upstreamReader, target)
	}
}

// sendConnectError writes an HTTP error response for CONNECT failures.
func (h *connectHandler) sendConnectError(conn net.Conn, code int, message string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s\n",
		code, message, message)
	_, _ = conn.Write([]byte(resp))
}

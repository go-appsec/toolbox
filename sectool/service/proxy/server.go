package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/go-appsec/llm-security-toolbox/sectool/service/store"
)

// ProxyServer is an HTTP proxy server that captures request/response pairs.
type ProxyServer struct {
	listener net.Listener
	addr     string

	// Configuration
	maxBodyBytes int

	// Certificate management for HTTPS MITM
	certManager *CertManager

	// History storage
	history *HistoryStore

	// Handlers for different protocols
	http1Handler   *http1Handler
	http2Handler   *http2Handler
	connectHandler *connectHandler
	wsHandler      *webSocketHandler

	// Shutdown coordination
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	closed      atomic.Bool
	running     atomic.Bool
	activeConns sync.Map // tracks active connections for force-close on shutdown
}

// NewProxyServer creates a new proxy server with HTTPS MITM support.
// configDir is the directory for CA certificates (e.g., ~/.sectool).
// maxBodyBytes limits request and response body sizes stored in history.
func NewProxyServer(port int, configDir string, maxBodyBytes int) (*ProxyServer, error) {
	certManager, err := newCertManager(configDir)
	if err != nil {
		return nil, fmt.Errorf("create cert manager: %w", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	storage := store.NewMemStorage()
	history := newHistoryStore(storage)

	wsHandler := newWebSocketHandler(history, certManager)

	http1Handler := &http1Handler{
		history:      history,
		maxBodyBytes: maxBodyBytes,
		wsHandler:    wsHandler,
	}

	http2Handler := newHTTP2Handler(history, maxBodyBytes)

	connectHandler := newConnectHandler(certManager, http1Handler, http2Handler, history, maxBodyBytes)

	s := &ProxyServer{
		listener:       listener,
		addr:           listener.Addr().String(),
		maxBodyBytes:   maxBodyBytes,
		certManager:    certManager,
		history:        history,
		http1Handler:   http1Handler,
		http2Handler:   http2Handler,
		connectHandler: connectHandler,
		wsHandler:      wsHandler,
		ctx:            ctx,
		cancel:         cancel,
	}

	return s, nil
}

// Addr returns the proxy listener address (e.g., "127.0.0.1:12345").
func (s *ProxyServer) Addr() string {
	return s.addr
}

// History returns the history store for external access.
func (s *ProxyServer) History() *HistoryStore {
	return s.history
}

// CertManager returns the certificate manager for external access.
func (s *ProxyServer) CertManager() *CertManager {
	return s.certManager
}

// SetRuleApplier sets the rule applier for all handlers.
// Call after construction but before Serve().
func (s *ProxyServer) SetRuleApplier(applier RuleApplier) {
	s.http1Handler.ruleApplier = applier
	s.http2Handler.SetRuleApplier(applier)
	s.connectHandler.SetRuleApplier(applier)
	s.wsHandler.SetRuleApplier(applier)
}

// WaitReady blocks until Serve() has entered its accept loop.
func (s *ProxyServer) WaitReady(ctx context.Context) error {
	for !s.running.Load() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			runtime.Gosched()
		}
	}
	return nil
}

// Serve starts accepting connections. Blocks until shutdown.
func (s *ProxyServer) Serve() error {
	s.running.Store(true)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.closed.Load() {
				return nil
			}
			select {
			case <-s.ctx.Done():
				return nil
			default:
			}
			log.Printf("proxy: accept error: %v", err)
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn)
		}()
	}
}

// handleConnection determines the protocol and routes to the appropriate handler.
func (s *ProxyServer) handleConnection(conn net.Conn) {
	s.activeConns.Store(conn, struct{}{})
	defer func() {
		s.activeConns.Delete(conn)
		_ = conn.Close()
	}()

	br := bufio.NewReader(conn)

	// Peek first bytes to detect protocol
	peek, err := br.Peek(24)
	if err != nil {
		// Connection closed or error before any data
		return
	}

	// HTTP/2 preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	h2Preface := []byte("PRI * HTTP/2.0")
	if bytes.HasPrefix(peek, h2Preface) {
		log.Printf("proxy: H2C not supported, closing connection from %s", conn.RemoteAddr())
		return
	}

	// CONNECT requests - handle HTTPS MITM
	if bytes.HasPrefix(peek, []byte("CONNECT ")) {
		s.connectHandler.Handle(s.ctx, conn, br)
		return
	}

	// Default: HTTP/1.1 request
	s.http1Handler.Handle(s.ctx, conn, br)
}

// Shutdown gracefully stops the server.
func (s *ProxyServer) Shutdown(ctx context.Context) error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil // already closed
	}

	// Stop accepting new connections
	_ = s.listener.Close()

	// Signal handlers to finish
	s.cancel()

	// Wait for in-flight connections with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All connections finished
	case <-ctx.Done():
		// Timeout - force-close all active connections
		s.activeConns.Range(func(key, _ any) bool {
			if conn, ok := key.(net.Conn); ok {
				_ = conn.Close()
			}
			return true
		})
		<-done // wait for goroutines to exit after connections closed
	}

	s.history.Close()
	return nil
}

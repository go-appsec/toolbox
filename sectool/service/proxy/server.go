package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

// TimeoutConfig holds configurable timeout values for proxy operations.
type TimeoutConfig struct {
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

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

	// registry: per-connection adapter claim/dispatch
	registry *protocol.Registry

	// Shutdown coordination
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	closed       atomic.Bool
	serveStarted atomic.Bool
	running      atomic.Bool
	activeConns  sync.Map // tracks active connections for force-close on shutdown
}

// NewProxyServer creates a new proxy server with HTTPS MITM support.
// configDir is the directory for CA certificates (e.g., ~/.sectool).
// maxBodyBytes limits request and response body sizes stored in history.
// historyStorage is the storage backend for proxy history entries.
// fullBuffer forces whole-body buffering for response body rules instead of streaming.
func NewProxyServer(port int, configDir string, maxBodyBytes int, historyStorage store.Storage, timeouts TimeoutConfig, fullBuffer bool) (*ProxyServer, error) {
	certManager, err := newCertManager(configDir)
	if err != nil {
		return nil, fmt.Errorf("create cert manager: %w", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ctx, cancel := context.WithCancel(context.Background())
	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	history := newHistoryStore(historyStorage)

	wsHandler := newWebSocketHandler(history, certManager, timeouts)

	http1Handler := &http1Handler{
		history:      history,
		maxBodyBytes: maxBodyBytes,
		timeouts:     timeouts,
		fullBuffer:   fullBuffer,
	}

	http2Handler := newHTTP2Handler(history, maxBodyBytes, timeouts)
	http2Handler.fullBuffer = fullBuffer

	connectHandler := newConnectHandler(certManager, http1Handler, http2Handler, history, maxBodyBytes, timeouts)

	// http1 is the unconditional fallthrough and must be registered last
	registry := &protocol.Registry{
		Early: []protocol.EarlyAdapter{
			http2Adapter{h: http2Handler},
			http1Adapter{h: http1Handler},
		},
		Upgrade: []protocol.UpgradeAdapter{
			wsAdapter{h: wsHandler},
		},
	}
	http1Handler.reg = registry
	connectHandler.reg = registry

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
		registry:       registry,
		ctx:            ctx,
		cancel:         cancel,
	}

	// Pre-increment wg so Shutdown's wg.Wait doesn't race with Serve's wg.Add.
	// Shutdown decrements this if Serve was never called (see served flag).
	s.wg.Add(1)

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

// SetCaptureFilter sets the capture filter for the proxy history.
// Entries rejected by the filter are still proxied but not stored.
func (s *ProxyServer) SetCaptureFilter(f CaptureFilter) {
	s.history.SetCaptureFilter(f)
}

// SetRuleApplier sets the rule applier for all handlers.
// Call after construction but before Serve().
func (s *ProxyServer) SetRuleApplier(applier types.RuleApplier) {
	s.http1Handler.ruleApplier = applier
	s.http2Handler.SetRuleApplier(applier)
	s.connectHandler.SetRuleApplier(applier)
	s.wsHandler.SetRuleApplier(applier)
}

// SetResponseInterceptor sets the response interceptor for HTTP handlers.
// Call after construction but before Serve().
func (s *ProxyServer) SetResponseInterceptor(interceptor ResponseInterceptor) {
	s.http1Handler.responseInterceptor = interceptor
	s.http2Handler.responseInterceptor = interceptor
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

// Registry returns the per-connection claim registry.
func (s *ProxyServer) Registry() *protocol.Registry { return s.registry }

// Serve starts accepting connections. Blocks until shutdown.
func (s *ProxyServer) Serve() error {
	// Decrement pre-incremented wg counter from NewProxyServer
	if s.serveStarted.CompareAndSwap(false, true) {
		defer s.wg.Done()
	}
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

	// Peek only the first byte to avoid blocking a binary protocol whose opening
	// message is shorter than the HTTP discriminators; widen only for openings that
	// could be the HTTP/2 cleartext preface or a CONNECT request, which genuine
	// clients send in full immediately
	first, err := br.Peek(1)
	if err != nil {
		// Connection closed or error before any data
		return
	}
	peek := first
	if first[0] == 'P' || first[0] == 'C' {
		if wide, werr := br.Peek(24); werr == nil {
			peek = wide
		}
	}

	// HTTP/2 preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	h2Preface := []byte("PRI * HTTP/2.0")
	if bytes.HasPrefix(peek, h2Preface) {
		log.Printf("proxy: H2C not supported, closing connection from %s", conn.RemoteAddr())
		return
	}

	// CONNECT: tunnel + MITM, then re-enter the early seam via routeByProtocol
	if bytes.HasPrefix(peek, []byte("CONNECT ")) {
		s.connectHandler.Handle(s.ctx, conn, br)
		return
	}

	// raw accept; http1 adapter is the fallthrough
	s.registry.DispatchEarly(s.ctx, &protocol.EarlyClaimCtx{
		Peek:         peek,
		ClientConn:   conn,
		ClientReader: br,
	})
}

// Shutdown gracefully stops the server.
func (s *ProxyServer) Shutdown(ctx context.Context) error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil // already closed
	}
	defer s.cancel()

	// Stop accepting new connections; Accept returns via s.closed
	_ = s.listener.Close()

	// A context without a deadline has no drain window, so cancel handlers now to guarantee Shutdown returns
	if _, ok := ctx.Deadline(); !ok {
		s.cancel()
	}

	if s.serveStarted.CompareAndSwap(false, true) {
		s.wg.Done()
	}

	// Drain in-flight connections until ctx fires, then force-close
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All connections finished gracefully before the deadline
	case <-ctx.Done():
		// Deadline hit: cancel handlers, then force-close active conns
		s.cancel()
		s.activeConns.Range(func(key, _ any) bool {
			if conn, ok := key.(net.Conn); ok {
				_ = conn.Close()
			}
			return true
		})
		<-done // wait for goroutines to exit after cancel + close
	}

	s.history.Close()
	return s.certManager.Close()
}

// isConnClosedErr returns true for errors indicating the peer closed the connection.
// These are expected during normal browser connection lifecycle (preconnect, idle cleanup).
func isConnClosedErr(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "connection reset") || strings.Contains(s, "broken pipe")
}

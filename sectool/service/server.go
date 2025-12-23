package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	Version         = "0.1.0"
	shutdownTimeout = 10 * time.Second
)

// Server is the sectool service daemon.
type Server struct {
	paths      ServicePaths
	burpMCPURL string

	// Runtime state
	listener   net.Listener
	httpServer *http.Server
	lockFile   *os.File
	started    chan struct{}
	startedAt  time.Time

	// Health metrics providers (registered by subsystems)
	mu             sync.RWMutex
	metricProvider map[string]HealthMetricProvider

	// Burp MCP connection state
	burpConnected bool

	// Shutdown coordination
	shutdownCh chan struct{}
	wg         sync.WaitGroup
}

func NewServer(flags DaemonFlags) (*Server, error) {
	if flags.WorkDir == "" {
		return nil, errors.New("workdir is required for service mode")
	}

	s := &Server{
		paths:          NewServicePaths(flags.WorkDir),
		burpMCPURL:     flags.BurpMCPURL,
		metricProvider: make(map[string]HealthMetricProvider),
		started:        make(chan struct{}),
		shutdownCh:     make(chan struct{}),
	}

	// TODO: Register ID count metrics once the ID tracking maps are defined:
	// s.RegisterHealthMetric("flows", func() string { return strconv.Itoa(len(s.flows)) })
	// s.RegisterHealthMetric("replays", func() string { return strconv.Itoa(len(s.replays)) })
	// s.RegisterHealthMetric("bundles", func() string { return strconv.Itoa(len(s.bundles)) })
	// s.RegisterHealthMetric("oast_sessions", func() string { return strconv.Itoa(len(s.oastSessions)) })

	return s, nil
}

func (s *Server) WaitTillStarted() {
	<-s.started
}

// Run starts the server and blocks until shutdown.
func (s *Server) Run(ctx context.Context) error {
	markStarted := sync.OnceFunc(func() {
		s.startedAt = time.Now()
		close(s.started)
	})
	defer markStarted() // even on error we consider it started (then immediately stopped)

	// Ensure directories exist
	if err := os.MkdirAll(s.paths.ServiceDir, 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %w", err)
	} else if err := os.MkdirAll(s.paths.RequestsDir, 0755); err != nil {
		return fmt.Errorf("failed to create requests directory: %w", err)
	}

	// Acquire exclusive lock on PID file (non-blocking, fail fast if another instance is running)
	// This also writes the PID to the file
	if err := s.acquireLock(); err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer s.releaseLock()

	// Create Unix socket listener
	if err := s.createListener(); err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	defer func() { _ = s.listener.Close() }()
	defer func() { _ = os.Remove(s.paths.SocketPath) }()

	// Setup HTTP server with base context
	s.httpServer = &http.Server{
		Handler: s.routes(),
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// TODO - Connect to Burp MCP here
	s.burpConnected = false

	// Run server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		markStarted()
		if err := s.httpServer.Serve(s.listener); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
		close(serverErr)
	}()

	select {
	case <-ctx.Done():
		log.Printf("context cancelled, initiating shutdown")
	case sig := <-sigCh:
		log.Printf("received signal %v, initiating shutdown", sig)
	case err := <-serverErr:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
	case <-s.shutdownCh:
		log.Printf("shutdown requested via API")
	}

	signal.Stop(sigCh)

	return s.shutdown()
}

// shutdown performs graceful shutdown.
func (s *Server) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}

	// Wait for any ongoing operations
	s.wg.Wait()

	// Cleanup requests directory
	if err := s.cleanupRequests(); err != nil {
		log.Printf("warning: failed to cleanup requests: %v", err)
	}

	// TODO: Close Burp MCP connection

	log.Printf("service stopped")
	return nil
}

// cleanupRequests removes exported request bundles.
func (s *Server) cleanupRequests() error {
	entries, err := os.ReadDir(s.paths.RequestsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			bundlePath := filepath.Join(s.paths.RequestsDir, entry.Name())
			if err := os.RemoveAll(bundlePath); err != nil {
				log.Printf("warning: failed to remove bundle %s: %v", entry.Name(), err)
			}
		}
	}

	return nil
}

// acquireLock acquires an exclusive flock on the PID file (non-blocking, fails fast).
// The lock is held for the lifetime of the server to prevent concurrent instances.
func (s *Server) acquireLock() error {
	f, err := os.OpenFile(s.paths.PIDPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}

	// Acquire exclusive lock (non-blocking - fail fast if another instance is running)
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return fmt.Errorf("another service instance is running: %w", err)
	}

	// Write PID to the locked file
	if err := f.Truncate(0); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to truncate PID file: %w", err)
	} else if _, err := f.WriteString(strconv.Itoa(os.Getpid())); err != nil {
		_ = f.Close()
		return fmt.Errorf("failed to write PID: %w", err)
	}

	s.lockFile = f
	return nil
}

// releaseLock releases the lock file and removes the PID file.
func (s *Server) releaseLock() {
	if s.lockFile != nil {
		_ = s.lockFile.Close() // closing releases flock
		_ = os.Remove(s.paths.PIDPath)
		s.lockFile = nil
	}
}

func (s *Server) createListener() error {
	_ = os.Remove(s.paths.SocketPath)

	listener, err := net.Listen("unix", s.paths.SocketPath)
	if err != nil {
		return err
	}

	if err := os.Chmod(s.paths.SocketPath, 0600); err != nil {
		_ = listener.Close()
		return err
	}

	s.listener = listener
	return nil
}

// routes sets up the HTTP routes.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /srv/stop", s.handleStop)

	mux.HandleFunc("POST /proxy/list", s.handleNotImplemented)
	mux.HandleFunc("POST /proxy/get", s.handleNotImplemented)
	mux.HandleFunc("POST /proxy/export", s.handleNotImplemented)

	mux.HandleFunc("POST /replay/send", s.handleNotImplemented)
	mux.HandleFunc("POST /replay/get", s.handleNotImplemented)

	mux.HandleFunc("POST /oast/create", s.handleNotImplemented)
	mux.HandleFunc("POST /oast/poll", s.handleNotImplemented)
	mux.HandleFunc("POST /oast/list", s.handleNotImplemented)
	mux.HandleFunc("POST /oast/delete", s.handleNotImplemented)

	return mux
}

// RegisterHealthMetric registers a health metric provider for the given key.
// The provider function is called during health checks to get the current value.
func (s *Server) RegisterHealthMetric(key string, provider HealthMetricProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.metricProvider[key] = provider
}

// handleHealth handles GET /health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	health := HealthResponse{
		Version:       Version,
		StartedAt:     s.startedAt.UTC().Format(time.RFC3339),
		BurpConnected: s.burpConnected,
		BurpMCPURL:    s.burpMCPURL,
	}

	// Collect metrics from registered providers
	if len(s.metricProvider) > 0 {
		health.Metrics = make(map[string]string, len(s.metricProvider))
		for key, provider := range s.metricProvider {
			health.Metrics[key] = provider()
		}
	}
	s.mu.RUnlock()

	s.writeJSON(w, http.StatusOK, health)
}

// handleStop handles POST /srv/stop
func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	resp := StopResponse{
		Message: "shutdown initiated",
	}
	s.writeJSON(w, http.StatusOK, resp)

	// Signal shutdown after response is sent (use RequestShutdown for double-close protection)
	time.AfterFunc(100*time.Millisecond, s.RequestShutdown)
}

// handleNotImplemented handles unimplemented endpoints
func (s *Server) handleNotImplemented(w http.ResponseWriter, r *http.Request) {
	s.writeError(w, http.StatusNotImplemented, ErrCodeInternal,
		fmt.Sprintf("endpoint %s not implemented", r.URL.Path),
		"this feature is coming in a future version")
}

// writeJSON writes a successful JSON response
func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	resp, err := SuccessResponse(data)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, ErrCodeInternal, err.Error(), "")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

// writeError writes an error JSON response
func (s *Server) writeError(w http.ResponseWriter, status int, code, message, hint string) {
	resp := ErrorResponse(code, message, hint)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("failed to encode error response: %v", err)
	}
}

// RequestShutdown can be called internally to trigger shutdown
func (s *Server) RequestShutdown() {
	select {
	case <-s.shutdownCh:
		// Already shutting down
	default:
		close(s.shutdownCh)
	}
}

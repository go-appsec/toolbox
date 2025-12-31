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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jentfoo/llm-security-toolbox/sectool/config"
	"github.com/jentfoo/llm-security-toolbox/sectool/service/store"
)

const shutdownTimeout = 10 * time.Second

// Server is the sectool service daemon.
type Server struct {
	paths          ServicePaths
	flagBurpMCPURL string // from command-line flag (may be empty)
	cfg            *config.Config

	// Runtime state
	listener   net.Listener
	httpServer *http.Server
	lockFile   *os.File
	started    chan struct{}
	startedAt  time.Time

	// Health metrics providers (registered by subsystems)
	mu             sync.RWMutex
	metricProvider map[string]HealthMetricProvider

	// Backend implementations for handling proxy, sending requests, OAST, etc
	httpBackend HttpBackend
	oastBackend OastBackend

	// Flow ID mapping (ephemeral)
	flowStore *store.FlowStore

	// Request/response results store (ephemeral)
	requestStore *store.RequestStore

	// proxyLastOffset tracks the highest offset seen across all proxy list queries.
	// Enables --since last to show only new traffic since the last query.
	// Global (not per-filter), unlike OAST which tracks per-session.
	proxyLastOffset atomic.Uint32

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
		flagBurpMCPURL: flags.BurpMCPURL,
		metricProvider: make(map[string]HealthMetricProvider),
		started:        make(chan struct{}),
		shutdownCh:     make(chan struct{}),
		flowStore:      store.NewFlowStore(),
		requestStore:   store.NewRequestStore(),
	}

	// Register health metrics for store counts
	s.RegisterHealthMetric("flows", func() string { return strconv.Itoa(s.flowStore.Count()) })
	s.RegisterHealthMetric("requests", func() string { return strconv.Itoa(s.requestStore.Count()) })

	return s, nil
}

func (s *Server) WaitTillStarted() {
	<-s.started
}

// Run starts the server and blocks until shutdown.
func (s *Server) Run(ctx context.Context) error {
	log.Printf("service starting (version=%s, workdir=%s)", config.Version, s.paths.WorkDir)

	markStarted := sync.OnceFunc(func() {
		s.startedAt = time.Now()
		close(s.started)
	})
	defer markStarted() // even on error we consider it started (then immediately stopped)

	// Ensure directories exist
	if err := os.MkdirAll(s.paths.ServiceDir, 0700); err != nil {
		return fmt.Errorf("failed to create service directory: %w", err)
	} else if err := os.MkdirAll(s.paths.RequestsDir, 0700); err != nil {
		return fmt.Errorf("failed to create requests directory: %w", err)
	}

	if err := s.loadOrCreateConfig(); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
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

	// Connect to Burp MCP
	if err := s.connectBurpMCP(ctx); err != nil {
		return fmt.Errorf("failed to connect to Burp MCP: %w", err)
	}
	// Setup OAST (nothing connected till used)
	s.oastBackend = NewInteractshBackend()
	log.Printf("service ready, listening on %s", s.paths.SocketPath)

	// Run server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		markStarted()
		if err := s.httpServer.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

	// Close backends
	if s.httpBackend != nil {
		if err := s.httpBackend.Close(); err != nil {
			log.Printf("warning: failed to close proxy HttpBackend connection: %v", err)
		}
	}
	if s.oastBackend != nil {
		if err := s.oastBackend.Close(); err != nil {
			log.Printf("warning: failed to close OastBackend: %v", err)
		}
	}

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

	// Wrap with credential verification (verifies peer UID matches server UID)
	s.listener = wrapListenerWithCredentialCheck(listener)
	if peerCredentialsSupported() {
		log.Printf("peer credential verification enabled")
	} else {
		log.Printf("peer credential verification not supported on this platform")
	}
	return nil
}

// routes sets up the HTTP routes.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("POST /srv/stop", s.handleStop)

	mux.HandleFunc("POST /proxy/list", s.handleProxyList)
	mux.HandleFunc("POST /proxy/export", s.handleProxyExport)

	mux.HandleFunc("POST /replay/send", s.handleReplaySend)
	mux.HandleFunc("POST /replay/get", s.handleReplayGet)

	mux.HandleFunc("POST /oast/create", s.handleOastCreate)
	mux.HandleFunc("POST /oast/poll", s.handleOastPoll)
	mux.HandleFunc("POST /oast/get", s.handleOastGet)
	mux.HandleFunc("POST /oast/list", s.handleOastList)
	mux.HandleFunc("POST /oast/delete", s.handleOastDelete)

	mux.HandleFunc("POST /proxy/rule/list", s.handleRuleList)
	mux.HandleFunc("POST /proxy/rule/add", s.handleRuleAdd)
	mux.HandleFunc("POST /proxy/rule/update", s.handleRuleUpdate)
	mux.HandleFunc("POST /proxy/rule/delete", s.handleRuleDelete)

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
	health := HealthResponse{
		Version:   config.Version,
		StartedAt: s.startedAt.UTC().Format(time.RFC3339),
	}

	// Collect metrics from registered providers (requires lock)
	s.mu.RLock()
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

// writeError writes an error JSON response.
func (s *Server) writeError(w http.ResponseWriter, status int, code, message, hint string) {
	if hint != "" {
		log.Printf("error: %s - %s (%s)", code, message, hint)
	} else {
		log.Printf("error: %s - %s", code, message)
	}
	resp := ErrorResponse(code, message, hint)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("failed to encode error response: %v", err)
	}
}

func (s *Server) RequestShutdown() {
	select {
	case <-s.shutdownCh:
		// Already shutting down
	default:
		close(s.shutdownCh)
	}
}

// loadOrCreateConfig loads config from disk or creates default if missing.
// Command-line flags override config file values.
func (s *Server) loadOrCreateConfig() error {
	cfg, err := config.Load(s.paths.ConfigPath)
	if os.IsNotExist(err) {
		cfg = config.DefaultConfig(config.Version)
		if err := cfg.Save(s.paths.ConfigPath); err != nil {
			return fmt.Errorf("failed to save default config: %w", err)
		}
		log.Printf("created default config at %s", s.paths.ConfigPath)
	} else if err != nil {
		return err
	}

	if s.flagBurpMCPURL != "" {
		cfg.BurpMCPURL = s.flagBurpMCPURL
	}

	s.cfg = cfg
	return nil
}

// burpMCPURL returns the effective Burp MCP URL from config.
func (s *Server) burpMCPURL() string {
	if s.cfg != nil {
		return s.cfg.BurpMCPURL
	}
	return config.DefaultBurpMCPURL
}

// connectBurpMCP establishes the connection to Burp MCP.
func (s *Server) connectBurpMCP(ctx context.Context) error {
	// TODO - FUTURE - replace this with a HttpBackend selection

	burpBackend := NewBurpBackend(s.burpMCPURL())
	if err := burpBackend.Connect(ctx); err != nil {
		return err
	}
	s.httpBackend = burpBackend
	return nil
}

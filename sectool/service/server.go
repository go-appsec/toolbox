package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-appsec/llm-security-toolbox/sectool/config"
	"github.com/go-appsec/llm-security-toolbox/sectool/service/store"
)

const (
	shutdownTimeout = 10 * time.Second
	caCertFile      = "ca.pem" // CA certificate filename in config directory
)

// Server is the sectool MCP server.
type Server struct {
	cfg             *config.Config
	configPath      string // resolved config file path (respects --config flag)
	flagBurpMCPURL  string
	flagConfigPath  string
	flagMCPPort     int  // CLI override, 0 means use config
	flagProxyPort   int  // CLI override for built-in proxy, 0 means use config
	flagRequireBurp bool // --burp flag: require Burp MCP

	// MCP server settings
	mcpPort           int
	mcpWorkflowMode   string
	proxyPort         int  // resolved port for built-in proxy
	usingBuiltinProxy bool // true if using built-in proxy instead of Burp

	// Runtime state
	mcpServer *mcpServer
	started   chan struct{}
	startedAt time.Time

	// Health metrics providers
	mu             sync.RWMutex
	metricProvider map[string]HealthMetricProvider

	// Backend implementations
	httpBackend    HttpBackend
	oastBackend    OastBackend
	crawlerBackend CrawlerBackend

	// Flow ID mapping (ephemeral)
	flowStore      *store.FlowStore
	crawlFlowStore *store.CrawlFlowStore

	// Request/response results store (ephemeral)
	requestStore *store.RequestStore

	// proxyLastOffset tracks the highest offset seen across all proxy list queries.
	// Enables "since=last" to show only new traffic since the last query.
	proxyLastOffset atomic.Uint32

	// Shutdown coordination
	shutdownCh chan struct{}
	wg         sync.WaitGroup
}

// NewServer creates a new MCP server instance with optional backends.
// If a backend is nil, Run initializes the default implementation.
func NewServer(flags MCPServerFlags, hb HttpBackend, ob OastBackend, cb CrawlerBackend) (*Server, error) {
	s := &Server{
		flagBurpMCPURL:  flags.BurpMCPURL,
		flagConfigPath:  flags.ConfigPath,
		flagMCPPort:     flags.MCPPort,
		flagProxyPort:   flags.ProxyPort,
		flagRequireBurp: flags.RequireBurp,
		mcpWorkflowMode: flags.WorkflowMode,
		metricProvider:  make(map[string]HealthMetricProvider),
		started:         make(chan struct{}),
		shutdownCh:      make(chan struct{}),
		flowStore:       store.NewFlowStore(),
		crawlFlowStore:  store.NewCrawlFlowStore(),
		requestStore:    store.NewRequestStore(),
		httpBackend:     hb,
		oastBackend:     ob,
		crawlerBackend:  cb,
	}

	// Register health metrics for store counts
	s.RegisterHealthMetric("flows", func() string { return strconv.Itoa(s.flowStore.Count()) })
	s.RegisterHealthMetric("crawl_flows", func() string { return strconv.Itoa(s.crawlFlowStore.Count()) })
	s.RegisterHealthMetric("requests", func() string { return strconv.Itoa(s.requestStore.Count()) })

	return s, nil
}

// WaitTillStarted blocks until the server has started.
func (s *Server) WaitTillStarted() {
	<-s.started
}

// Run starts the MCP server and blocks until shutdown.
func (s *Server) Run(ctx context.Context) error {
	log.Printf("sectool MCP server starting (version=%s)", config.Version)

	markStarted := sync.OnceFunc(func() {
		s.startedAt = time.Now()
		close(s.started)
	})
	defer markStarted()

	// Load or create config from ~/.sectool/config.json
	if err := s.loadOrCreateConfig(); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Setup HTTP backend (Burp or built-in proxy)
	if s.httpBackend == nil {
		if err := s.setupHttpBackend(ctx); err != nil {
			return fmt.Errorf("failed to setup HTTP backend: %w", err)
		}
	}

	// Setup OAST backend
	if s.oastBackend == nil {
		s.oastBackend = NewInteractshBackend()
	}

	// Setup Crawler backend
	if s.crawlerBackend == nil {
		s.crawlerBackend = NewCollyBackend(s.cfg.Crawler, s.cfg.MaxBodyBytes, s.crawlFlowStore, s.flowStore, s.httpBackend)
	}

	// Start MCP server
	s.mcpServer = newMCPServer(s, s.mcpWorkflowMode)
	if err := s.mcpServer.Start(s.mcpPort); err != nil {
		return fmt.Errorf("failed to start MCP server: %w", err)
	}

	markStarted()
	log.Printf("MCP server listening on http://%s/mcp", s.mcpServer.Addr())
	s.printMCPConfig()

	select {
	case <-ctx.Done():
		log.Printf("context cancelled, initiating shutdown")
	case sig := <-sigCh:
		log.Printf("received signal %v, initiating shutdown", sig)
	case <-s.shutdownCh:
		log.Printf("shutdown requested")
	}

	signal.Stop(sigCh)

	return s.shutdown()
}

// shutdown performs graceful shutdown.
func (s *Server) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// Close MCP server
	if s.mcpServer != nil {
		if err := s.mcpServer.Close(ctx); err != nil {
			log.Printf("MCP server shutdown error: %v", err)
		}
	}

	// Wait for any ongoing operations
	s.wg.Wait()

	// Close backends
	if s.httpBackend != nil {
		if err := s.httpBackend.Close(); err != nil {
			log.Printf("warning: failed to close HttpBackend: %v", err)
		}
	}
	if s.oastBackend != nil {
		if err := s.oastBackend.Close(); err != nil {
			log.Printf("warning: failed to close OastBackend: %v", err)
		}
	}
	if s.crawlerBackend != nil {
		if err := s.crawlerBackend.Close(); err != nil {
			log.Printf("warning: failed to close CrawlerBackend: %v", err)
		}
	}

	log.Printf("sectool MCP server stopped")
	return nil
}

// RegisterHealthMetric registers a health metric provider for the given key.
func (s *Server) RegisterHealthMetric(key string, provider HealthMetricProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.metricProvider[key] = provider
}

// RequestShutdown initiates server shutdown.
func (s *Server) RequestShutdown() {
	select {
	case <-s.shutdownCh:
		// Already shutting down
	default:
		close(s.shutdownCh)
	}
}

// loadOrCreateConfig loads config and applies CLI flag overrides.
// Precedence: CLI flags > config file > defaults
func (s *Server) loadOrCreateConfig() error {
	// Determine config path (respects --config flag)
	s.configPath = s.flagConfigPath
	if s.configPath == "" {
		s.configPath = config.DefaultPath()
	}

	cfg, err := config.LoadOrCreatePath(s.configPath)
	if err != nil {
		return err
	}

	// Apply CLI flag overrides (non-zero values override config)
	if s.flagMCPPort != 0 {
		s.mcpPort = s.flagMCPPort
	} else {
		s.mcpPort = cfg.MCPPort
	}

	// Resolve proxy port
	if s.flagProxyPort != 0 {
		s.proxyPort = s.flagProxyPort
	} else {
		s.proxyPort = cfg.ProxyPort
	}

	s.cfg = cfg
	return nil
}

// setupHttpBackend sets up the HTTP backend based on flags and config.
// Priority:
// 1. If --proxy-port is specified, use built-in proxy (skip Burp)
// 2. If --burp flag is set, require Burp (error if unavailable)
// 3. If config burp_required is true, require Burp
// 4. Otherwise, try Burp first, fall back to built-in proxy
func (s *Server) setupHttpBackend(ctx context.Context) error {
	// Case 1: --proxy-port specified, use built-in proxy directly
	if s.flagProxyPort != 0 {
		log.Printf("--proxy-port specified, using built-in proxy")
		return s.startBuiltinProxy()
	}

	// Case 2: --burp flag requires Burp
	if s.flagRequireBurp {
		if err := s.connectBurpMCP(ctx); err != nil {
			return fmt.Errorf("--burp flag requires Burp MCP: %w", err)
		}
		return nil
	}

	// Case 3: config burp_required is true
	if s.cfg.BurpRequired != nil && *s.cfg.BurpRequired {
		if err := s.connectBurpMCP(ctx); err != nil {
			return fmt.Errorf("config burp_required is true: %w", err)
		}
		return nil
	}

	// Case 4: Try Burp, fall back to built-in proxy
	if err := s.connectBurpMCP(ctx); err != nil {
		log.Printf("Burp MCP not available (%v), falling back to built-in proxy", err)
		return s.startBuiltinProxy()
	}
	return nil
}

// connectBurpMCP establishes the connection to Burp MCP.
func (s *Server) connectBurpMCP(ctx context.Context) error {
	burpURL := s.flagBurpMCPURL
	if burpURL == "" {
		burpURL = config.DefaultBurpMCPURL
	}

	burpBackend := NewBurpBackend(burpURL)
	if err := burpBackend.Connect(ctx); err != nil {
		return err
	}
	s.httpBackend = burpBackend
	return nil
}

// startBuiltinProxy starts the native built-in proxy.
func (s *Server) startBuiltinProxy() error {
	configDir := filepath.Dir(s.configPath)

	backend, err := NewNativeProxyBackend(s.proxyPort, configDir, s.cfg.MaxBodyBytes)
	if err != nil {
		return fmt.Errorf("start built-in proxy: %w", err)
	}

	// Start proxy server in background
	go func() {
		if err := backend.Serve(); err != nil {
			log.Printf("proxy: server error: %v", err)
		}
	}()

	s.httpBackend = backend
	s.usingBuiltinProxy = true
	return nil
}

// printMCPConfig outputs MCP configuration instructions to stderr.
func (s *Server) printMCPConfig() {
	addr := s.mcpServer.Addr()
	mcpURL := fmt.Sprintf("http://%s/mcp", addr)
	sseURL := fmt.Sprintf("http://%s/sse", addr)

	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "================================================================================")
	if s.usingBuiltinProxy {
		if backend, ok := s.httpBackend.(*NativeProxyBackend); ok {
			s.printBuiltinProxyConfigAddr(backend.Addr())
			_, _ = fmt.Fprintln(os.Stderr, "")
			_, _ = fmt.Fprintln(os.Stderr, "----------------------------------------------------------------")
			_, _ = fmt.Fprintln(os.Stderr, "")
		}
	}
	_, _ = fmt.Fprintf(os.Stderr, "MCP Endpoint: %s\n", mcpURL)
	_, _ = fmt.Fprintf(os.Stderr, "SSE Endpoint: %s (legacy)\n", sseURL)
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "Claude Code:")
	_, _ = fmt.Fprintf(os.Stderr, "  claude mcp add --transport http sectool %s\n", mcpURL)
	_, _ = fmt.Fprintln(os.Stderr, "")
	_, _ = fmt.Fprintln(os.Stderr, "Codex (~/.codex/config.toml):")
	_, _ = fmt.Fprintln(os.Stderr, "  [mcp_servers.sectool]")
	_, _ = fmt.Fprintf(os.Stderr, "  url = \"%s\"\n", mcpURL)
	_, _ = fmt.Fprintln(os.Stderr, "================================================================================")
	_, _ = fmt.Fprintln(os.Stderr, "")
}

// printBuiltinProxyConfigAddr outputs browser proxy configuration instructions.
func (s *Server) printBuiltinProxyConfigAddr(proxyAddr string) {
	configDir := filepath.Dir(s.configPath)
	caCertPath := filepath.Join(configDir, caCertFile)

	_, _ = fmt.Fprintln(os.Stderr, "Built-in Proxy Configuration:")
	_, _ = fmt.Fprintf(os.Stderr, "Proxy Address: %s\n", proxyAddr)
	_, _ = fmt.Fprintf(os.Stderr, "CA Certificate: %s\n", caCertPath)
}

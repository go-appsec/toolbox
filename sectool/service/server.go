package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

const (
	caCertFile = "ca.pem" // CA certificate filename in config directory
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

	// Backend implementations
	httpBackend    HttpBackend
	oastBackend    OastBackend
	crawlerBackend CrawlerBackend

	// Storage temp directory (shared by all spill stores)
	storageTempDir string

	// Replay history store (shared by both backends)
	replayHistoryStore *store.ReplayHistoryStore

	// Notes store
	noteStore    *store.NoteStore
	notesEnabled bool

	// Proxy history storage (passed to native proxy backend)
	historyStorage store.Storage
	// Rule storage (passed to native proxy backend)
	ruleStorage store.Storage
	// Responder storage (passed to native proxy backend)
	responderStorage store.Storage
	// Burp flow index storage (allocated lazily when burp backend is selected)
	burpIdxStorage store.Storage

	// lastFlowID tracks the last flow_id returned from proxy_poll flows mode.
	// Used for "since=last" cursor to support both proxy and replay entries.
	lastFlowID atomic.Value // stores string

	// Shutdown coordination
	shutdownCh chan struct{}

	// quietLogging suppresses verbose startup output
	quietLogging bool
}

// NewServer creates a new MCP server instance with optional backends.
// If a backend is nil, Run initializes the default implementation.
func NewServer(flags MCPServerFlags, hb HttpBackend, ob OastBackend, cb CrawlerBackend) (*Server, error) {
	// Create shared temp directory for all spill stores
	storageTempDir, err := os.MkdirTemp("", "sectool-spill-*")
	if err != nil {
		return nil, fmt.Errorf("create storage temp dir: %w", err)
	}

	// Create per-store spill instances sharing the same temp directory
	storeNames := []string{"replay", "hist", "rule", "notes", "resp"}
	stores := make([]store.Storage, len(storeNames))
	for i, name := range storeNames {
		stores[i], err = newSpillStore(storageTempDir, name)
		if err != nil {
			// Close already-created stores
			for j := 0; j < i; j++ {
				_ = stores[j].Close()
			}
			_ = os.RemoveAll(storageTempDir)
			return nil, fmt.Errorf("create %s storage: %w", name, err)
		}
	}
	replayStorage, historyStorage, ruleStorage, notesStorage, responderStorage := stores[0], stores[1], stores[2], stores[3], stores[4]

	s := &Server{
		flagBurpMCPURL:     flags.BurpMCPURL,
		flagConfigPath:     flags.ConfigPath,
		flagMCPPort:        flags.MCPPort,
		flagProxyPort:      flags.ProxyPort,
		flagRequireBurp:    flags.RequireBurp,
		mcpWorkflowMode:    flags.WorkflowMode,
		notesEnabled:       flags.Notes,
		started:            make(chan struct{}),
		shutdownCh:         make(chan struct{}),
		storageTempDir:     storageTempDir,
		replayHistoryStore: store.NewReplayHistoryStore(replayStorage),
		historyStorage:     historyStorage,
		ruleStorage:        ruleStorage,
		responderStorage:   responderStorage,
		noteStore:          store.NewNoteStore(notesStorage),
		httpBackend:        hb,
		oastBackend:        ob,
		crawlerBackend:     cb,
	}

	return s, nil
}

// SetQuietLogging suppresses verbose startup output and removes timestamps
// from log output. Intended for use in tests.
func (s *Server) SetQuietLogging() {
	s.quietLogging = true
	log.SetFlags(0)
}

// WaitTillStarted blocks until the server has started.
func (s *Server) WaitTillStarted() {
	<-s.started
}

// Run starts the MCP server and blocks until shutdown.
func (s *Server) Run(ctx context.Context) error {
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

	// Setup Default backends if not already specified
	if s.httpBackend == nil {
		if err := s.setupHttpBackend(ctx); err != nil {
			return fmt.Errorf("failed to setup HTTP backend: %w", err)
		}
	}
	if s.oastBackend == nil {
		token := s.cfg.InteractshAuthToken
		if token == "" {
			token = os.Getenv("INTERACTSH_TOKEN")
		}
		ib := NewInteractshBackend(s.cfg.InteractshServerURL, token)
		ib.Start(ctx)
		s.oastBackend = ib
	}
	if s.crawlerBackend == nil {
		s.crawlerBackend = NewCollyBackend(s.cfg, s.replayHistoryStore, s.httpBackend)
	}

	s.mcpServer = newMCPServer(s, s.mcpWorkflowMode)
	if err := s.mcpServer.Start(s.mcpPort); err != nil {
		return fmt.Errorf("failed to start MCP server: %w", err)
	}

	log.Printf("MCP server (version=%s) listening on http://%s/mcp", config.Version, s.mcpServer.Addr())
	if !s.quietLogging {
		s.printMCPConfig()
	}
	markStarted()

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

func (s *Server) shutdown() error {
	var wg sync.WaitGroup
	closeAsync := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := fn(); err != nil {
				log.Printf("warning: failed to close %s: %v", name, err)
			}
		}()
	}
	closeAsync("MCP Server", s.mcpServer.Close)
	closeAsync("HttpBackend", s.httpBackend.Close)
	closeAsync("OastBackend", s.oastBackend.Close)
	closeAsync("CrawlerBackend", s.crawlerBackend.Close)
	closeAsync("ReplayHistoryStore", s.replayHistoryStore.Close)
	closeAsync("NoteStore", s.noteStore.Close)
	closeAsync("HistoryStorage", s.historyStorage.Close)
	closeAsync("RuleStorage", s.ruleStorage.Close)
	if s.burpIdxStorage != nil {
		closeAsync("BurpIdxStorage", s.burpIdxStorage.Close)
	}

	wg.Wait()

	_ = os.RemoveAll(s.storageTempDir)

	log.Printf("sectool MCP server stopped")
	return nil
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

// DeleteProxyHistory removes the supplied flow_ids from the proxy backend and the replay store.
// Flow_ids referenced by any saved note are retained and returned in skippedNoted.
// Each store silently ignores ids it doesn't own, so callers don't need to pre-route by source.
func (s *Server) DeleteProxyHistory(ctx context.Context, flowIDs []string) (int, int, []string, error) {
	if len(flowIDs) == 0 {
		return 0, 0, nil, nil
	}
	skipped, candidates := s.noteStore.SplitReferencedFlows(flowIDs)
	if len(candidates) == 0 {
		return 0, 0, skipped, nil
	}

	// Proxy delete first: if the backend can't delete
	// we don't want a half-applied state in the replay store
	deletedProxy, err := s.httpBackend.DeleteProxyEntries(ctx, candidates)
	if err != nil {
		return 0, 0, skipped, err
	}
	deletedReplay := s.replayHistoryStore.Delete(candidates)
	return deletedProxy, deletedReplay, skipped, nil
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
		log.Printf("Burp MCP not available, falling back to built-in proxy")
		return s.startBuiltinProxy()
	}
	return nil
}

// newSpillStore creates a per-store spill instance under the shared temp directory.
func newSpillStore(tempDir, name string) (store.Storage, error) {
	cfg := store.DefaultSpillStoreConfig()
	cfg.Dir = tempDir
	cfg.FilePrefix = name
	return store.NewSpillStore(cfg)
}

// connectBurpMCP prepares burp storage and establishes the connection to Burp MCP.
func (s *Server) connectBurpMCP(ctx context.Context) error {
	burpURL := s.flagBurpMCPURL
	if burpURL == "" {
		burpURL = config.DefaultBurpMCPURL
	}

	burpIdx, err := newSpillStore(s.storageTempDir, "burp_idx")
	if err != nil {
		return fmt.Errorf("create burp_idx storage: %w", err)
	}

	backend, err := ConnectBurpBackend(ctx, burpURL, burpIdx)
	if err != nil {
		_ = burpIdx.Close()
		return err
	}
	s.httpBackend = backend
	s.burpIdxStorage = burpIdx
	return nil
}

// startBuiltinProxy starts the native built-in proxy.
func (s *Server) startBuiltinProxy() error {
	configDir := filepath.Dir(s.configPath)
	timeouts := proxy.TimeoutConfig{
		DialTimeout:  time.Duration(s.cfg.Proxy.DialTimeoutSecs) * time.Second,
		ReadTimeout:  time.Duration(s.cfg.Proxy.ReadTimeoutSecs) * time.Second,
		WriteTimeout: time.Duration(s.cfg.Proxy.WriteTimeoutSecs) * time.Second,
	}

	backend, err := NewNativeProxyBackend(s.proxyPort, configDir, s.cfg.MaxBodyBytes, s.historyStorage, s.ruleStorage, s.responderStorage, timeouts)
	if err != nil {
		return fmt.Errorf("start built-in proxy: %w", err)
	}

	// Configure capture exclusion filters

	if captureFilter, err := BuildCaptureFilter(s.cfg.Proxy); err != nil {
		return fmt.Errorf("invalid capture filter: %w", err)
	} else if captureFilter != nil {
		backend.SetCaptureFilter(captureFilter)
	}

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

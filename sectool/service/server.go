package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

const (
	caCertFile = "ca.pem" // CA certificate filename in config directory

	// gracefulShutdownTimeout bounds how long shutdown lets in-flight
	// connections drain before force-closing them. Streaming MCP sessions
	// never idle, so this is the effective exit latency; keep it short.
	gracefulShutdownTimeout = 1 * time.Second
)

// Server is the sectool MCP server.
type Server struct {
	cfg               *config.Config
	configPath        string // resolved config file path (respects --config flag)
	flagBurpMCPURL    string
	flagConfigPath    string
	flagMCPPort       int    // CLI override, 0 means use config
	flagProxyPort     int    // CLI override for built-in proxy, 0 means use config
	flagRequireBurp   bool   // --burp flag: require Burp MCP
	flagSidecarSocket string // CLI override for the sidecar IPC socket

	// MCP server settings
	mcpPort           int
	mcpWorkflowMode   string
	proxyPort         int    // resolved port for built-in proxy
	sidecarSocket     string // resolved sidecar IPC socket address
	usingBuiltinProxy bool   // true if using built-in proxy instead of Burp

	// Runtime state
	mcpServer *mcpServer
	mcpReady  atomic.Pointer[mcpServer] // set once mcpServer is built; backs sidecar core_invoke
	started   chan struct{}

	// Backend implementations
	httpBackend    HttpBackend
	oastBackend    OastBackend
	crawlerBackend CrawlerBackend

	// Storage temp directory (shared by all spill stores)
	storageDir string

	// ownsStorageDir set when the server created storageDir and must remove it on shutdown
	ownsStorageDir bool

	// storageProvider allocates per-backend Storage instances under storageDir.
	storageProvider store.Provider

	// Replay history store (shared across backends and tool handlers)
	replayHistoryStore *store.ReplayHistoryStore

	// Notes store
	noteStore    *store.NoteStore
	notesEnabled bool

	// lastFlowID tracks the last flow_id returned from proxy_poll flows mode.
	// Used for "since=last" cursor to support both proxy and replay entries.
	lastFlowID atomic.Value // stores string

	// Shutdown coordination
	shutdownCh chan struct{}

	// quietLogging suppresses verbose startup output
	quietLogging bool
}

// NewServer creates a new MCP server instance with optional backends, allocating and owning a temp
// storage directory. If a backend is nil, Run initializes the default implementation.
func NewServer(flags MCPServerFlags, hb HttpBackend, ob OastBackend, cb CrawlerBackend) (*Server, error) {
	storageDir, err := os.MkdirTemp("", "sectool-spill-*")
	if err != nil {
		return nil, fmt.Errorf("create storage temp dir: %w", err)
	}
	s, err := NewServerWithStorageDir(flags, storageDir, hb, ob, cb)
	if err != nil {
		_ = os.RemoveAll(storageDir)
		return nil, err
	}
	s.ownsStorageDir = true
	return s, nil
}

// NewServerWithStorageDir creates a new MCP server instance with optional backends, using the
// caller-owned storageDir for spill stores. The caller is responsible for removing storageDir.
func NewServerWithStorageDir(flags MCPServerFlags, storageDir string, hb HttpBackend, ob OastBackend, cb CrawlerBackend) (*Server, error) {
	storageProvider := func(name string) (store.Storage, error) {
		return newSpillStore(storageDir, name)
	}

	// Cross-cutting stores allocated
	replayStorage, err := storageProvider("replay")
	if err != nil {
		return nil, fmt.Errorf("create replay storage: %w", err)
	}
	notesStorage, err := storageProvider("notes")
	if err != nil {
		_ = replayStorage.Close()
		return nil, fmt.Errorf("create notes storage: %w", err)
	}

	s := &Server{
		flagBurpMCPURL:     flags.BurpMCPURL,
		flagConfigPath:     flags.ConfigPath,
		flagMCPPort:        flags.MCPPort,
		flagProxyPort:      flags.ProxyPort,
		flagRequireBurp:    flags.RequireBurp,
		flagSidecarSocket:  flags.SidecarSocket,
		mcpWorkflowMode:    flags.WorkflowMode,
		notesEnabled:       flags.Notes,
		started:            make(chan struct{}),
		shutdownCh:         make(chan struct{}),
		storageDir:         storageDir,
		storageProvider:    storageProvider,
		replayHistoryStore: store.NewReplayHistoryStore(replayStorage),
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
	s.mcpReady.Store(s.mcpServer)
	if err := s.mcpServer.Start(s.mcpPort); err != nil {
		return fmt.Errorf("failed to start MCP server: %w", err)
	}

	// serve after the core tools exist so sidecars can't register a conflicting tool
	if backend, ok := s.httpBackend.(*NativeProxyBackend); ok {
		go func() {
			if err := backend.Serve(); err != nil {
				log.Printf("proxy: server error: %v", err)
			}
		}()
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
	ctx, cancel := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
	defer cancel()

	var wg sync.WaitGroup
	closeAsync := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if err := fn(ctx); err != nil {
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

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Backstop past the graceful deadline: returns even if a Close ignores ctx,
	// leaving room for backends to complete their own force-close at the deadline
	select {
	case <-done:
	case <-time.After(gracefulShutdownTimeout + time.Second):
		log.Printf("warning: shutdown did not complete within %s; forcing exit", gracefulShutdownTimeout+time.Second)
	}

	if s.ownsStorageDir {
		_ = os.RemoveAll(s.storageDir)
	}

	log.Printf("sectool MCP server stopped")
	return nil
}

// CoreInvoke dispatches a core MCP tool by name for the sidecar core_invoke
// method, delegating to the MCP server's tool handlers once it is built.
func (s *Server) CoreInvoke(ctx context.Context, tool string, params json.RawMessage) (string, bool, error) {
	m := s.mcpReady.Load()
	if m == nil {
		return "", false, errors.New("core tools not ready")
	}
	return m.CoreInvoke(ctx, tool, params)
}

// OriginateNative backs a sidecar's invoke_adapter targeting the reserved
// "sectool" adapter: it originates an outbound HTTP request through the native
// send path. Returns an error until the MCP server is ready.
func (s *Server) OriginateNative(ctx context.Context, p wire.SidecarSendParams, invokedBy string) (wire.SidecarSendResult, *wire.Error) {
	m := s.mcpReady.Load()
	if m == nil {
		return wire.SidecarSendResult{}, wire.NewError(wire.CodeInjectSendFailed, "invoke_adapter: native origination not ready")
	}
	return m.originateNative(ctx, p, invokedBy)
}

// CoreToolNames returns the static core MCP tool names captured at construction,
// or nil before the MCP server is built. It lets the sidecar registry reject a
// tool-name collision against core tools; connected sidecars' tool names are
// checked separately, so this stays the genuine core set.
func (s *Server) CoreToolNames() []string {
	m := s.mcpReady.Load()
	if m == nil {
		return nil
	}
	return m.coreTools
}

// MCPAddr returns the bound MCP listener address, or "" before the server starts.
func (s *Server) MCPAddr() string {
	if s.mcpServer == nil {
		return ""
	}
	return s.mcpServer.Addr()
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

// DeleteProxyHistory removes the supplied flow_ids, and their child flows, from
// the proxy backend and the replay store. A flow_id is retained and returned in
// skippedNoted when it or any of its children is referenced by a saved note.
// Each store silently ignores ids it doesn't own, so callers don't need to pre-route by source.
func (s *Server) DeleteProxyHistory(ctx context.Context, flowIDs []string) (int, int, []string, error) {
	if len(flowIDs) == 0 {
		return 0, 0, nil, nil
	}
	skipped, candidates := s.splitNotedFlows(ctx, flowIDs)
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

// splitNotedFlows splits flowIDs into those retained for a note reference
// somewhere in their subtree (left / first) and those safe to delete (right).
func (s *Server) splitNotedFlows(ctx context.Context, flowIDs []string) ([]string, []string) {
	subtrees := make(map[string][]string, len(flowIDs))
	all := make([]string, 0, len(flowIDs))
	for _, fid := range flowIDs {
		subtrees[fid] = s.flowSubtree(ctx, fid)
		all = append(all, subtrees[fid]...)
	}

	referenced, _ := s.noteStore.SplitReferencedFlows(all)
	if len(referenced) == 0 {
		return nil, flowIDs
	}
	noted := bulk.SliceToSet(referenced)
	return bulk.SliceSplit(func(fid string) bool {
		return slices.ContainsFunc(subtrees[fid], func(id string) bool {
			_, ok := noted[id]
			return ok
		})
	}, flowIDs)
}

// flowSubtree returns flowID followed by its descendant flow_ids, breadth-first.
func (s *Server) flowSubtree(ctx context.Context, flowID string) []string {
	subtree := []string{flowID}
	seen := map[string]struct{}{flowID: {}}
	for i := 0; i < len(subtree); i++ {
		children, err := s.httpBackend.GetProxyChildren(ctx, subtree[i])
		if err != nil {
			log.Printf("history/delete: children of %s: %v", subtree[i], err)
			continue
		}
		for _, c := range children {
			if _, dup := seen[c.FlowID]; dup {
				continue // guard against a cyclic parent link
			}
			seen[c.FlowID] = struct{}{}
			subtree = append(subtree, c.FlowID)
		}
	}
	return subtree
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

	// Apply CLI flag overrides (positive overrides config; negative = ephemeral)
	switch {
	case s.flagMCPPort < 0:
		s.mcpPort = 0 // ephemeral: OS assigns a free port
	case s.flagMCPPort > 0:
		s.mcpPort = s.flagMCPPort
	default:
		s.mcpPort = cfg.MCPPort
	}

	// Resolve proxy port
	if s.flagProxyPort != 0 {
		s.proxyPort = s.flagProxyPort
	} else {
		s.proxyPort = cfg.ProxyPort
	}

	// Resolve sidecar socket: flag > config (config is already defaulted)
	if s.flagSidecarSocket != "" {
		s.sidecarSocket = s.flagSidecarSocket
	} else {
		s.sidecarSocket = cfg.Sidecars.Socket
	}

	s.cfg = cfg
	return nil
}

// sidecarsEnabled reports whether the operator opted into sidecars.
func (s *Server) sidecarsEnabled() bool {
	return s.cfg.Sidecars.Enabled != nil && *s.cfg.Sidecars.Enabled
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
		s.warnSidecarsUnderBurp()
		return nil
	}

	// Case 3: config burp_required is true
	if s.cfg.BurpRequired {
		if err := s.connectBurpMCP(ctx); err != nil {
			return fmt.Errorf("config burp_required is true: %w", err)
		}
		s.warnSidecarsUnderBurp()
		return nil
	}

	// Case 4: Try Burp, fall back to built-in proxy
	if err := s.connectBurpMCP(ctx); err != nil {
		log.Printf("Burp MCP not available, falling back to built-in proxy")
		return s.startBuiltinProxy()
	}
	s.warnSidecarsUnderBurp()
	return nil
}

// warnSidecarsUnderBurp logs a warning when sidecars are enabled but the Burp
// backend is active, which does not host the sidecar listener.
func (s *Server) warnSidecarsUnderBurp() {
	if s.sidecarsEnabled() {
		log.Printf("warning: sidecars enabled but unavailable under the Burp backend; continuing without sidecars")
	}
}

// newSpillStore creates a per-store spill instance under the shared temp directory.
func newSpillStore(tempDir, name string) (store.Storage, error) {
	cfg := store.DefaultSpillStoreConfig()
	cfg.Dir = tempDir
	cfg.FilePrefix = name
	return store.NewSpillStore(cfg)
}

// connectBurpMCP establishes the connection to Burp MCP.
func (s *Server) connectBurpMCP(ctx context.Context) error {
	burpURL := s.flagBurpMCPURL
	if burpURL == "" {
		burpURL = config.DefaultBurpMCPURL
	}

	backend, err := ConnectBurpBackend(ctx, burpURL, s.storageProvider)
	if err != nil {
		return err
	}
	s.httpBackend = backend
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

	backend, err := NewNativeProxyBackend(s.proxyPort, configDir, s.cfg.MaxBodyBytes, s.storageProvider, timeouts, s.cfg.Proxy.FullBuffer)
	if err != nil {
		return fmt.Errorf("start built-in proxy: %w", err)
	}

	if s.sidecarsEnabled() {
		if err := backend.EnableSidecars(sidecar.Config{
			Socket:            s.sidecarSocket,
			HeartbeatInterval: time.Duration(s.cfg.Sidecars.HeartbeatIntervalSecs) * time.Second,
			HeartbeatTimeout:  time.Duration(s.cfg.Sidecars.HeartbeatTimeoutSecs) * time.Second,
			NativeProxyPort:   s.proxyPort,
			ScopeCheck:        s.cfg.IsDomainAllowed,
			DialTimeout:       timeouts.DialTimeout,
			NativeHTTPSend:    s.OriginateNative,
		}, s, s.replayHistoryStore); err != nil {
			_ = backend.Close(context.Background())
			return fmt.Errorf("enable sidecars: %w", err)
		}
	}

	// Configure capture exclusion filters

	if captureFilter, err := BuildCaptureFilter(s.cfg.Proxy); err != nil {
		return fmt.Errorf("invalid capture filter: %w", err)
	} else if captureFilter != nil {
		backend.SetCaptureFilter(captureFilter)
	}

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

package sidecar

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// shutdownDrainSeconds is requested of each sidecar on graceful shutdown.
const shutdownDrainSeconds = 5

// Config configures the sidecar Manager and listener.
type Config struct {
	Socket            string
	HeartbeatInterval time.Duration
	HeartbeatTimeout  time.Duration
	NativeProxyPort   int      // proxy listen port; excluded from sidecar early_claim ranges
	ReservedNames     []string // built-in adapter names sidecars may not reuse
	// ScopeCheck gates dial_upstream destinations; nil allows any host.
	ScopeCheck func(host string) (allowed bool, reason string)
	// DialTimeout bounds each dial_upstream connection attempt.
	DialTimeout time.Duration
	// NativeHTTPSend originates an outbound HTTP request through the in-process
	// proxy on a sidecar's behalf; nil disables native origination.
	NativeHTTPSend func(ctx context.Context, p wire.SidecarSendParams, invokedBy string) (wire.SidecarSendResult, *wire.Error)
}

// Manager owns the registry of connected sidecars: registration, conflict
// resolution, heartbeat, reconnect/resume, and shutdown.
type Manager struct {
	cfg        Config
	registry   *protocol.Registry
	flows      FlowSink
	coreInvoke CoreService
	rules      RuleSource
	now        func() time.Time

	mu          sync.Mutex
	records     map[string]*Record
	byInstance  map[string]*Record
	resumeState map[string]*resumeEntry

	toolsChanged atomic.Pointer[func()]
}

// NewManager creates a Manager. registry dispatches connections to sidecar
// adapters, flows sinks push_flow, coreInvoke backs core_invoke, and rules supplies
// sync_rules snapshots.
func NewManager(cfg Config, registry *protocol.Registry, flows FlowSink, coreInvoke CoreService, rules RuleSource) *Manager {
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 10 * time.Second
	}
	if cfg.HeartbeatTimeout <= 0 {
		cfg.HeartbeatTimeout = 30 * time.Second
	}
	return &Manager{
		cfg:         cfg,
		registry:    registry,
		flows:       flows,
		coreInvoke:  coreInvoke,
		rules:       rules,
		now:         time.Now,
		records:     map[string]*Record{},
		byInstance:  map[string]*Record{},
		resumeState: map[string]*resumeEntry{},
	}
}

// SetToolsChangedHook registers a callback invoked when the set of connected
// adapters changes, so the MCP server can recompose the advertised tool list.
func (m *Manager) SetToolsChangedHook(fn func()) {
	m.toolsChanged.Store(&fn)
}

// notifyToolsChanged invokes the change hook off the caller's goroutine to avoid
// lock contention.
func (m *Manager) notifyToolsChanged() {
	if fn := m.toolsChanged.Load(); fn != nil {
		go (*fn)()
	}
}

// Get returns the record for an adapter name.
func (m *Manager) Get(name string) (*Record, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.records[name]
	return r, ok
}

// Count returns the number of registered sidecars.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.records)
}

// hasResumeState reports whether bookkeeping is stashed for an instance_id.
func (m *Manager) hasResumeState(instanceID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.resumeState[instanceID]
	return ok
}

// HandleConn drives one accepted sidecar connection until it closes.
func (m *Manager) HandleConn(ctx context.Context, conn net.Conn) {
	s := &session{m: m}
	s.peer = wire.NewPeer(conn, s)

	go m.heartbeatLoop(ctx, s)
	// peer.Run blocks in ReadFrame, close on cancel to unblock unregistered sessions
	go func() {
		select {
		case <-ctx.Done():
			_ = s.peer.Close()
		case <-s.peer.Done():
		}
	}()

	_ = s.peer.Run(ctx)
	log.Printf("sidecar[%s]: connection closed", s.adapterName())
	m.detachSession(s)
}

// heartbeatLoop pings the registered sidecar and marks it unhealthy when no pong
// arrives within the timeout.
func (m *Manager) heartbeatLoop(ctx context.Context, s *session) {
	ticker := time.NewTicker(m.cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.peer.Done():
			return
		case <-ticker.C:
			rec := s.record()
			if rec == nil {
				continue
			}
			sincePong := m.now().Sub(rec.lastPong())
			if sincePong > m.cfg.HeartbeatTimeout {
				rec.healthy.Store(false)
				log.Printf("sidecar[%s]: heartbeat timeout (no pong for %s, threshold=%s)", rec.Name, sincePong.Round(time.Second), m.cfg.HeartbeatTimeout)
			}
			_ = s.peer.Notify(wire.MethodPing, nil)
		}
	}
}

// detachSession removes a record when its connection closes, stashing resume
// state for a resuming sidecar.
func (m *Manager) detachSession(s *session) {
	rec := s.record()
	if rec == nil {
		return
	}
	instanceTag := rec.InstanceID
	if instanceTag == "" {
		instanceTag = "-"
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.records[rec.Name]; !ok || cur != rec {
		return // already replaced by a reconnect
	}
	delete(m.records, rec.Name)
	if rec.InstanceID != "" && m.byInstance[rec.InstanceID] == rec {
		delete(m.byInstance, rec.InstanceID)
	}
	m.releaseClaims(rec)
	if rec.resume && rec.InstanceID != "" {
		m.resumeState[rec.InstanceID] = &resumeEntry{ownedFlows: rec.ownedFlows, inFlight: rec.inFlight}
	}

	log.Printf("sidecar[%s]: disconnected instance_id=%s", rec.Name, instanceTag)
	m.notifyToolsChanged()
}

// removeLocked drops a record and closes its connection; callers hold mu.
func (m *Manager) removeLocked(rec *Record) {
	delete(m.records, rec.Name)
	if rec.InstanceID != "" && m.byInstance[rec.InstanceID] == rec {
		delete(m.byInstance, rec.InstanceID)
	}
	m.releaseClaims(rec)
	_ = rec.peer.Close()
}

// releaseClaims unregisters the sidecar's claim bridge and tears down its active
// byte streams, closing the client sockets so none is orphaned.
func (m *Manager) releaseClaims(rec *Record) {
	m.registry.RemoveEarly(rec.Name)
	m.registry.RemoveUpgrade(rec.Name)
	rec.bridge.shutdown()
}

// Shutdown requests a graceful close of every sidecar and waits briefly.
func (m *Manager) Shutdown(ctx context.Context) {
	m.mu.Lock()
	recs := bulk.MapValuesSlice(m.records)
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, r := range recs {
		wg.Add(1)
		go func(r *Record) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			var res wire.ShutdownResult
			_ = r.peer.Call(cctx, wire.MethodShutdown, wire.ShutdownParams{DrainSeconds: shutdownDrainSeconds}, &res)
			_ = r.peer.Close()
		}(r)
	}
	wg.Wait()
}

// session is the per-connection JSON-RPC handler. It processes register, then
// tracks the resulting record for heartbeats.
type session struct {
	m    *Manager
	peer *wire.Peer

	mu  sync.Mutex
	rec *Record
}

func (s *session) record() *Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec
}

func (s *session) HandleRequest(ctx context.Context, method string, params json.RawMessage) (any, *wire.Error) {
	switch method {
	case wire.MethodRegister:
		var p wire.RegisterParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, wire.NewError(wire.CodeRegistrationRejected, "register: invalid params")
		}
		rec, res, rpcErr := s.m.handleRegister(s.peer, &p)
		if rpcErr != nil {
			return nil, rpcErr
		}
		s.mu.Lock()
		s.rec = rec
		s.mu.Unlock()
		// seed rules before exposing claims or tools so nothing runs without them
		rec.pushRules(ctx, s.m.rules)
		s.m.activateClaims(rec)
		s.m.notifyToolsChanged()
		return res, nil
	case wire.MethodPushFlow:
		var p wire.Flow
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, wire.NewError(wire.CodeFlowRejected, "push_flow: invalid params")
		}
		return s.handlePushFlow(&p)
	case wire.MethodCoreInvoke:
		var p wire.CoreInvokeParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, wire.NewError(wire.CodeCoreInvokeRejected, "core_invoke: invalid params")
		}
		return s.handleCoreInvoke(ctx, &p)
	case wire.MethodDialUpstream:
		var p wire.DialUpstreamParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, wire.NewError(wire.CodeDialFailed, "dial_upstream: invalid params")
		}
		return s.handleDialUpstream(ctx, &p)
	case wire.MethodInvokeAdapter:
		var p wire.InvokeAdapterParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, wire.NewError(wire.CodeUnknownDestAdapter, "invoke_adapter: invalid params")
		}
		return s.handleInvokeAdapter(ctx, &p)
	case wire.MethodPing:
		return struct{}{}, nil
	default:
		return nil, wire.NewError(-32601, "method not found: "+method)
	}
}

func (s *session) HandleNotification(_ context.Context, method string, params json.RawMessage) {
	switch method {
	case wire.MethodPing:
		_ = s.peer.Notify(wire.MethodPong, nil)
	case wire.MethodPong:
		if rec := s.record(); rec != nil {
			rec.recordPong(s.m.now())
		}
	case wire.MethodLog:
		var p wire.LogParams
		if err := json.Unmarshal(params, &p); err != nil {
			log.Printf("sidecar[%s]: drop malformed %s notification: %v", s.adapterName(), method, err)
		} else {
			s.handleLog(&p)
		}
	case wire.MethodReportMetrics:
		var p wire.ReportMetricsParams
		if err := json.Unmarshal(params, &p); err != nil {
			log.Printf("sidecar[%s]: drop malformed %s notification: %v", s.adapterName(), method, err)
		} else {
			s.handleReportMetrics(&p)
		}
	case wire.MethodCloseStream:
		var p wire.StreamEndedParams
		if err := json.Unmarshal(params, &p); err != nil {
			log.Printf("sidecar[%s]: drop malformed %s notification: %v", s.adapterName(), method, err)
		} else if rec := s.record(); rec != nil {
			rec.bridge.streams.closeStream(p.StreamID)
		}
	case wire.MethodStreamWrite:
		var p wire.StreamWriteParams
		if err := json.Unmarshal(params, &p); err != nil {
			log.Printf("sidecar[%s]: drop malformed %s notification: %v", s.adapterName(), method, err)
		} else if rec := s.record(); rec != nil {
			if werr := rec.bridge.streams.streamWrite(p.StreamID, p.Data); werr != nil {
				log.Printf("sidecar[%s]: %s (stream_id=%s)", s.adapterName(), werr.Message, p.StreamID)
			}
		}
	}
}

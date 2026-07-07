package sidecar

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// Record is the registry entry for one connected sidecar adapter.
type Record struct {
	Name         string
	ProtoVersion wire.ProtocolVersion
	Protocols    []string
	Capabilities wire.Capabilities
	MCPTools     []wire.MCPTool // tool definitions the sidecar provides
	InstanceID   string

	peer    *wire.Peer
	bridge  *bridge
	resume  bool
	healthy atomic.Bool
	// appliedVersion is the rule snapshot version the sidecar last acked.
	appliedVersion atomic.Uint64

	mu       sync.Mutex
	liveness Liveness
	// Ownership and in-flight bookkeeping used to reclaim state on reconnect/resume.
	ownedFlows map[string]struct{}
	inFlight   map[string]struct{}
}

// Liveness tracks heartbeat responses.
type Liveness struct {
	LastPongRecv time.Time
}

// resumeEntry stashes a disconnected sidecar's bookkeeping so a reconnect with
// resume=true can reclaim it.
type resumeEntry struct {
	ownedFlows map[string]struct{}
	inFlight   map[string]struct{}
}

// Healthy reports whether the sidecar is answering heartbeats. An unhealthy
// sidecar must not claim new connections.
func (r *Record) Healthy() bool { return r.healthy.Load() }

func (r *Record) alive() bool { return r.peer != nil && !r.peer.Closed() }

func (r *Record) recordPong(now time.Time) {
	r.mu.Lock()
	r.liveness.LastPongRecv = now
	r.mu.Unlock()
	r.healthy.Store(true)
}

func (r *Record) lastPong() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.liveness.LastPongRecv
}

// trackOwned records a newly emitted flow as owned, and in-flight when it still
// awaits a two-phase completion.
func (r *Record) trackOwned(flowID string, inFlight bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ownedFlows[flowID] = struct{}{}
	if inFlight {
		r.inFlight[flowID] = struct{}{}
	}
}

// owns reports whether the adapter emitted the flow.
func (r *Record) owns(flowID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.ownedFlows[flowID]
	return ok
}

// markComplete clears a flow's in-flight status after two-phase completion.
func (r *Record) markComplete(flowID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.inFlight, flowID)
}

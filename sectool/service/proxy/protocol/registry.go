package protocol

import (
	"context"
	"slices"
	"sync"

	"github.com/go-analyze/bulk"
)

// Registry holds the ordered claim seams for the native proxy backend; first
// claim wins. The fallthrough early adapter (ClaimEarly always true) must be last.
// Sidecar bridges are inserted and removed at runtime, so access is guarded.
type Registry struct {
	mu      sync.RWMutex
	Early   []EarlyAdapter
	Upgrade []UpgradeAdapter
}

// InsertEarly adds an early adapter ahead of the trailing fallthrough so it is
// evaluated before the built-in HTTP adapters. A nil or empty list appends.
func (r *Registry) InsertEarly(a EarlyAdapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n := len(r.Early); n > 0 {
		r.Early = append(r.Early[:n-1:n-1], a, r.Early[n-1])
	} else {
		r.Early = append(r.Early, a)
	}
}

// RemoveEarly drops the early adapter with the given name.
func (r *Registry) RemoveEarly(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i := slices.IndexFunc(r.Early, func(a EarlyAdapter) bool { return a.Name() == name }); i >= 0 {
		r.Early = slices.Delete(r.Early, i, i+1)
	}
}

// InsertUpgrade adds an upgrade adapter at the front so sidecar claims are
// evaluated before the built-in WebSocket adapter. Callers insert in
// most-specific-first order.
func (r *Registry) InsertUpgrade(a UpgradeAdapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Upgrade = bulk.SlicePrependInPlace(a, r.Upgrade)
}

// RemoveUpgrade drops the upgrade adapter with the given name.
func (r *Registry) RemoveUpgrade(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i := slices.IndexFunc(r.Upgrade, func(a UpgradeAdapter) bool { return a.Name() == name }); i >= 0 {
		r.Upgrade = slices.Delete(r.Upgrade, i, i+1)
	}
}

// DispatchEarly serves the connection with the first early adapter that claims it.
func (r *Registry) DispatchEarly(ctx context.Context, c *EarlyClaimCtx) {
	for _, a := range r.snapshotEarly() {
		if a.ClaimEarly(c) {
			a.ServeEarly(ctx, c)
			return
		}
	}
}

// MatchTLS returns the first TLS early adapter that claims a connection by its
// ClientHello SNI and CONNECT target, before TLS termination.
func (r *Registry) MatchTLS(sni, host string, port int) (TLSEarlyAdapter, bool) {
	for _, a := range r.snapshotEarly() {
		if t, ok := a.(TLSEarlyAdapter); ok && t.ClaimTLS(sni, host, port) {
			return t, true
		}
	}
	return nil, false
}

// ClaimUpgrade returns the first upgrade adapter that claims the parsed request.
func (r *Registry) ClaimUpgrade(c *UpgradeClaimCtx) (UpgradeAdapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, a := range r.Upgrade {
		if a.ClaimUpgrade(c) {
			return a, true
		}
	}
	return nil, false
}

// snapshotEarly copies the early list so dispatch can iterate without holding the
// lock across an adapter's claim/serve (which may run a blocking probe call).
func (r *Registry) snapshotEarly() []EarlyAdapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.Early)
}

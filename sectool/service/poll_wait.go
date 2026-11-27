package service

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const (
	// Poll wait defaults shared by proxy_poll and oast_poll.
	defaultPollWait = 30 * time.Second
	maxPollWait     = 120 * time.Second

	// flowRecheckInterval bounds how often a waiting poll re-fetches when change
	// signals are absent (Burp backend) or dropped by the notifier throttle.
	flowRecheckInterval = time.Second

	// notifyThrottle coalesces concurrent capture bursts into one wake per window.
	notifyThrottle = 100 * time.Millisecond
)

// parseWaitDuration parses the shared proxy_poll/oast_poll wait parameter:
// duration string, defaultPollWait when empty, capped at maxPollWait. Zero disables waiting.
func parseWaitDuration(s string) (time.Duration, error) {
	if s == "" {
		return defaultPollWait, nil
	}
	wait, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid wait duration: %w", err)
	}
	if wait < 0 {
		wait = 0
	}
	return min(wait, maxPollWait), nil
}

// flowNotifier broadcasts history changes to long-poll waiters. Wakes are
// best-effort: a burst within the throttle window sends one, and waiters recover
// the rest on their next re-check tick.
type flowNotifier struct {
	mu       sync.Mutex
	ch       chan struct{} // closed and replaced on each wake
	last     time.Time     // time of the last wake, for throttling
	throttle time.Duration
}

func newFlowNotifier() *flowNotifier {
	return &flowNotifier{ch: make(chan struct{}), throttle: notifyThrottle}
}

// Notify wakes current waiters unless within the throttle window of the last wake.
func (n *flowNotifier) Notify() {
	n.mu.Lock()
	defer n.mu.Unlock()

	if time.Since(n.last) < n.throttle {
		return
	}
	close(n.ch)
	n.ch = make(chan struct{})
	n.last = time.Now()
}

// Watch returns the channel the next Notify closes. Callers must watch before
// fetching so a concurrent change cannot be missed.
func (n *flowNotifier) Watch() <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.ch
}

// waitForFlowMatch returns collect's matches, waiting up to wait for one when the
// first pass is empty. The wait ends on a change signal, a recheck tick, ctx
// cancellation, shutdown, or expiry; timedOut reports an expired wait with no
// matches. A nil shutdown never fires.
func waitForFlowMatch(ctx context.Context, notify *flowNotifier, shutdown <-chan struct{}, wait, recheck time.Duration, collect func() ([]flowEntry, int, error)) (filtered []flowEntry, totalMatched int, timedOut bool, err error) {
	filtered, totalMatched, err = collect()
	if err != nil || len(filtered) > 0 || wait <= 0 {
		return filtered, totalMatched, false, err
	}

	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	ticker := time.NewTicker(recheck)
	defer ticker.Stop()

	for {
		// watch before fetching: a concurrent change closes the grabbed channel
		changed := notify.Watch()
		filtered, totalMatched, err = collect()
		if err != nil || len(filtered) > 0 {
			return filtered, totalMatched, false, err
		}
		select {
		case <-changed:
		case <-ticker.C:
		case <-ctx.Done():
			return filtered, totalMatched, false, nil
		case <-shutdown:
			return filtered, totalMatched, false, nil
		case <-deadline.C:
			// final pass: the throttle may have dropped a late change
			filtered, totalMatched, err = collect()
			return filtered, totalMatched, err == nil && len(filtered) == 0, err
		}
	}
}

// wireFlowChangeHooks wakes waiting proxy_polls from native history and replay
// store changes; backends without a change signal rely on interval re-polling.
func (s *Server) wireFlowChangeHooks() {
	if backend, ok := s.httpBackend.(*NativeProxyBackend); ok {
		backend.History().SetChangeHook(s.flowChanges.Notify)
	}
	s.replayHistoryStore.SetChangeHook(s.flowChanges.Notify)
}

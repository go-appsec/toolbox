package sidecar

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// stubRuleSource serves a mutable rule list, scoping each rule to the queried
// adapter so a test can confirm the manager routed each sidecar its own snapshot.
type stubRuleSource struct {
	mu    sync.Mutex
	rules []string // rule ids, empty for no rules
}

func (s *stubRuleSource) set(ids ...string) {
	s.mu.Lock()
	s.rules = ids
	s.mu.Unlock()
}

func (s *stubRuleSource) RuleSnapshot(adapter string) []wire.Rule {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]wire.Rule, 0, len(s.rules))
	for _, id := range s.rules {
		out = append(out, wire.Rule{RuleID: id, Type: wire.RuleTypeRequestBody, Adapter: adapter})
	}
	return out
}

// syncRecorder is a stub sidecar peer capturing the sync_rules pushes it receives.
// When gate is non-nil a handler blocks on it, letting a test hold one push open.
type syncRecorder struct {
	mu       sync.Mutex
	got      [][]wire.Rule
	inFlight int
	overlap  bool

	gate chan struct{}
}

func (s *syncRecorder) handle(_ context.Context, method string, params json.RawMessage) (any, *wire.Error) {
	if method != wire.MethodSyncRules {
		return nil, wire.NewError(-32601, "no")
	}
	var p wire.SyncRulesParams
	_ = json.Unmarshal(params, &p)

	s.mu.Lock()
	s.inFlight++
	if s.inFlight > 1 {
		s.overlap = true
	}
	gate := s.gate
	s.gate = nil // only the first push is held
	s.mu.Unlock()

	if gate != nil {
		<-gate
	}

	s.mu.Lock()
	s.got = append(s.got, p.Rules)
	s.inFlight--
	s.mu.Unlock()
	return wire.SyncRulesResult{Ack: true}, nil
}

func (s *syncRecorder) snapshots() [][]wire.Rule {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]wire.Rule(nil), s.got...)
}

// dialRecorder connects a stub sidecar that records sync_rules pushes.
func dialRecorder(t *testing.T, m *Manager, rec *syncRecorder) *wire.Peer {
	t.Helper()
	srvConn, cliConn := net.Pipe()
	go m.HandleConn(t.Context(), srvConn)

	p := wire.NewPeer(cliConn, nil)
	p.SetHandler(wire.HandlerFuncs{
		Request: rec.handle,
		Notification: func(_ context.Context, method string, _ json.RawMessage) {
			if method == wire.MethodPing {
				_ = p.Notify(wire.MethodPong, nil)
			}
		},
	})
	go func() { _ = p.Run(t.Context()) }()
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestManagerPushRules(t *testing.T) {
	t.Parallel()

	t.Run("scoped_snapshot_delivered", func(t *testing.T) {
		src := &stubRuleSource{}
		m := testManager(Config{})
		m.rules = src

		got := &syncRecorder{}
		p := dialRecorder(t, m, got)
		_, rerr := register(t, p, baseParams("alpha"))
		require.Nil(t, rerr)
		require.Len(t, got.snapshots(), 1) // empty seed at registration

		src.set("r1")
		m.PushRules(t.Context())

		snaps := got.snapshots()
		require.Len(t, snaps, 2)
		require.Len(t, snaps[1], 1)
		assert.Equal(t, "r1", snaps[1][0].RuleID)
		assert.Equal(t, "alpha", snaps[1][0].Adapter)
	})

	t.Run("empty_snapshot_clears", func(t *testing.T) {
		src := &stubRuleSource{}
		src.set("r1")
		m := testManager(Config{})
		m.rules = src

		got := &syncRecorder{}
		p := dialRecorder(t, m, got)
		_, rerr := register(t, p, baseParams("alpha"))
		require.Nil(t, rerr)
		require.Len(t, got.snapshots(), 1) // seeded at registration

		// deleting the last rule must still push, so the sidecar drops it
		src.set()
		m.PushRules(t.Context())

		snaps := got.snapshots()
		require.Len(t, snaps, 2)
		assert.Empty(t, snaps[1])
	})

	t.Run("stalled_push_releases_lock", func(t *testing.T) {
		src := &stubRuleSource{}
		src.set("r1")
		m := testManager(Config{})
		m.rules = src

		got := &syncRecorder{}
		p := dialRecorder(t, m, got)
		_, rerr := register(t, p, baseParams("alpha"))
		require.Nil(t, rerr)

		// hold the next push open, so the bounded caller hits its deadline
		got.mu.Lock()
		got.gate = make(chan struct{})
		gate := got.gate
		got.mu.Unlock()

		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		t.Cleanup(cancel)
		m.PushRules(ctx)

		// pushMu is released, so a later push proceeds once the sidecar answers again
		close(gate)
		m.PushRules(t.Context())
		assert.Len(t, got.snapshots(), 3)
	})

	t.Run("serializes_per_record", func(t *testing.T) {
		src := &stubRuleSource{}
		src.set("old")
		m := testManager(Config{})
		m.rules = src

		got := &syncRecorder{}
		p := dialRecorder(t, m, got)
		_, rerr := register(t, p, baseParams("alpha"))
		require.Nil(t, rerr)
		require.Len(t, got.snapshots(), 1) // seeded at registration

		// hold a push open, then start a second while the first is in flight
		got.mu.Lock()
		got.gate = make(chan struct{})
		gate := got.gate
		got.mu.Unlock()

		first := make(chan struct{})
		go func() {
			defer close(first)
			m.PushRules(t.Context())
		}()
		require.Eventually(t, func() bool {
			got.mu.Lock()
			defer got.mu.Unlock()
			return got.inFlight == 1
		}, 2*time.Second, time.Millisecond)

		src.set("new")
		second := make(chan struct{})
		go func() {
			defer close(second)
			m.PushRules(t.Context())
		}()
		// the second push blocks on pushMu, so it cannot finish while the first is held
		select {
		case <-second:
			t.Fatal("second push completed while the first was in flight")
		default:
		}

		close(gate)
		<-first
		<-second

		got.mu.Lock()
		overlap := got.overlap
		got.mu.Unlock()
		assert.False(t, overlap)

		// the queued push read the snapshot after acquiring the lock, so it carries "new"
		snaps := got.snapshots()
		require.Len(t, snaps, 3)
		require.Len(t, snaps[2], 1)
		assert.Equal(t, "new", snaps[2][0].RuleID)
	})
}

func TestRecordPushRulesSeed(t *testing.T) {
	t.Parallel()

	// an empty seed still pushes, clearing any cache a resuming sidecar retained
	t.Run("pushed_when_no_rules", func(t *testing.T) {
		m := testManager(Config{})
		m.rules = &stubRuleSource{}

		got := &syncRecorder{}
		p := dialRecorder(t, m, got)
		_, rerr := register(t, p, baseParams("alpha"))
		require.Nil(t, rerr)

		snaps := got.snapshots()
		require.Len(t, snaps, 1)
		assert.Empty(t, snaps[0])
	})

	t.Run("claims_wait_for_seed", func(t *testing.T) {
		src := &stubRuleSource{}
		src.set("r1")
		m := testManager(Config{})
		m.rules = src

		gate := make(chan struct{})
		got := &syncRecorder{gate: gate}
		p := dialRecorder(t, m, got)

		params := baseParams("alpha")
		params.Capabilities.UpgradeClaims = []wire.UpgradeClaim{{UpgradeSignal: "connect"}}
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, rerr := register(t, p, params)
			assert.Nil(t, rerr)
		}()

		claimed := func() bool {
			_, ok := m.registry.ClaimUpgrade(&protocol.UpgradeClaimCtx{Signal: "connect"})
			return ok
		}
		// hold the seed in flight; the claim seam must stay closed until it lands
		require.Eventually(t, func() bool {
			got.mu.Lock()
			defer got.mu.Unlock()
			return got.inFlight == 1
		}, 2*time.Second, time.Millisecond)
		assert.False(t, claimed())

		close(gate)
		<-done
		assert.True(t, claimed())
	})

	t.Run("tools_wait_for_seed", func(t *testing.T) {
		src := &stubRuleSource{}
		src.set("r1")
		m := toolManager([]string{"proxy_poll"})
		m.rules = src

		var notified atomic.Bool
		m.SetToolsChangedHook(func() { notified.Store(true) })

		gate := make(chan struct{})
		got := &syncRecorder{gate: gate}
		p := dialRecorder(t, m, got)

		done := make(chan struct{})
		go func() {
			defer close(done)
			_, rerr := register(t, p, toolParams("alpha", "alpha_tool"))
			assert.Nil(t, rerr)
		}()

		// hold the seed in flight; the tool must not be advertised until it lands
		require.Eventually(t, func() bool {
			got.mu.Lock()
			defer got.mu.Unlock()
			return got.inFlight == 1
		}, 2*time.Second, time.Millisecond)
		assert.False(t, notified.Load())

		close(gate)
		<-done
		assert.Eventually(t, notified.Load, 2*time.Second, time.Millisecond)
	})

	t.Run("pushed_when_rules_exist", func(t *testing.T) {
		src := &stubRuleSource{}
		src.set("r1", "r2")
		m := testManager(Config{})
		m.rules = src

		got := &syncRecorder{}
		p := dialRecorder(t, m, got)
		_, rerr := register(t, p, baseParams("alpha"))
		require.Nil(t, rerr)

		// the seed completes before register returns, so rules precede any claim
		snaps := got.snapshots()
		require.Len(t, snaps, 1)
		assert.Len(t, snaps[0], 2)
	})
}

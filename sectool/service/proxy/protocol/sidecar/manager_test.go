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

// fakeRules is a no-op RuleSource returning an empty snapshot.
type fakeRules struct{}

func (fakeRules) RuleSnapshot(string) []wire.Rule { return nil }

func testManager(cfg Config) *Manager {
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = time.Hour // effectively disable unless overridden
	}
	if cfg.HeartbeatTimeout == 0 {
		cfg.HeartbeatTimeout = time.Hour
	}
	if cfg.ReservedNames == nil {
		cfg.ReservedNames = []string{"http/1.1", "http/2", "websocket"}
	}
	return NewManager(cfg, &protocol.Registry{}, newFakeFlows(), fakeCoreTools{}, fakeRules{})
}

// dialManager connects a client wire.Peer to the manager over net.Pipe. When
// answerPing is true the client replies pong to keep itself healthy.
func dialManager(t *testing.T, m *Manager, answerPing bool) *wire.Peer {
	t.Helper()
	srv, cli := net.Pipe()
	go m.HandleConn(t.Context(), srv)

	var p *wire.Peer
	p = wire.NewPeer(cli, wire.HandlerFuncs{
		Notification: func(_ context.Context, method string, _ json.RawMessage) {
			if answerPing && method == wire.MethodPing {
				_ = p.Notify(wire.MethodPong, nil)
			}
		},
	})
	go func() { _ = p.Run(t.Context()) }()
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func baseParams(name string) wire.RegisterParams {
	return wire.RegisterParams{
		Name:            name,
		ProtocolVersion: wire.ProtocolVersion{Major: wire.VersionMajor, Minor: wire.VersionMinor},
		Protocols:       []string{"custom.foo"},
	}
}

func register(t *testing.T, p *wire.Peer, params wire.RegisterParams) (wire.RegisterResult, *wire.Error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	t.Cleanup(cancel)
	var res wire.RegisterResult
	err := p.Call(ctx, wire.MethodRegister, params, &res)
	return res, err
}

func TestManagerRegister(t *testing.T) {
	t.Parallel()

	t.Run("happy_path", func(t *testing.T) {
		m := testManager(Config{})
		p := dialManager(t, m, true)

		res, err := register(t, p, baseParams("demo"))
		require.Nil(t, err)
		assert.Equal(t, wire.VersionMajor, res.ProtocolVersion.Major)
		assert.Equal(t, wire.VersionMinor, res.ProtocolVersion.Minor)
		_, perr := time.Parse(time.RFC3339Nano, res.ServerTime)
		require.NoError(t, perr)

		rec, ok := m.Get("demo")
		require.True(t, ok)
		assert.True(t, rec.Healthy())
		assert.Equal(t, 1, m.Count())
	})

	t.Run("minor_too_new", func(t *testing.T) {
		m := testManager(Config{})
		p := dialManager(t, m, true)

		params := baseParams("demo")
		params.ProtocolVersion.Minor = wire.VersionMinor + 7
		_, err := register(t, p, params)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeVersionUnsupported, err.Code)
		require.NotNil(t, err.Data)
		assert.Equal(t, "demo", err.Data.Adapter)
		assert.Equal(t, 0, m.Count())
	})

	t.Run("major_mismatch", func(t *testing.T) {
		m := testManager(Config{})
		p := dialManager(t, m, true)

		params := baseParams("demo")
		params.ProtocolVersion.Major = wire.VersionMajor + 1
		_, err := register(t, p, params)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeVersionUnsupported, err.Code)
		require.NotNil(t, err.Data)
		assert.Equal(t, "demo", err.Data.Adapter)
		assert.Equal(t, 0, m.Count())
	})

	t.Run("duplicate_name", func(t *testing.T) {
		m := testManager(Config{})
		p1 := dialManager(t, m, true)
		_, err1 := register(t, p1, baseParams("dup"))
		require.Nil(t, err1)

		p2 := dialManager(t, m, true)
		_, err2 := register(t, p2, baseParams("dup"))
		require.NotNil(t, err2)
		assert.Equal(t, wire.CodeDuplicateRegistration, err2.Code)
		require.NotNil(t, err2.Data)
		assert.Equal(t, "dup", err2.Data.Adapter)
		assert.Equal(t, "dup", err2.Data.ConflictAdapter)
	})

	t.Run("reserved_name", func(t *testing.T) {
		m := testManager(Config{})
		p := dialManager(t, m, true)
		_, err := register(t, p, baseParams("http/1.1"))
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeDuplicateRegistration, err.Code)
		assert.Equal(t, "http/1.1", err.Data.ConflictAdapter)
	})

	t.Run("invalid_instance_id", func(t *testing.T) {
		m := testManager(Config{})
		p := dialManager(t, m, true)
		params := baseParams("demo")
		params.InstanceID = "not-a-uuid"
		_, err := register(t, p, params)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeRegistrationRejected, err.Code)
	})

	t.Run("reregister_same_conn", func(t *testing.T) {
		m := testManager(Config{})
		p := dialManager(t, m, true)
		params := baseParams("demo")
		params.InstanceID = "33333333-3333-3333-3333-333333333333"
		_, err := register(t, p, params)
		require.Nil(t, err)

		// second register on the live connection is rejected, not self-closed
		_, err = register(t, p, params)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeDuplicateRegistration, err.Code)

		rec, ok := m.Get("demo")
		require.True(t, ok)
		assert.True(t, rec.Healthy())
		assert.Equal(t, 1, m.Count())
	})

	t.Run("failed_reregister_keeps_existing", func(t *testing.T) {
		m := testManager(Config{NativeProxyPort: 8080})
		p1 := dialManager(t, m, true)
		params := baseParams("demo")
		params.InstanceID = "44444444-4444-4444-4444-444444444444"
		_, err := register(t, p1, params)
		require.Nil(t, err)
		rec1, _ := m.Get("demo")

		// reconnect whose claim blankets the native proxy port fails validation
		p2 := dialManager(t, m, true)
		bad := params
		bad.Capabilities.EarlyClaims = []wire.EarlyClaim{{PortRange: wire.PortRange{Low: 8080, High: 8080}}}
		_, err = register(t, p2, bad)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeCapabilityConflict, err.Code)

		rec2, ok := m.Get("demo")
		require.True(t, ok)
		assert.Same(t, rec1, rec2)
		assert.True(t, rec2.Healthy())
	})

	t.Run("failed_reregister_keeps_resume", func(t *testing.T) {
		const instance = "55555555-5555-5555-5555-555555555555"
		m := testManager(Config{NativeProxyPort: 8080})
		p1 := dialManager(t, m, true)
		params := baseParams("demo")
		params.InstanceID = instance
		params.Resume = true
		_, err := register(t, p1, params)
		require.Nil(t, err)

		// drop the connection so resume state is stashed
		_ = p1.Close()
		require.Eventually(t, func() bool { return m.Count() == 0 && m.hasResumeState(instance) }, 2*time.Second, 10*time.Millisecond)

		// a failing reconnect must not consume the stash
		p2 := dialManager(t, m, true)
		bad := params
		bad.Capabilities.EarlyClaims = []wire.EarlyClaim{{PortRange: wire.PortRange{Low: 8080, High: 8080}}}
		_, err = register(t, p2, bad)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeCapabilityConflict, err.Code)
		assert.True(t, m.hasResumeState(instance))
	})

	t.Run("resume_reclaim_race", func(t *testing.T) {
		const instance = "66666666-6666-6666-6666-666666666666"
		m := testManager(Config{})
		p1 := dialManager(t, m, true)
		params := baseParams("demo")
		params.InstanceID = instance
		params.Resume = true
		_, err := register(t, p1, params)
		require.Nil(t, err)

		// spam push_flow on conn1 so its handlers mutate ownedFlows during reclaim
		stop := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			pushLoop(t, p1, stop)
		}()

		// reconnect same instance while conn1 is live: reclaims its bookkeeping
		p2 := dialManager(t, m, true)
		_, err = register(t, p2, params)
		require.Nil(t, err)

		// push on conn2 too: a shared (uncloned) map would race conn1's lingering handlers
		for range 50 {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			var res wire.PushFlowResult
			_ = p2.Call(ctx, wire.MethodPushFlow, wire.Flow{Request: &wire.FlowMessage{Method: "GET", Path: "/"}}, &res)
			cancel()
		}

		close(stop)
		wg.Wait()

		rec, ok := m.Get("demo")
		require.True(t, ok)
		assert.Equal(t, instance, rec.InstanceID)
	})
}

// pushLoop emits create push_flows until stop closes.
func pushLoop(t *testing.T, p *wire.Peer, stop <-chan struct{}) {
	t.Helper()
	for {
		select {
		case <-stop:
			return
		default:
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		var res wire.PushFlowResult
		_ = p.Call(ctx, wire.MethodPushFlow, wire.Flow{Request: &wire.FlowMessage{Method: "GET", Path: "/"}}, &res)
		cancel()
	}
}

func TestManagerHeartbeat(t *testing.T) {
	t.Parallel()

	t.Run("healthy_after_register", func(t *testing.T) {
		m := testManager(Config{HeartbeatInterval: 15 * time.Millisecond, HeartbeatTimeout: 150 * time.Millisecond})
		p := dialManager(t, m, true)
		_, err := register(t, p, baseParams("demo"))
		require.Nil(t, err)
		rec, _ := m.Get("demo")

		require.True(t, rec.Healthy())
		rec.healthy.Store(false)
		rec.recordPong(time.Unix(0, 0))
		require.True(t, rec.Healthy())
	})

	t.Run("unhealthy_on_timeout", func(t *testing.T) {
		m := testManager(Config{HeartbeatInterval: 15 * time.Millisecond, HeartbeatTimeout: 40 * time.Millisecond})
		p := dialManager(t, m, false) // silent: never answers ping
		_, err := register(t, p, baseParams("demo"))
		require.Nil(t, err)
		rec, _ := m.Get("demo")

		require.Eventually(t, func() bool { return !rec.Healthy() }, 2*time.Second, 20*time.Millisecond)
	})
}

func TestManagerReconnectResume(t *testing.T) {
	t.Parallel()

	const instance = "11111111-1111-1111-1111-111111111111"
	m := testManager(Config{})

	p1 := dialManager(t, m, true)
	params := baseParams("demo")
	params.InstanceID = instance
	params.Resume = true
	_, err := register(t, p1, params)
	require.Nil(t, err)
	require.Equal(t, 1, m.Count())

	// drop connection: record removed, resume state stashed
	_ = p1.Close()
	require.Eventually(t, func() bool { return m.Count() == 0 && m.hasResumeState(instance) }, 2*time.Second, 10*time.Millisecond)

	// Reconnect with the same instance_id reattaches.
	p2 := dialManager(t, m, true)
	_, err = register(t, p2, params)
	require.Nil(t, err)
	rec, ok := m.Get("demo")
	require.True(t, ok)
	assert.Equal(t, instance, rec.InstanceID)
	assert.False(t, m.hasResumeState(instance))
}

func TestManagerHandleConn(t *testing.T) {
	t.Parallel()

	t.Run("cancel_closes_unregistered", func(t *testing.T) {
		m := testManager(Config{})
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		srv, cli := net.Pipe()
		done := make(chan struct{})
		go func() {
			m.HandleConn(ctx, srv)
			close(done)
		}()

		p := wire.NewPeer(cli, wire.HandlerFuncs{})
		go func() { _ = p.Run(t.Context()) }()
		t.Cleanup(func() { _ = p.Close() })

		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("HandleConn did not return")
		}
		assert.Eventually(t, p.Closed, 2*time.Second, 10*time.Millisecond)
	})
}

func TestManagerShutdown(t *testing.T) {
	t.Parallel()

	m := testManager(Config{})
	drained := make(chan int, 1)
	srv, cli := net.Pipe()
	go m.HandleConn(t.Context(), srv)

	p := wire.NewPeer(cli, wire.HandlerFuncs{
		Request: func(_ context.Context, method string, params json.RawMessage) (any, *wire.Error) {
			if method == wire.MethodShutdown {
				var sp wire.ShutdownParams
				_ = json.Unmarshal(params, &sp)
				drained <- sp.DrainSeconds
				return wire.ShutdownResult{Ack: true}, nil
			}
			return nil, wire.NewError(-32601, "no")
		},
	})
	go func() { _ = p.Run(t.Context()) }()
	t.Cleanup(func() { _ = p.Close() })

	_, err := register(t, p, baseParams("demo"))
	require.Nil(t, err)

	m.Shutdown(t.Context())
	select {
	case d := <-drained:
		assert.Equal(t, shutdownDrainSeconds, d)
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown not delivered")
	}
	assert.Eventually(t, func() bool { return m.Count() == 0 }, 2*time.Second, 10*time.Millisecond)
}

func TestSessionQueueDiag(t *testing.T) {
	t.Parallel()

	srv, cli := net.Pipe()
	t.Cleanup(func() { _ = cli.Close() })
	s := &session{diag: make(chan func(), diagQueue)}
	s.peer = wire.NewPeer(srv, wire.HandlerFuncs{})
	t.Cleanup(func() { _ = s.peer.Close() })
	go s.writeDiag()

	t.Run("runs_in_order", func(t *testing.T) {
		got := make(chan int, 10)
		for i := range 10 {
			s.queueDiag(func() { got <- i })
		}
		for i := range 10 {
			select {
			case v := <-got:
				require.Equal(t, i, v)
			case <-time.After(2 * time.Second):
				t.Fatal("diagnostic not run")
			}
		}
	})

	t.Run("drops_when_full", func(t *testing.T) {
		// wedge the writer so the queue fills without draining
		started := make(chan struct{})
		block := make(chan struct{})
		s.queueDiag(func() { close(started); <-block })
		<-started // writer pulled the wedge; the buffer is empty again

		var ran, dropped atomic.Int32
		for range diagQueue {
			s.queueDiag(func() { ran.Add(1) })
		}
		for range 100 {
			s.queueDiag(func() { dropped.Add(1) })
		}
		close(block)

		require.Eventually(t, func() bool { return ran.Load() == diagQueue }, 2*time.Second, 10*time.Millisecond)
		assert.Zero(t, dropped.Load())
	})
}

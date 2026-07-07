package sidecar

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// fakeRules is a no-op RuleSource returning an empty snapshot.
type fakeRules struct{}

func (fakeRules) RuleSnapshot(string) (uint64, []wire.Rule) { return 0, nil }

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

	p := wire.NewPeer(cli, nil)
	p.SetHandler(wire.HandlerFuncs{
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
		assert.Empty(t, res.RulesSnapshot)
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
}

func TestManagerHeartbeat(t *testing.T) {
	t.Parallel()

	t.Run("healthy_while_answering", func(t *testing.T) {
		// timeout wide vs interval so -race jitter can't delay a pong past it
		m := testManager(Config{HeartbeatInterval: 15 * time.Millisecond, HeartbeatTimeout: 150 * time.Millisecond})
		p := dialManager(t, m, true)
		_, err := register(t, p, baseParams("demo"))
		require.Nil(t, err)
		rec, _ := m.Get("demo")

		require.Never(t, func() bool { return !rec.Healthy() }, 300*time.Millisecond, 20*time.Millisecond)
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

func TestManagerShutdown(t *testing.T) {
	t.Parallel()

	m := testManager(Config{})
	drained := make(chan int, 1)
	srv, cli := net.Pipe()
	go m.HandleConn(t.Context(), srv)

	p := wire.NewPeer(cli, nil)
	p.SetHandler(wire.HandlerFuncs{
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

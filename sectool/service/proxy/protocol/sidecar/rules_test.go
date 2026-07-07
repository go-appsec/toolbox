package sidecar

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// stubRuleSource returns one rule named after the queried adapter, so a test can
// confirm the manager routed each sidecar its own scoped snapshot. version is read
// through a pointer so it can change between register and PushRules.
type stubRuleSource struct{ version *uint64 }

func (s stubRuleSource) RuleSnapshot(adapter string) (uint64, []wire.Rule) {
	return *s.version, []wire.Rule{{RuleID: adapter + "-r", Type: "request_body", Adapter: adapter}}
}

func TestManagerPushRules(t *testing.T) {
	t.Parallel()

	var version uint64
	m := testManager(Config{})
	m.rules = stubRuleSource{version: &version}

	srvConn, cliConn := net.Pipe()
	go m.HandleConn(t.Context(), srvConn)

	got := make(chan wire.SyncRulesParams, 1)
	p := wire.NewPeer(cliConn, nil)
	p.SetHandler(wire.HandlerFuncs{
		Request: func(_ context.Context, method string, params json.RawMessage) (any, *wire.Error) {
			if method != wire.MethodSyncRules {
				return nil, wire.NewError(-32601, "no")
			}
			var sp wire.SyncRulesParams
			_ = json.Unmarshal(params, &sp)
			got <- sp
			return wire.SyncRulesResult{Ack: true, AppliedVersion: sp.SnapshotVersion}, nil
		},
		Notification: func(_ context.Context, method string, _ json.RawMessage) {
			if method == wire.MethodPing {
				_ = p.Notify(wire.MethodPong, nil)
			}
		},
	})
	go func() { _ = p.Run(t.Context()) }()
	t.Cleanup(func() { _ = p.Close() })

	res, rerr := register(t, p, baseParams("alpha"))
	require.Nil(t, rerr)
	// registration carries the initial version 0 snapshot scoped to this adapter
	require.Len(t, res.RulesSnapshot, 1)
	assert.Equal(t, "alpha", res.RulesSnapshot[0].Adapter)

	rec, ok := m.Get("alpha")
	require.True(t, ok)
	assert.Equal(t, uint64(0), rec.appliedVersion.Load())

	version = 9
	m.PushRules(t.Context())

	// PushRules waits for the ack, so the snapshot has arrived
	select {
	case sp := <-got:
		assert.Equal(t, uint64(9), sp.SnapshotVersion)
		require.Len(t, sp.Rules, 1)
		assert.Equal(t, "alpha", sp.Rules[0].Adapter)
	default:
		t.Fatal("sidecar did not receive sync_rules")
	}
	assert.Equal(t, uint64(9), rec.appliedVersion.Load())
}

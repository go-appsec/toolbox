package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubEarly records claim/serve calls for dispatch-order testing.
type stubEarly struct {
	name       string
	claim      bool
	claimCalls int
	serveCalls int
}

func (s *stubEarly) Name() string                                        { return s.name }
func (s *stubEarly) ClaimEarly(*protocol.EarlyClaimCtx) bool             { s.claimCalls++; return s.claim }
func (s *stubEarly) ServeEarly(context.Context, *protocol.EarlyClaimCtx) { s.serveCalls++ }

func TestRegistryDispatchEarly(t *testing.T) {
	t.Parallel()

	t.Run("first_claim_wins", func(t *testing.T) {
		first := &stubEarly{name: "first", claim: true}
		second := &stubEarly{name: "second", claim: true}
		reg := &protocol.Registry{Early: []protocol.EarlyAdapter{first, second}}

		reg.DispatchEarly(context.Background(), &protocol.EarlyClaimCtx{})

		assert.Equal(t, 1, first.serveCalls)
		assert.Equal(t, 0, second.serveCalls)
		assert.Equal(t, 0, second.claimCalls) // short-circuits once first claims
	})

	t.Run("fallthrough_to_later", func(t *testing.T) {
		decline := &stubEarly{name: "decline", claim: false}
		fallthr := &stubEarly{name: "fallthrough", claim: true}
		reg := &protocol.Registry{Early: []protocol.EarlyAdapter{decline, fallthr}}

		reg.DispatchEarly(context.Background(), &protocol.EarlyClaimCtx{})

		assert.Equal(t, 0, decline.serveCalls)
		assert.Equal(t, 1, fallthr.serveCalls)
	})

	t.Run("no_claimer_no_serve", func(t *testing.T) {
		none := &stubEarly{name: "none", claim: false}
		reg := &protocol.Registry{Early: []protocol.EarlyAdapter{none}}

		reg.DispatchEarly(context.Background(), &protocol.EarlyClaimCtx{})

		assert.Equal(t, 0, none.serveCalls)
	})
}

func TestRegistryInsertRemoveEarly(t *testing.T) {
	t.Parallel()

	fallthr := &stubEarly{name: "fallthrough", claim: true}
	reg := &protocol.Registry{Early: []protocol.EarlyAdapter{fallthr}}

	sidecar := &stubEarly{name: "sidecar", claim: true}
	reg.InsertEarly(sidecar)

	// Inserted ahead of the fallthrough, so it claims first
	reg.DispatchEarly(context.Background(), &protocol.EarlyClaimCtx{})
	assert.Equal(t, 1, sidecar.serveCalls)
	assert.Equal(t, 0, fallthr.serveCalls)

	// Removed, the fallthrough handles the connection again
	reg.RemoveEarly("sidecar")
	reg.DispatchEarly(context.Background(), &protocol.EarlyClaimCtx{})
	assert.Equal(t, 1, sidecar.serveCalls)
	assert.Equal(t, 1, fallthr.serveCalls)
}

func TestEarlyClaim(t *testing.T) {
	t.Parallel()

	var h1 http1Adapter
	var h2 http2Adapter

	tests := []struct {
		name     string
		ctx      *protocol.EarlyClaimCtx
		h2Claims bool
	}{
		{"raw_accept", &protocol.EarlyClaimCtx{}, false},
		{"alpn_h2", &protocol.EarlyClaimCtx{TLSTerminated: true, ALPN: alpnH2}, true},
		{"alpn_http1", &protocol.EarlyClaimCtx{TLSTerminated: true, ALPN: alpnHTTP1}, false},
		{"cleartext_h2_alpn", &protocol.EarlyClaimCtx{ALPN: alpnH2}, false}, // not TLS-terminated
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.h2Claims, h2.ClaimEarly(tt.ctx))
			assert.True(t, h1.ClaimEarly(tt.ctx)) // http1 is the unconditional fallthrough
		})
	}
}

func TestClaimUpgrade(t *testing.T) {
	t.Parallel()

	reg := &protocol.Registry{Upgrade: []protocol.UpgradeAdapter{wsAdapter{}}}

	handshake := &types.RawHTTP1Request{Headers: types.Headers{
		{Name: "Upgrade", Value: "websocket"},
		{Name: "Connection", Value: "Upgrade"},
	}}
	a, ok := reg.ClaimUpgrade(&protocol.UpgradeClaimCtx{Req: handshake})
	require.True(t, ok)
	assert.Equal(t, types.ProtocolTagWS, a.Name())

	plain := &types.RawHTTP1Request{Headers: types.Headers{{Name: "Host", Value: "example.com"}}}
	_, ok = reg.ClaimUpgrade(&protocol.UpgradeClaimCtx{Req: plain})
	assert.False(t, ok)
}

func TestServeRejectsH2C(t *testing.T) {
	t.Parallel()

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{}, false)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", proxy.Addr())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// Cleartext HTTP/2 preface is rejected and the connection closed with no response.
	_, err = conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	require.NoError(t, err)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	assert.Zero(t, n)
	// Connection is closed, not merely left to hit the read deadline
	require.ErrorIs(t, err, io.EOF)
}

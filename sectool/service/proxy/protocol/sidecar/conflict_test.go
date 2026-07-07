package sidecar

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

func mustRegister(t *testing.T, m *Manager, params wire.RegisterParams) {
	t.Helper()
	p := dialManager(t, m, true)
	_, err := register(t, p, params)
	require.Nil(t, err)
}

func registerErr(t *testing.T, m *Manager, params wire.RegisterParams) *wire.Error {
	t.Helper()
	p := dialManager(t, m, true)
	_, err := register(t, p, params)
	return err
}

func TestConflictEarlyClaim(t *testing.T) {
	t.Parallel()

	t.Run("overlap_no_matcher", func(t *testing.T) {
		m := testManager(Config{})
		a := baseParams("a")
		a.Capabilities.EarlyClaim = &wire.EarlyClaim{PortRange: wire.PortRange{Low: 8000, High: 8100}}
		mustRegister(t, m, a)

		b := baseParams("b")
		b.Capabilities.EarlyClaim = &wire.EarlyClaim{PortRange: wire.PortRange{Low: 8050, High: 8200}}
		err := registerErr(t, m, b)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeCapabilityConflict, err.Code)
		assert.Equal(t, "b", err.Data.Adapter)
		assert.Equal(t, "a", err.Data.ConflictAdapter)
	})

	t.Run("distinguished_by_prefix", func(t *testing.T) {
		m := testManager(Config{})
		a := baseParams("a")
		a.Capabilities.EarlyClaim = &wire.EarlyClaim{
			PortRange:        wire.PortRange{Low: 9000, High: 9000},
			MagicBytesPrefix: base64.StdEncoding.EncodeToString([]byte("AB")),
		}
		mustRegister(t, m, a)

		b := baseParams("b")
		b.Capabilities.EarlyClaim = &wire.EarlyClaim{
			PortRange:        wire.PortRange{Low: 9000, High: 9000},
			MagicBytesPrefix: base64.StdEncoding.EncodeToString([]byte("CD")),
		}
		require.Nil(t, registerErr(t, m, b))
	})

	t.Run("includes_native_port", func(t *testing.T) {
		m := testManager(Config{NativeProxyPort: 8080})
		a := baseParams("a")
		a.Capabilities.EarlyClaim = &wire.EarlyClaim{PortRange: wire.PortRange{Low: 8000, High: 8100}}
		err := registerErr(t, m, a)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeCapabilityConflict, err.Code)
		assert.Equal(t, "native-proxy", err.Data.ConflictAdapter)
	})
}

func TestConflictUpgradeClaim(t *testing.T) {
	t.Parallel()

	t.Run("incomparable_overlap", func(t *testing.T) {
		m := testManager(Config{})
		a := baseParams("a")
		a.Capabilities.UpgradeClaim = &wire.UpgradeClaim{HostPattern: "*.example.com", PathPattern: "/ws"}
		mustRegister(t, m, a)

		b := baseParams("b")
		b.Capabilities.UpgradeClaim = &wire.UpgradeClaim{HostPattern: "app.example.com", PathPattern: "/ws/*"}
		err := registerErr(t, m, b)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeCapabilityConflict, err.Code)
	})

	t.Run("most_specific_wins", func(t *testing.T) {
		m := testManager(Config{})
		a := baseParams("a")
		a.Capabilities.UpgradeClaim = &wire.UpgradeClaim{HostPattern: "*.example.com", PathPattern: "/ws/*"}
		mustRegister(t, m, a)

		b := baseParams("b")
		b.Capabilities.UpgradeClaim = &wire.UpgradeClaim{HostPattern: "app.example.com", PathPattern: "/ws"}
		require.Nil(t, registerErr(t, m, b))
	})
}

func TestPatternRank(t *testing.T) {
	t.Parallel()
	assert.Equal(t, rankCatchAll, patternRank(""))
	assert.Equal(t, rankCatchAll, patternRank("*"))
	assert.Equal(t, rankLiteral, patternRank("app.example.com"))
	assert.Equal(t, rankGlob, patternRank("*.example.com"))
	assert.Equal(t, rankRegex, patternRank(`^app\.example\.com$`))
}

func TestPrefixesDistinct(t *testing.T) {
	t.Parallel()
	enc := base64.StdEncoding.EncodeToString
	assert.True(t, prefixesDistinct(enc([]byte("AB")), enc([]byte("CD"))))
	assert.False(t, prefixesDistinct(enc([]byte("AB")), enc([]byte("ABC")))) // one is a prefix of the other
	assert.False(t, prefixesDistinct("", enc([]byte("AB"))))                 // empty matches all
}

func TestEarlyClaimsDistinct(t *testing.T) {
	t.Parallel()
	raw := &wire.EarlyClaim{PortRange: wire.PortRange{Low: 1, High: 1}}
	tlsTerm := &wire.EarlyClaim{PortRange: wire.PortRange{Low: 1, High: 1}, TLS: &wire.TLSClaim{Terminate: true}}
	assert.False(t, earlyClaimsDistinct(raw, tlsTerm), "mixing tls-terminate and raw is ambiguous")

	probeA := &wire.EarlyClaim{Probe: true}
	probeB := &wire.EarlyClaim{Probe: true}
	assert.True(t, earlyClaimsDistinct(probeA, probeB), "two probe claims may chain")

	staticPrefix := &wire.EarlyClaim{MagicBytesPrefix: base64.StdEncoding.EncodeToString([]byte("AB"))}
	assert.False(t, earlyClaimsDistinct(probeA, staticPrefix), "mixed probe/static is ambiguous")
}

func TestRangesOverlap(t *testing.T) {
	t.Parallel()
	assert.True(t, rangesOverlap(wire.PortRange{Low: 1, High: 10}, wire.PortRange{Low: 5, High: 15}))
	assert.False(t, rangesOverlap(wire.PortRange{Low: 1, High: 10}, wire.PortRange{Low: 11, High: 20}))
}

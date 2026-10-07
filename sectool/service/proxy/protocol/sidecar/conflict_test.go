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
		a.Capabilities.EarlyClaims = []wire.EarlyClaim{{PortRange: wire.PortRange{Low: 8000, High: 8100}}}
		mustRegister(t, m, a)

		b := baseParams("b")
		b.Capabilities.EarlyClaims = []wire.EarlyClaim{{PortRange: wire.PortRange{Low: 8050, High: 8200}}}
		err := registerErr(t, m, b)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeCapabilityConflict, err.Code)
		assert.Equal(t, "b", err.Data.Adapter)
		assert.Equal(t, "a", err.Data.ConflictAdapter)
	})

	t.Run("distinguished_by_prefix", func(t *testing.T) {
		m := testManager(Config{})
		a := baseParams("a")
		a.Capabilities.EarlyClaims = []wire.EarlyClaim{{
			PortRange:        wire.PortRange{Low: 9000, High: 9000},
			MagicBytesPrefix: base64.StdEncoding.EncodeToString([]byte("AB")),
		}}
		mustRegister(t, m, a)

		b := baseParams("b")
		b.Capabilities.EarlyClaims = []wire.EarlyClaim{{
			PortRange:        wire.PortRange{Low: 9000, High: 9000},
			MagicBytesPrefix: base64.StdEncoding.EncodeToString([]byte("CD")),
		}}
		require.Nil(t, registerErr(t, m, b))
	})

	t.Run("includes_native_port", func(t *testing.T) {
		m := testManager(Config{NativeProxyPort: 8080})
		a := baseParams("a")
		a.Capabilities.EarlyClaims = []wire.EarlyClaim{{PortRange: wire.PortRange{Low: 8000, High: 8100}}}
		err := registerErr(t, m, a)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeCapabilityConflict, err.Code)
		assert.Equal(t, "native-proxy", err.Data.ConflictAdapter)
	})

	t.Run("wildcard_with_magic_keeps_native_port", func(t *testing.T) {
		m := testManager(Config{NativeProxyPort: 8080})
		a := baseParams("a")
		a.Capabilities.EarlyClaims = []wire.EarlyClaim{{
			MagicBytesPrefix: base64.StdEncoding.EncodeToString([]byte("ECHO")),
		}}
		require.Nil(t, registerErr(t, m, a))
	})

	t.Run("wildcard_overlaps_explicit_range", func(t *testing.T) {
		m := testManager(Config{})
		a := baseParams("a")
		a.Capabilities.EarlyClaims = []wire.EarlyClaim{{}}
		mustRegister(t, m, a)

		b := baseParams("b")
		b.Capabilities.EarlyClaims = []wire.EarlyClaim{{PortRange: wire.PortRange{Low: 1883, High: 1883}}}
		err := registerErr(t, m, b)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeCapabilityConflict, err.Code)
		assert.Equal(t, "a", err.Data.ConflictAdapter)
	})

	t.Run("invalid_claim_rejected", func(t *testing.T) {
		m := testManager(Config{})
		a := baseParams("a")
		a.Capabilities.EarlyClaims = []wire.EarlyClaim{{PortRange: wire.PortRange{Low: 900, High: 100}}}
		err := registerErr(t, m, a)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeRegistrationRejected, err.Code)
	})
}

func TestConflictUpgradeClaim(t *testing.T) {
	t.Parallel()

	t.Run("incomparable_overlap", func(t *testing.T) {
		m := testManager(Config{})
		a := baseParams("a")
		a.Capabilities.UpgradeClaims = []wire.UpgradeClaim{{HostPattern: `.*\.example\.com`, PathPattern: "/ws"}}
		mustRegister(t, m, a)

		b := baseParams("b")
		b.Capabilities.UpgradeClaims = []wire.UpgradeClaim{{HostPattern: `app\.example\.com`, PathPattern: "/ws/.*"}}
		err := registerErr(t, m, b)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeCapabilityConflict, err.Code)
	})

	t.Run("most_specific_wins", func(t *testing.T) {
		m := testManager(Config{})
		a := baseParams("a")
		a.Capabilities.UpgradeClaims = []wire.UpgradeClaim{{HostPattern: `.*\.example\.com`, PathPattern: "/ws/.*"}}
		mustRegister(t, m, a)

		b := baseParams("b")
		b.Capabilities.UpgradeClaims = []wire.UpgradeClaim{{HostPattern: `app\.example\.com`, PathPattern: "/ws"}}
		require.Nil(t, registerErr(t, m, b))
	})

	t.Run("raw_host_literal_dominates", func(t *testing.T) {
		m := testManager(Config{})
		a := baseParams("a")
		a.Capabilities.UpgradeClaims = []wire.UpgradeClaim{{HostPattern: `.*\.example\.com`, PathPattern: "/ws"}}
		mustRegister(t, m, a)

		b := baseParams("b")
		b.Capabilities.UpgradeClaims = []wire.UpgradeClaim{{HostPattern: "ctrl.example.com", PathPattern: "/ws"}}
		require.Nil(t, registerErr(t, m, b))
	})
}

func TestConflictSelfOverlap(t *testing.T) {
	t.Parallel()

	t.Run("distinct_upgrade_claims_ok", func(t *testing.T) {
		m := testManager(Config{})
		a := baseParams("a")
		a.Capabilities.UpgradeClaims = []wire.UpgradeClaim{
			{HostPattern: "ctrl.example.com", PathPattern: "/ts2021"},
			{HostPattern: "ctrl.example.com", PathPattern: "/derp"},
		}
		require.Nil(t, registerErr(t, m, a))
	})

	t.Run("overlapping_upgrade_claims_rejected", func(t *testing.T) {
		m := testManager(Config{})
		a := baseParams("a")
		a.Capabilities.UpgradeClaims = []wire.UpgradeClaim{
			{HostPattern: "ctrl.example.com", PathPattern: "/ws"},
			{HostPattern: "ctrl.example.com", PathPattern: "/ws"},
		}
		err := registerErr(t, m, a)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeCapabilityConflict, err.Code)
		assert.Equal(t, "a", err.Data.Adapter)
		assert.Equal(t, "a", err.Data.ConflictAdapter)
	})

	t.Run("overlapping_early_claims_rejected", func(t *testing.T) {
		m := testManager(Config{})
		a := baseParams("a")
		a.Capabilities.EarlyClaims = []wire.EarlyClaim{
			{PortRange: wire.PortRange{Low: 8000, High: 8100}},
			{PortRange: wire.PortRange{Low: 8050, High: 8200}},
		}
		err := registerErr(t, m, a)
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeCapabilityConflict, err.Code)
		assert.Equal(t, "a", err.Data.ConflictAdapter)
	})
}

func TestConflictClaimSeams(t *testing.T) {
	t.Parallel()

	// a raw claim and a TLS-terminating claim live on separate seams, so one
	// registration may declare both for the plain and TLS forms of a protocol
	m := testManager(Config{NativeProxyPort: 8080})
	a := baseParams("a")
	a.Capabilities.EarlyClaims = []wire.EarlyClaim{
		{MagicBytesPrefix: base64.StdEncoding.EncodeToString([]byte("MQTT"))},
		{PortRange: wire.PortRange{Low: 8883, High: 8883}, TLS: &wire.TLSClaim{Terminate: true}},
	}
	require.Nil(t, registerErr(t, m, a))
}

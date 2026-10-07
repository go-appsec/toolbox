package sidecar

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// mustCompileUpgrade compiles a single claim for match/conflict assertions.
func mustCompileUpgrade(t *testing.T, uc wire.UpgradeClaim) *upgradeClaim {
	t.Helper()

	out, err := compileUpgradeClaims([]wire.UpgradeClaim{uc})
	require.NoError(t, err)
	return &out[0]
}

func TestCompileUpgradeClaims(t *testing.T) {
	t.Parallel()

	t.Run("empty_signal_defaults_http_101", func(t *testing.T) {
		assert.Equal(t, signalHTTP101, mustCompileUpgrade(t, wire.UpgradeClaim{}).signal)
	})
	t.Run("unknown_signal_rejected", func(t *testing.T) {
		_, err := compileUpgradeClaims([]wire.UpgradeClaim{{UpgradeSignal: "ws"}})
		assert.Error(t, err)
	})
	t.Run("invalid_regex_rejected", func(t *testing.T) {
		_, err := compileUpgradeClaims([]wire.UpgradeClaim{{HostPattern: "*.example.com"}})
		assert.Error(t, err)
	})
	t.Run("raw_host_src_preserved", func(t *testing.T) {
		uc := mustCompileUpgrade(t, wire.UpgradeClaim{HostPattern: "ctrl.example.com"})
		assert.Equal(t, "ctrl.example.com", uc.host.src)
	})
}

func TestPatternMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		value   string
		match   bool
	}{
		{name: "empty_matches_any", pattern: "", value: "anything", match: true},
		{name: "literal_exact", pattern: `app\.example\.com`, value: "app.example.com", match: true},
		{name: "literal_anchored", pattern: `app\.example\.com`, value: "app.example.com.evil.test", match: false},
		{name: "raw_dot_literal_exact", pattern: "app.example.com", value: "app.example.com", match: true},
		{name: "raw_dot_no_wildcard", pattern: "app.example.com", value: "appXexampleYcom", match: false},
		{name: "raw_path_literal_exact", pattern: "/api/v1.2/status", value: "/api/v1.2/status", match: true},
		{name: "raw_path_no_wildcard", pattern: "/api/v1.2/status", value: "/api/v1x2/status", match: false},
		{name: "regex_wildcard", pattern: `.*\.example\.com`, value: "app.example.com", match: true},
		{name: "regex_alternation", pattern: "/ws/(chat|feed)", value: "/ws/feed", match: true},
		{name: "regex_anchored_both_ends", pattern: "/ws", value: "/ws/chat", match: false},
		{name: "explicit_anchors_allowed", pattern: "^/ws$", value: "/ws", match: true},
		{name: "regex_metacharacters_literal", pattern: `/api/v1\(beta\)`, value: "/api/v1(beta)", match: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := compilePattern(tt.pattern)
			require.NoError(t, err)
			assert.Equal(t, tt.match, p.match(tt.value))
		})
	}
}

func TestPatternRank(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern string
		rank    int
	}{
		{pattern: "", rank: rankCatchAll},
		{pattern: `app\.example\.com`, rank: rankLiteral},
		{pattern: "/ws", rank: rankLiteral},
		{pattern: "ctrl.example.com", rank: rankLiteral},
		{pattern: "/api/v1.2/status", rank: rankLiteral},
		{pattern: ".", rank: rankLiteral},
		{pattern: `.*\.example\.com`, rank: rankRegex},
		{pattern: ".*", rank: rankRegex},
	}

	for _, tt := range tests {
		p, err := compilePattern(tt.pattern)
		require.NoError(t, err)
		assert.Equal(t, tt.rank, p.rank(), tt.pattern)
	}
}

func TestUpgradeClaimMatch(t *testing.T) {
	t.Parallel()

	t.Run("empty_signal_matches_http_101", func(t *testing.T) {
		uc := mustCompileUpgrade(t, wire.UpgradeClaim{PathPattern: "/control"})
		assert.True(t, uc.match(upgradeCtx(signalHTTP101, "GET", "h", "/control", "custom")))
	})
	t.Run("connect_signal_ignores_path", func(t *testing.T) {
		uc := mustCompileUpgrade(t, wire.UpgradeClaim{UpgradeSignal: signalConnect})
		assert.True(t, uc.match(upgradeCtx(signalConnect, "CONNECT", "h", "h:443", "")))
	})
	t.Run("regex_path_matches", func(t *testing.T) {
		uc := mustCompileUpgrade(t, wire.UpgradeClaim{PathPattern: "/ws/(chat|feed)"})
		assert.True(t, uc.match(upgradeCtx(signalHTTP101, "GET", "h", "/ws/chat", "websocket")))
		assert.False(t, uc.match(upgradeCtx(signalHTTP101, "GET", "h", "/ws/other", "websocket")))
	})
}

func TestUpgradeClaimConflict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		a, b     wire.UpgradeClaim
		conflict bool
	}{
		{
			name:     "identical_claims",
			a:        wire.UpgradeClaim{HostPattern: "ctrl.example.com", PathPattern: "/ws"},
			b:        wire.UpgradeClaim{HostPattern: "ctrl.example.com", PathPattern: "/ws"},
			conflict: true,
		},
		{
			name:     "distinct_literal_paths",
			a:        wire.UpgradeClaim{HostPattern: "ctrl.example.com", PathPattern: "/ts2021"},
			b:        wire.UpgradeClaim{HostPattern: "ctrl.example.com", PathPattern: "/derp"},
			conflict: false,
		},
		{
			name:     "incomparable_specificity",
			a:        wire.UpgradeClaim{HostPattern: `.*\.example\.com`, PathPattern: "/ws"},
			b:        wire.UpgradeClaim{HostPattern: `app\.example\.com`, PathPattern: "/ws/.*"},
			conflict: true,
		},
		{
			name:     "one_claim_dominates",
			a:        wire.UpgradeClaim{HostPattern: `.*\.example\.com`, PathPattern: "/ws/.*"},
			b:        wire.UpgradeClaim{HostPattern: `app\.example\.com`, PathPattern: "/ws"},
			conflict: false,
		},
		{
			name:     "literal_dominates_regex_host",
			a:        wire.UpgradeClaim{HostPattern: `.*\.example\.com`, PathPattern: "/ws"},
			b:        wire.UpgradeClaim{HostPattern: "ctrl.example.com", PathPattern: "/ws"},
			conflict: false,
		},
		{
			name:     "different_signals",
			a:        wire.UpgradeClaim{HostPattern: "ctrl.example.com", UpgradeSignal: signalConnect},
			b:        wire.UpgradeClaim{HostPattern: "ctrl.example.com", UpgradeSignal: signalHTTP101},
			conflict: false,
		},
		{
			name:     "empty_signal_versus_connect",
			a:        wire.UpgradeClaim{HostPattern: "ctrl.example.com"},
			b:        wire.UpgradeClaim{HostPattern: "ctrl.example.com", UpgradeSignal: signalConnect},
			conflict: false,
		},
		{
			name:     "empty_signal_versus_explicit_http_101",
			a:        wire.UpgradeClaim{HostPattern: "ctrl.example.com"},
			b:        wire.UpgradeClaim{HostPattern: "ctrl.example.com", UpgradeSignal: signalHTTP101},
			conflict: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, b := mustCompileUpgrade(t, tt.a), mustCompileUpgrade(t, tt.b)
			assert.Equal(t, tt.conflict, upgradeClaimConflict(a, b))
			assert.Equal(t, tt.conflict, upgradeClaimConflict(b, a))
		})
	}
}

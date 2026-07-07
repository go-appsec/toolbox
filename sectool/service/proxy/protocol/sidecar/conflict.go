package sidecar

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// checkConflicts validates a registration against reserved names and already
// registered sidecars. Callers hold m.mu.
func (m *Manager) checkConflicts(p *wire.RegisterParams) *wire.Error {
	if slices.Contains(m.cfg.ReservedNames, p.Name) {
		return wire.NewError(wire.CodeDuplicateRegistration,
			"adapter name conflicts with a built-in adapter: "+p.Name).
			WithData(&wire.ErrorData{Adapter: p.Name, ConflictAdapter: p.Name})
	}
	if ec := p.Capabilities.EarlyClaim; ec != nil {
		if err := m.checkEarlyClaim(p.Name, ec); err != nil {
			return err
		}
	}
	if uc := p.Capabilities.UpgradeClaim; uc != nil {
		if err := m.checkUpgradeClaim(p.Name, uc); err != nil {
			return err
		}
	}
	return m.checkToolNames(p)
}

// checkToolNames rejects a registration whose mcp_tools names duplicate one
// another, collide with a core tool, or collide with another sidecar's tool.
// Callers hold m.mu.
func (m *Manager) checkToolNames(p *wire.RegisterParams) *wire.Error {
	if len(p.MCPTools) == 0 {
		return nil
	}
	owner := map[string]string{} // tool name -> owning adapter
	for _, n := range m.coreInvoke.CoreToolNames() {
		owner[n] = types.AdapterScopeCore
	}
	for _, r := range m.records {
		for _, t := range r.MCPTools {
			owner[t.Name] = r.Name
		}
	}
	seen := map[string]struct{}{}
	for _, t := range p.MCPTools {
		if _, dup := seen[t.Name]; dup {
			return wire.NewError(wire.CodeToolNameConflict,
				"duplicate mcp_tool name in registration: "+t.Name).
				WithData(&wire.ErrorData{Adapter: p.Name, ConflictAdapter: p.Name})
		}
		seen[t.Name] = struct{}{}
		if other, taken := owner[t.Name]; taken {
			return wire.NewError(wire.CodeToolNameConflict,
				fmt.Sprintf("mcp_tool name %q already provided by adapter %q", t.Name, other)).
				WithData(&wire.ErrorData{Adapter: p.Name, ConflictAdapter: other})
		}
	}
	return nil
}

func (m *Manager) checkEarlyClaim(name string, ec *wire.EarlyClaim) *wire.Error {
	if m.cfg.NativeProxyPort != 0 &&
		ec.PortRange.Low <= m.cfg.NativeProxyPort && m.cfg.NativeProxyPort <= ec.PortRange.High {
		return wire.NewError(wire.CodeCapabilityConflict,
			fmt.Sprintf("early_claim port range %d-%d includes the native proxy port %d",
				ec.PortRange.Low, ec.PortRange.High, m.cfg.NativeProxyPort)).
			WithData(&wire.ErrorData{Adapter: name, ConflictAdapter: "native-proxy"})
	}
	for _, r := range m.records {
		other := r.Capabilities.EarlyClaim
		if other == nil || !rangesOverlap(ec.PortRange, other.PortRange) {
			continue
		}
		if !earlyClaimsDistinct(ec, other) {
			return wire.NewError(wire.CodeCapabilityConflict,
				fmt.Sprintf("early_claim port range %d-%d overlaps adapter %q with no distinguishing matcher",
					ec.PortRange.Low, ec.PortRange.High, r.Name)).
				WithData(&wire.ErrorData{Adapter: name, ConflictAdapter: r.Name})
		}
	}
	return nil
}

func (m *Manager) checkUpgradeClaim(name string, uc *wire.UpgradeClaim) *wire.Error {
	for _, r := range m.records {
		other := r.Capabilities.UpgradeClaim
		if other == nil || !upgradeOverlap(uc, other) {
			continue
		}
		if !dominates(uc, other) && !dominates(other, uc) {
			return wire.NewError(wire.CodeCapabilityConflict,
				fmt.Sprintf("upgrade_claim (%s %s) overlaps adapter %q with incomparable specificity",
					uc.HostPattern, uc.PathPattern, r.Name)).
				WithData(&wire.ErrorData{Adapter: name, ConflictAdapter: r.Name})
		}
	}
	return nil
}

func rangesOverlap(a, b wire.PortRange) bool {
	return a.Low <= b.High && b.Low <= a.High
}

// earlyClaimsDistinct reports whether two overlapping-range early claims are
// distinguished by a non-overlapping matcher.
func earlyClaimsDistinct(a, b *wire.EarlyClaim) bool {
	if terminatesTLS(a) != terminatesTLS(b) {
		return false // mixing TLS-terminate and raw on one range is ambiguous
	}
	if a.Probe || b.Probe {
		return a.Probe && b.Probe // both probe may chain; mixed probe/static is ambiguous
	}
	return prefixesDistinct(a.MagicBytesPrefix, b.MagicBytesPrefix) || sniDistinct(a, b)
}

func terminatesTLS(e *wire.EarlyClaim) bool { return e.TLS != nil && e.TLS.Terminate }

func prefixesDistinct(a, b string) bool {
	pa, _ := base64.StdEncoding.DecodeString(a)
	pb, _ := base64.StdEncoding.DecodeString(b)
	if len(pa) == 0 || len(pb) == 0 {
		return false
	}
	return !bytes.HasPrefix(pa, pb) && !bytes.HasPrefix(pb, pa)
}

func sniDistinct(a, b *wire.EarlyClaim) bool {
	sa, sb := sniOf(a), sniOf(b)
	return sa != "" && sb != "" && sa != sb
}

func sniOf(e *wire.EarlyClaim) string {
	if e.TLS != nil {
		return e.TLS.SNIMatch
	}
	return ""
}

// upgradeOverlap reports whether two upgrade claims can match a common
// (host, path) under the same upgrade signal.
func upgradeOverlap(a, b *wire.UpgradeClaim) bool {
	if a.UpgradeSignal != "" && b.UpgradeSignal != "" && a.UpgradeSignal != b.UpgradeSignal {
		return false
	}
	return patternOverlap(a.HostPattern, b.HostPattern) && patternOverlap(a.PathPattern, b.PathPattern)
}

func patternOverlap(a, b string) bool {
	if a == "" || b == "" || a == "*" || b == "*" {
		return true
	}
	if patternRank(a) == rankLiteral && patternRank(b) == rankLiteral {
		return a == b
	}
	return true // glob/regex involved: assume potential overlap
}

// dominates reports whether a is strictly more specific than b across both the
// host and path patterns (literal > glob > regex > catch-all).
func dominates(a, b *wire.UpgradeClaim) bool {
	ah, ap := patternRank(a.HostPattern), patternRank(a.PathPattern)
	bh, bp := patternRank(b.HostPattern), patternRank(b.PathPattern)
	return ah >= bh && ap >= bp && (ah > bh || ap > bp)
}

const (
	rankCatchAll = 0
	rankRegex    = 1
	rankGlob     = 2
	rankLiteral  = 3
)

func patternRank(p string) int {
	switch {
	case p == "" || p == "*":
		return rankCatchAll
	case strings.ContainsAny(p, `^$()[]{}+|\`):
		return rankRegex
	case strings.ContainsAny(p, "*?"):
		return rankGlob
	default:
		return rankLiteral
	}
}

// patternMatch reports whether value matches the claim pattern, interpreting it by
// rank (catch-all, literal, glob, or regex).
func patternMatch(pattern, value string) bool {
	switch patternRank(pattern) {
	case rankCatchAll:
		return true
	case rankLiteral:
		return pattern == value
	case rankGlob:
		re, err := regexp.Compile("^" + globToRegex(pattern) + "$")
		return err == nil && re.MatchString(value)
	default:
		re, err := regexp.Compile(pattern)
		return err == nil && re.MatchString(value)
	}
}

// globToRegex converts a *(any) / ?(single) glob into a regex fragment.
func globToRegex(glob string) string {
	escaped := regexp.QuoteMeta(glob)
	escaped = strings.ReplaceAll(escaped, `\*`, ".*")
	escaped = strings.ReplaceAll(escaped, `\?`, ".")
	return escaped
}

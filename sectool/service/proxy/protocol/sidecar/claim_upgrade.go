package sidecar

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// upgrade signals a claim may declare; an empty signal defaults to http101.
const (
	signalHTTP101 = "http_101"
	signalConnect = "connect"
)

// pattern ranks, ordered least to most specific for claim precedence.
const (
	rankCatchAll = iota
	rankRegex
	rankLiteral
)

// re2Metachars other than '.' force regex semantics; a pattern of plain text
// and dots is quoted and matched literally instead.
const re2Metachars = `\+*?()|[]{}^$`

// pattern is a compiled claim matcher: an RE2 pattern anchored to the whole value.
type pattern struct {
	src string
	re  *regexp.Regexp // nil matches any value
	// lit is the only value the pattern can match, empty when it matches more than one.
	lit string
}

// compilePattern compiles a claim pattern; an empty pattern matches any value. A
// pattern holding no RE2 metacharacters beyond '.' is quoted first, so a raw
// hostname or path claims exactly itself and ranks literal.
func compilePattern(p string) (pattern, error) {
	if p == "" {
		return pattern{}, nil
	}
	src := p
	// dots match literally; any other metachar opts into full RE2
	if !strings.ContainsAny(strings.ReplaceAll(p, ".", ""), re2Metachars) {
		p = regexp.QuoteMeta(p)
	}
	re, err := regexp.Compile("^(?:" + p + ")$")
	if err != nil {
		return pattern{}, fmt.Errorf("invalid pattern %q: %w", src, err)
	}
	out := pattern{src: src, re: re}
	if lit, complete := re.LiteralPrefix(); complete {
		out.lit = lit
	}
	return out, nil
}

// match reports whether value satisfies the pattern.
func (p pattern) match(value string) bool {
	switch {
	case p.re == nil:
		return true
	case p.lit != "":
		return p.lit == value
	default:
		return p.re.MatchString(value)
	}
}

// overlaps reports whether two patterns can match a common value.
func (p pattern) overlaps(o pattern) bool {
	if p.re == nil || o.re == nil {
		return true
	} else if p.lit != "" && o.lit != "" {
		return p.lit == o.lit
	}
	return true // a regex on either side may still intersect
}

func (p pattern) rank() int {
	switch {
	case p.re == nil:
		return rankCatchAll
	case p.lit != "":
		return rankLiteral
	default:
		return rankRegex
	}
}

// upgradeClaim is the compiled form of a wire upgrade_claim, shared by runtime
// matching and registration conflict analysis so the two cannot diverge.
type upgradeClaim struct {
	signal  string
	methods []string
	host    pattern
	path    pattern
}

// compileUpgradeClaims compiles a registration's upgrade claims, returning an error
// naming the first claim that can never match.
func compileUpgradeClaims(claims []wire.UpgradeClaim) ([]upgradeClaim, error) {
	out := make([]upgradeClaim, len(claims))
	for i := range claims {
		c, err := compileUpgradeClaim(&claims[i])
		if err != nil {
			return nil, fmt.Errorf("upgrade_claim[%d]: %w", i, err)
		}
		out[i] = c
	}
	return out, nil
}

func compileUpgradeClaim(uc *wire.UpgradeClaim) (upgradeClaim, error) {
	out := upgradeClaim{signal: uc.UpgradeSignal, methods: uc.MethodSet}
	if out.signal == "" {
		out.signal = signalHTTP101
	} else if out.signal != signalHTTP101 && out.signal != signalConnect {
		return upgradeClaim{}, fmt.Errorf("unknown upgrade_signal %q", uc.UpgradeSignal)
	}

	var err error
	if out.host, err = compilePattern(uc.HostPattern); err != nil {
		return upgradeClaim{}, fmt.Errorf("host_pattern: %w", err)
	} else if out.path, err = compilePattern(uc.PathPattern); err != nil {
		return upgradeClaim{}, fmt.Errorf("path_pattern: %w", err)
	}
	return out, nil
}

// match reports whether the claim takes the offered upgrade request.
func (u *upgradeClaim) match(c *protocol.UpgradeClaimCtx) bool {
	if u.signal != c.Signal {
		return false
	} else if u.signal == signalHTTP101 && c.Req.GetHeader("Upgrade") == "" {
		return false
	} else if len(u.methods) > 0 && !slices.Contains(u.methods, c.Req.Method) {
		return false
	}
	var host string
	if c.Target != nil {
		host = c.Target.Hostname
	}
	return u.host.match(host) && u.path.match(upgradePath(c))
}

// upgradeClaimConflict reports whether two upgrade claims overlap with neither
// strictly more specific than the other.
func upgradeClaimConflict(a, b *upgradeClaim) bool {
	if a.signal != b.signal || !a.host.overlaps(b.host) || !a.path.overlaps(b.path) {
		return false
	}
	return !dominates(a, b) && !dominates(b, a)
}

// dominates reports whether a is strictly more specific than b across both the host
// and path patterns (literal > regex > catch-all).
func dominates(a, b *upgradeClaim) bool {
	ah, ap := a.host.rank(), a.path.rank()
	bh, bp := b.host.rank(), b.path.rank()
	return ah >= bh && ap >= bp && (ah > bh || ap > bp)
}

// mostSpecificUpgrade returns the claim with the highest combined host+path rank,
// used to rank a multi-claim record against other adapters. The slice is non-empty.
func mostSpecificUpgrade(claims []upgradeClaim) *upgradeClaim {
	best := &claims[0]
	bestRank := best.host.rank() + best.path.rank()
	for i := 1; i < len(claims); i++ {
		if r := claims[i].host.rank() + claims[i].path.rank(); r > bestRank {
			best, bestRank = &claims[i], r
		}
	}
	return best
}

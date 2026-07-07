package sidecar

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

type compiledRule struct {
	rule     wire.Rule
	compiled *regexp.Regexp // nil for literal rules
}

// RuleCache holds the rules sectool pushes and applies the ones scoped to this adapter
// on the hot path. Safe for concurrent use.
type RuleCache struct {
	adapter string

	mu      sync.RWMutex
	version uint64
	rules   []compiledRule
}

// replace swaps the cache for a new snapshot, compiling regex rules. A rule whose
// pattern fails to compile leaves the previous cache intact and returns an error.
func (c *RuleCache) replace(version uint64, rules []wire.Rule) error {
	compiled := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		cr := compiledRule{rule: r}
		if r.IsRegex {
			re, err := regexp.Compile(r.Find)
			if err != nil {
				return fmt.Errorf("rule %s: invalid regex %q: %w", r.RuleID, r.Find, err)
			}
			cr.compiled = re
		}
		compiled = append(compiled, cr)
	}
	c.mu.Lock()
	c.version, c.rules = version, compiled
	c.mu.Unlock()
	return nil
}

// Version returns the snapshot version currently applied.
func (c *RuleCache) Version() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.version
}

// ApplyBody applies body rules of the given type (request_body or response_body) and
// returns the result plus the ids of rules that changed it. Matching is case-sensitive.
func (c *RuleCache) ApplyBody(body []byte, ruleType string) ([]byte, []string) {
	return c.apply(body, false, func(r wire.Rule) bool { return r.Type == ruleType })
}

// ApplyWS applies WebSocket rules for the given direction (ws:to-server or
// ws:to-client), including ws:both, to a frame payload.
func (c *RuleCache) ApplyWS(payload []byte, direction string) ([]byte, []string) {
	return c.apply(payload, false, func(r wire.Rule) bool {
		return r.Type == wire.RuleTypeWSBoth || r.Type == direction
	})
}

// ApplyHeaders applies header rules of the given type (request_header or
// response_header) to the header list, returning the result and the fired rule ids.
// Matching is case-insensitive, mirroring the in-process proxy.
func (c *RuleCache) ApplyHeaders(headers []wire.Header, ruleType string) ([]wire.Header, []string) {
	block, fired := c.apply(renderHeaders(headers), true, func(r wire.Rule) bool { return r.Type == ruleType })
	if len(fired) == 0 {
		return headers, nil
	}
	return parseHeaders(block), fired
}

// apply runs every scoped, matching rule in order and records the ids that changed
// the bytes.
func (c *RuleCache) apply(input []byte, caseInsensitive bool, matches func(wire.Rule) bool) ([]byte, []string) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var fired []string
	for _, cr := range c.rules {
		if !c.scoped(cr.rule) || !matches(cr.rule) {
			continue
		}
		before := input
		input = applyRule(input, cr, caseInsensitive)
		if !bytes.Equal(before, input) {
			fired = append(fired, cr.rule.RuleID)
		}
	}
	return input, fired
}

// scoped reports whether this adapter applies the rule: an empty scope applies
// everywhere, otherwise it must name this adapter.
func (c *RuleCache) scoped(r wire.Rule) bool {
	return r.Adapter == "" || r.Adapter == c.adapter
}

// applyRule applies a single rule to input.
func applyRule(input []byte, cr compiledRule, caseInsensitive bool) []byte {
	r := cr.rule
	if r.Find == "" {
		if caseInsensitive && len(input) > 0 && !bytes.HasSuffix(input, []byte("\r\n")) {
			input = append(input, '\r', '\n')
		}
		return append(input, []byte(r.Replace)...)
	}
	if cr.compiled != nil {
		return cr.compiled.ReplaceAll(input, []byte(r.Replace))
	}
	if caseInsensitive {
		return replaceCaseInsensitive(input, r.Find, r.Replace)
	}
	return bytes.ReplaceAll(input, []byte(r.Find), []byte(r.Replace))
}

// replaceCaseInsensitive replaces all case-insensitive occurrences of find.
func replaceCaseInsensitive(input []byte, find, replace string) []byte {
	src := string(input)
	lowerInput := strings.ToLower(src)
	lowerFind := strings.ToLower(find)
	var out strings.Builder
	for {
		idx := strings.Index(lowerInput, lowerFind)
		if idx < 0 {
			out.WriteString(src)
			return []byte(out.String())
		}
		out.WriteString(src[:idx])
		out.WriteString(replace)
		src = src[idx+len(lowerFind):]
		lowerInput = lowerInput[idx+len(lowerFind):]
	}
}

func renderHeaders(headers []wire.Header) []byte {
	var b bytes.Buffer
	for _, h := range headers {
		b.WriteString(h.Name)
		b.WriteString(": ")
		b.WriteString(h.Value)
		b.WriteString("\r\n")
	}
	return b.Bytes()
}

func parseHeaders(block []byte) []wire.Header {
	trimmed := strings.TrimRight(string(block), "\r\n")
	if trimmed == "" {
		return nil
	}
	var out []wire.Header
	for _, line := range strings.Split(trimmed, "\r\n") {
		name, value, _ := strings.Cut(line, ":")
		out = append(out, wire.Header{Name: name, Value: strings.TrimPrefix(value, " ")})
	}
	return out
}

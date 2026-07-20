package sidecar

import (
	"bytes"
	"fmt"
	"regexp"
	"sync"

	"github.com/go-appsec/toolbox/pkg/mutate"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

type compiledRule struct {
	rule     wire.Rule
	compiled *regexp.Regexp // nil for literal rules
}

// RuleCache holds the rules sectool pushes and applies the ones scoped to this adapter on the hot path. Safe for concurrent use.
type RuleCache struct {
	adapter string

	mu    sync.RWMutex
	rules []compiledRule
}

// replace swaps the cache for a new snapshot, compiling regex rules. A rule whose
// pattern fails to compile leaves the previous cache intact and returns an error.
func (c *RuleCache) replace(rules []wire.Rule) error {
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
	c.rules = compiled
	c.mu.Unlock()
	return nil
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
	rendered := mutate.RenderHeaders(headers, func(h wire.Header) string { return h.Name }, func(h wire.Header) string { return h.Value })
	block, fired := c.apply(rendered, true, func(r wire.Rule) bool { return r.Type == ruleType })
	if len(fired) == 0 {
		return headers, nil
	}
	return mutate.ParseHeaders(block, func(name, value string, _ []byte) wire.Header {
		return wire.Header{Name: name, Value: value}
	}), fired
}

// apply runs every scoped, matching rule in order and records the ids that changed the bytes.
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
		return mutate.ReplaceCaseInsensitive(input, r.Find, r.Replace)
	}
	return bytes.ReplaceAll(input, []byte(r.Find), []byte(r.Replace))
}

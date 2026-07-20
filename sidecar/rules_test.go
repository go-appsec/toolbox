package sidecar

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

func TestRuleCacheApplyBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rules     []wire.Rule
		input     string
		ruleType  string
		want      string
		wantFired []string
	}{
		{
			name:      "literal_replace",
			rules:     []wire.Rule{{RuleID: "r1", Type: wire.RuleTypeRequestBody, Find: "foo", Replace: "bar"}},
			input:     "a foo b foo",
			ruleType:  wire.RuleTypeRequestBody,
			want:      "a bar b bar",
			wantFired: []string{"r1"},
		},
		{
			name:      "regex_replace",
			rules:     []wire.Rule{{RuleID: "r1", Type: wire.RuleTypeResponseBody, IsRegex: true, Find: `\d+`, Replace: "N"}},
			input:     "id=42 n=7",
			ruleType:  wire.RuleTypeResponseBody,
			want:      "id=N n=N",
			wantFired: []string{"r1"},
		},
		{
			name:      "empty_find_appends",
			rules:     []wire.Rule{{RuleID: "r1", Type: wire.RuleTypeRequestBody, Replace: "X"}},
			input:     "body",
			ruleType:  wire.RuleTypeRequestBody,
			want:      "bodyX",
			wantFired: []string{"r1"},
		},
		{
			name:     "type_mismatch_skipped",
			rules:    []wire.Rule{{RuleID: "r1", Type: wire.RuleTypeResponseBody, Find: "foo", Replace: "bar"}},
			input:    "foo",
			ruleType: wire.RuleTypeRequestBody,
			want:     "foo",
		},
		{
			name: "scope_filtering",
			rules: []wire.Rule{
				{RuleID: "empty", Type: wire.RuleTypeRequestBody, Find: "a", Replace: "1"},
				{RuleID: "own", Type: wire.RuleTypeRequestBody, Adapter: "alpha", Find: "b", Replace: "2"},
				{RuleID: "other", Type: wire.RuleTypeRequestBody, Adapter: "beta", Find: "c", Replace: "3"},
				{RuleID: "builtin", Type: wire.RuleTypeRequestBody, Adapter: "sectool", Find: "d", Replace: "4"},
			},
			input:     "abcd",
			ruleType:  wire.RuleTypeRequestBody,
			want:      "12cd",
			wantFired: []string{"empty", "own"},
		},
		{
			name: "ordered_chain",
			rules: []wire.Rule{
				{RuleID: "r1", Type: wire.RuleTypeRequestBody, Find: "a", Replace: "b"},
				{RuleID: "r2", Type: wire.RuleTypeRequestBody, Find: "b", Replace: "c"},
			},
			input:     "a",
			ruleType:  wire.RuleTypeRequestBody,
			want:      "c",
			wantFired: []string{"r1", "r2"},
		},
		{
			name:     "no_match_no_fire",
			rules:    []wire.Rule{{RuleID: "r1", Type: wire.RuleTypeRequestBody, Find: "zzz", Replace: "x"}},
			input:    "abc",
			ruleType: wire.RuleTypeRequestBody,
			want:     "abc",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &RuleCache{adapter: "alpha"}
			require.NoError(t, c.replace(tc.rules))
			out, fired := c.ApplyBody([]byte(tc.input), tc.ruleType)
			assert.Equal(t, tc.want, string(out))
			assert.Equal(t, tc.wantFired, fired)
		})
	}
}

func TestRuleCacheApplyHeaders(t *testing.T) {
	t.Parallel()

	c := &RuleCache{adapter: "alpha"}
	require.NoError(t, c.replace([]wire.Rule{
		{RuleID: "rewrite", Type: wire.RuleTypeRequestHeader, Find: "secret: a", Replace: "Secret: b"},
		{RuleID: "append", Type: wire.RuleTypeRequestHeader, Replace: "X-Added: 1"},
	}))

	headers := []wire.Header{{Name: "Host", Value: "x"}, {Name: "Secret", Value: "a"}}
	out, fired := c.ApplyHeaders(headers, wire.RuleTypeRequestHeader)

	assert.Equal(t, []string{"rewrite", "append"}, fired)
	assert.Equal(t, []wire.Header{
		{Name: "Host", Value: "x"},
		{Name: "Secret", Value: "b"},
		{Name: "X-Added", Value: "1"},
	}, out)
}

func TestRuleCacheApplyHeadersNonASCII(t *testing.T) {
	t.Parallel()

	c := &RuleCache{adapter: "alpha"}
	require.NoError(t, c.replace([]wire.Rule{
		{RuleID: "fold", Type: wire.RuleTypeRequestHeader, Find: "SECRET", Replace: "REDACTED"},
	}))

	out, fired := c.ApplyHeaders([]wire.Header{{Name: "X-Data", Value: "İ secret Ⱥ"}}, wire.RuleTypeRequestHeader)

	assert.Equal(t, []string{"fold"}, fired)
	assert.Equal(t, []wire.Header{{Name: "X-Data", Value: "İ REDACTED Ⱥ"}}, out)
}

func TestRuleCacheReplaceRejectsBadRegex(t *testing.T) {
	t.Parallel()

	c := &RuleCache{adapter: "alpha"}
	require.NoError(t, c.replace([]wire.Rule{{RuleID: "ok", Type: wire.RuleTypeRequestBody, Find: "a", Replace: "b"}}))

	err := c.replace([]wire.Rule{{RuleID: "bad", Type: wire.RuleTypeRequestBody, IsRegex: true, Find: "("}})
	require.Error(t, err)
	// prior snapshot is retained on failure
	out, _ := c.ApplyBody([]byte("a"), wire.RuleTypeRequestBody)
	assert.Equal(t, "b", string(out))
}

func TestConnSyncRules(t *testing.T) {
	t.Parallel()

	addr, peerCh := fakeServer(t, registerOK)
	conn, err := Dial(t.Context(), addr, Registration{Name: "alpha"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	srv := <-peerCh

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	t.Cleanup(cancel)
	var res wire.SyncRulesResult
	require.Nil(t, srv.Call(ctx, wire.MethodSyncRules, wire.SyncRulesParams{
		Rules: []wire.Rule{{RuleID: "r1", Type: wire.RuleTypeRequestBody, Find: "foo", Replace: "bar"}},
	}, &res))

	assert.True(t, res.Ack)

	out, fired := conn.Rules().ApplyBody([]byte("foo"), wire.RuleTypeRequestBody)
	assert.Equal(t, "bar", string(out))
	assert.Equal(t, []string{"r1"}, fired)
}

package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jentfoo/llm-security-toolbox/sectool/service/mcp"
)

func TestFormatSectoolComment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		id    string
		label string
		want  string
	}{
		{"id_only", "abc123", "", "sectool:abc123"},
		{"id_and_label", "abc123", "my-label", "sectool:abc123:my-label"},
		{"label_with_colons", "abc123", "my:complex", "sectool:abc123:my:complex"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, formatSectoolComment(tt.id, tt.label))
		})
	}
}

func TestParseSectoolComment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		comment string
		wantID  string
		wantLbl string
		wantOK  bool
	}{
		{"id_only", "sectool:abc123", "abc123", "", true},
		{"id_and_label", "sectool:abc123:my-label", "abc123", "my-label", true},
		{"label_with_colons", "sectool:abc123:my:complex:label", "abc123", "my:complex:label", true},
		{"not_sectool", "other:abc123", "", "", false},
		{"empty_comment", "", "", "", false},
		{"sectool_no_id", "sectool:", "", "", false},
		{"just_prefix", "sectool", "", "", false},
		{"burp_rule", "Emulate IE", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, label, ok := parseSectoolComment(tt.comment)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantID, id)
			assert.Equal(t, tt.wantLbl, label)
		})
	}
}

func TestParseSectoolCommentRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		id    string
		label string
	}{
		{"abc123", ""},
		{"XyZ789", "my-rule"},
		{"a1b2c3", "test:with:colons"},
	}

	for _, c := range cases {
		comment := formatSectoolComment(c.id, c.label)
		gotID, gotLabel, ok := parseSectoolComment(comment)
		assert.True(t, ok)
		assert.Equal(t, c.id, gotID)
		assert.Equal(t, c.label, gotLabel)
	}
}

func TestBurpBackendRules(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		websocket  bool
		ruleType1  string // primary type for add tests
		ruleType2  string // secondary type for regex tests
		updateType string // type for update tests
	}{
		{"http_rules", false, mcp.RuleTypeRequestHeader, mcp.RuleTypeResponseHeader, mcp.RuleTypeRequestBody},
		{"ws_rules", true, "ws:to-server", "ws:to-client", "ws:both"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockServer := NewTestMCPServer(t)
			client := mcp.New(mockServer.URL())
			require.NoError(t, client.Connect(t.Context()))
			t.Cleanup(func() { _ = client.Close() })

			backend := &BurpBackend{client: client}

			var createdRuleIDs []string // Track rules for cleanup verification

			t.Run("list_empty", func(t *testing.T) {
				rules, err := backend.ListRules(t.Context(), tc.websocket)
				require.NoError(t, err)
				assert.Empty(t, rules)
			})

			t.Run("add_rule", func(t *testing.T) {
				rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
					Label:   "test-add",
					Type:    tc.ruleType1,
					IsRegex: false,
					Match:   "",
					Replace: "X-Test: value",
				})
				require.NoError(t, err)
				createdRuleIDs = append(createdRuleIDs, rule.RuleID)

				assert.NotEmpty(t, rule.RuleID)
				assert.Equal(t, "test-add", rule.Label)
				assert.Equal(t, tc.ruleType1, rule.Type)
				assert.False(t, rule.IsRegex)
				assert.Equal(t, "X-Test: value", rule.Replace)

				// Verify in list
				rules, err := backend.ListRules(t.Context(), tc.websocket)
				require.NoError(t, err)
				require.Len(t, rules, 1)
				assert.Equal(t, rule.RuleID, rules[0].RuleID)
			})

			t.Run("add_regex_rule", func(t *testing.T) {
				rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
					Label:   "test-regex",
					Type:    tc.ruleType2,
					IsRegex: true,
					Match:   "^X-Remove.*$",
					Replace: "",
				})
				require.NoError(t, err)
				createdRuleIDs = append(createdRuleIDs, rule.RuleID)

				assert.True(t, rule.IsRegex)
				assert.Equal(t, "^X-Remove.*$", rule.Match)
			})

			t.Run("duplicate_label_rejected", func(t *testing.T) {
				_, err := backend.AddRule(t.Context(), ProxyRuleInput{
					Label: "test-add",
					Type:  tc.ruleType1,
				})
				require.Error(t, err)
				assert.Contains(t, err.Error(), "already exists")
			})

			t.Run("update_to_duplicate_label", func(t *testing.T) {
				// Try to update test-regex rule to have test-add's label
				_, err := backend.UpdateRule(t.Context(), createdRuleIDs[1], ProxyRuleInput{
					Label: "test-add",
					Type:  tc.ruleType1,
				})
				require.Error(t, err)
				assert.Contains(t, err.Error(), "already exists")
			})

			t.Run("update_by_id", func(t *testing.T) {
				updated, err := backend.UpdateRule(t.Context(), createdRuleIDs[0], ProxyRuleInput{
					Label:   "test-updated",
					Type:    tc.updateType,
					IsRegex: true,
					Match:   "old",
					Replace: "new",
				})
				require.NoError(t, err)

				assert.Equal(t, createdRuleIDs[0], updated.RuleID)
				assert.Equal(t, "test-updated", updated.Label)
				assert.Equal(t, tc.updateType, updated.Type)
				assert.True(t, updated.IsRegex)
			})

			t.Run("update_by_label", func(t *testing.T) {
				updated, err := backend.UpdateRule(t.Context(), "test-regex", ProxyRuleInput{
					Label:   "test-regex-updated",
					Type:    tc.ruleType2,
					IsRegex: false,
					Match:   "find",
					Replace: "replace",
				})
				require.NoError(t, err)
				assert.Equal(t, "test-regex-updated", updated.Label)
			})

			t.Run("update_preserves_label", func(t *testing.T) {
				// Add a rule with a label
				rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
					Label:   "preserved-label",
					Type:    tc.ruleType1,
					Replace: "X-Original: value",
				})
				require.NoError(t, err)

				// Update the rule without providing a label (empty string)
				updated, err := backend.UpdateRule(t.Context(), rule.RuleID, ProxyRuleInput{
					Type:    tc.ruleType1,
					Replace: "X-Updated: value",
				})
				require.NoError(t, err)

				// Label should be preserved
				assert.Equal(t, "preserved-label", updated.Label)
				assert.Equal(t, "X-Updated: value", updated.Replace)

				// Verify we can still find by label
				rules, err := backend.ListRules(t.Context(), tc.websocket)
				require.NoError(t, err)
				var found bool
				for _, r := range rules {
					if r.RuleID == rule.RuleID {
						assert.Equal(t, "preserved-label", r.Label)
						found = true
						break
					}
				}
				assert.True(t, found, "rule should be found in list")

				// Verify delete by label still works after update
				err = backend.DeleteRule(t.Context(), "preserved-label")
				require.NoError(t, err)
			})

			t.Run("update_not_found", func(t *testing.T) {
				_, err := backend.UpdateRule(t.Context(), "nonexistent", ProxyRuleInput{
					Type:    tc.ruleType1,
					Replace: "X-Test: value",
				})
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrNotFound)
			})

			t.Run("delete_by_id", func(t *testing.T) {
				rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
					Label: "to-delete-by-id",
					Type:  tc.ruleType1,
				})
				require.NoError(t, err)

				err = backend.DeleteRule(t.Context(), rule.RuleID)
				require.NoError(t, err)

				rules, err := backend.ListRules(t.Context(), tc.websocket)
				require.NoError(t, err)
				for _, r := range rules {
					assert.NotEqual(t, rule.RuleID, r.RuleID)
				}
			})

			t.Run("delete_by_label", func(t *testing.T) {
				rule, err := backend.AddRule(t.Context(), ProxyRuleInput{
					Label: "to-delete-by-label",
					Type:  tc.ruleType1,
				})
				require.NoError(t, err)

				err = backend.DeleteRule(t.Context(), "to-delete-by-label")
				require.NoError(t, err)

				rules, err := backend.ListRules(t.Context(), tc.websocket)
				require.NoError(t, err)
				for _, r := range rules {
					assert.NotEqual(t, rule.RuleID, r.RuleID)
				}
			})

			t.Run("delete_not_found", func(t *testing.T) {
				err := backend.DeleteRule(t.Context(), "nonexistent")
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrNotFound)
			})
		})
	}
}

func TestWsToBurpType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"ws:to-server", "client_to_server"},
		{"ws:to-client", "server_to_client"},
		{"ws:both", "both_directions"},
		{"unknown", "unknown"},               // pass through unknown types
		{"request_header", "request_header"}, // HTTP types pass through
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, wsToBurpType(tt.input))
		})
	}
}

func TestBurpToWSType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		{"client_to_server", "ws:to-server"},
		{"server_to_client", "ws:to-client"},
		{"both_directions", "ws:both"},
		{"unknown", "unknown"},               // pass through unknown types
		{"request_header", "request_header"}, // HTTP types pass through
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, burpToWSType(tt.input))
		})
	}
}

func TestBurpBackendRuleIsolation(t *testing.T) {
	t.Parallel()

	mockServer := NewTestMCPServer(t)
	client := mcp.New(mockServer.URL())
	require.NoError(t, client.Connect(t.Context()))
	t.Cleanup(func() { _ = client.Close() })

	backend := &BurpBackend{client: client}

	// Add HTTP rule
	httpRule, err := backend.AddRule(t.Context(), ProxyRuleInput{
		Label: "http-only",
		Type:  mcp.RuleTypeRequestHeader,
	})
	require.NoError(t, err)

	// Add WS rule with ws: prefixed type
	wsRule, err := backend.AddRule(t.Context(), ProxyRuleInput{
		Label: "ws-only",
		Type:  "ws:both",
	})
	require.NoError(t, err)

	// HTTP rule should only appear in HTTP list
	httpRules, err := backend.ListRules(t.Context(), false)
	require.NoError(t, err)
	require.Len(t, httpRules, 1)
	assert.Equal(t, httpRule.RuleID, httpRules[0].RuleID)
	assert.Equal(t, mcp.RuleTypeRequestHeader, httpRules[0].Type)

	// WS rule should only appear in WS list with ws: prefixed type
	wsRules, err := backend.ListRules(t.Context(), true)
	require.NoError(t, err)
	require.Len(t, wsRules, 1)
	assert.Equal(t, wsRule.RuleID, wsRules[0].RuleID)
	assert.Equal(t, "ws:both", wsRules[0].Type)
}

func TestBurpBackendUpdateTypeMismatch(t *testing.T) {
	t.Parallel()

	mockServer := NewTestMCPServer(t)
	client := mcp.New(mockServer.URL())
	require.NoError(t, client.Connect(t.Context()))
	t.Cleanup(func() { _ = client.Close() })

	backend := &BurpBackend{client: client}

	// Add HTTP rule
	httpRule, err := backend.AddRule(t.Context(), ProxyRuleInput{
		Label: "http-rule",
		Type:  mcp.RuleTypeRequestHeader,
	})
	require.NoError(t, err)

	// Add WS rule
	wsRule, err := backend.AddRule(t.Context(), ProxyRuleInput{
		Label: "ws-rule",
		Type:  "ws:both",
	})
	require.NoError(t, err)

	t.Run("http_with_ws_type", func(t *testing.T) {
		_, err := backend.UpdateRule(t.Context(), httpRule.RuleID, ProxyRuleInput{
			Type:    "ws:to-server",
			Replace: "test",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot update HTTP rule with WebSocket type")
	})

	t.Run("ws_with_http_type", func(t *testing.T) {
		_, err := backend.UpdateRule(t.Context(), wsRule.RuleID, ProxyRuleInput{
			Type:    mcp.RuleTypeRequestHeader,
			Replace: "test",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot update WebSocket rule with HTTP type")
	})
}

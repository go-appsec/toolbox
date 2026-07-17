package service

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/mcp"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sidecar/wire"
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
		name      string
		websocket bool
		ruleType1 string // primary type for add tests
		ruleType2 string // secondary type for regex tests
	}{
		{"http_rules", false, mcp.RuleTypeRequestHeader, mcp.RuleTypeResponseHeader},
		{"ws_rules", true, "ws:to-server", "ws:to-client"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockServer := NewTestMCPServer(t)
			client := mcp.New(mockServer.URL(), mcp.WithHealthCheckInterval(0))
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
				rule, err := backend.AddRule(t.Context(), protocol.RuleEntry{
					Label:   "test-add",
					Type:    tc.ruleType1,
					IsRegex: false,
					Find:    "",
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
				rule, err := backend.AddRule(t.Context(), protocol.RuleEntry{
					Label:   "test-regex",
					Type:    tc.ruleType2,
					IsRegex: true,
					Find:    "^X-Remove.*$",
					Replace: "",
				})
				require.NoError(t, err)
				createdRuleIDs = append(createdRuleIDs, rule.RuleID)

				assert.True(t, rule.IsRegex)
				assert.Equal(t, "^X-Remove.*$", rule.Find)
			})

			t.Run("duplicate_label_rejected", func(t *testing.T) {
				_, err := backend.AddRule(t.Context(), protocol.RuleEntry{
					Label: "test-add",
					Type:  tc.ruleType1,
				})
				require.Error(t, err)
				assert.Contains(t, err.Error(), "already exists")
			})

			t.Run("delete_by_id", func(t *testing.T) {
				rule, err := backend.AddRule(t.Context(), protocol.RuleEntry{
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
				rule, err := backend.AddRule(t.Context(), protocol.RuleEntry{
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
	client := mcp.New(mockServer.URL(), mcp.WithHealthCheckInterval(0))
	require.NoError(t, client.Connect(t.Context()))
	t.Cleanup(func() { _ = client.Close() })

	backend := &BurpBackend{client: client}

	// Add HTTP rule
	httpRule, err := backend.AddRule(t.Context(), protocol.RuleEntry{
		Label: "http-only",
		Type:  mcp.RuleTypeRequestHeader,
	})
	require.NoError(t, err)

	// Add WS rule with ws: prefixed type
	wsRule, err := backend.AddRule(t.Context(), protocol.RuleEntry{
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

func TestBurpBackendConfigEditingDisabled(t *testing.T) {
	t.Parallel()

	t.Run("add_rule_fails", func(t *testing.T) {
		backend, mockServer := newTestBurpBackend(t)
		mockServer.SetConfigEditingDisabled(true)

		_, err := backend.AddRule(t.Context(), protocol.RuleEntry{
			Label: "should-fail",
			Type:  mcp.RuleTypeRequestHeader,
			Find:  "old",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConfigEditDisabled)
	})

	t.Run("delete_rule_fails", func(t *testing.T) {
		backend, mockServer := newTestBurpBackend(t)

		// Add a rule while editing is enabled
		rule, err := backend.AddRule(t.Context(), protocol.RuleEntry{
			Label: "to-delete",
			Type:  mcp.RuleTypeRequestHeader,
		})
		require.NoError(t, err)

		// Disable editing, then try to delete
		mockServer.SetConfigEditingDisabled(true)
		err = backend.DeleteRule(t.Context(), rule.RuleID)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrConfigEditDisabled)
	})

	t.Run("list_still_works", func(t *testing.T) {
		backend, mockServer := newTestBurpBackend(t)
		mockServer.SetConfigEditingDisabled(true)

		// List is a read operation and should succeed regardless
		rules, err := backend.ListRules(t.Context(), false)
		require.NoError(t, err)
		assert.Empty(t, rules)
	})
}

func newTestBurpBackend(t *testing.T) (*BurpBackend, *TestMCPServer) {
	t.Helper()
	mockServer := NewTestMCPServer(t)
	client := mcp.New(mockServer.URL(), mcp.WithHealthCheckInterval(0))
	require.NoError(t, client.Connect(t.Context()))
	backend, err := NewBurpBackend(client, store.MemProvider)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close(context.Background()) })
	return backend, mockServer
}

func TestBurpBackendSendRequest(t *testing.T) {
	t.Parallel()

	t.Run("creates_repeater_tab", func(t *testing.T) {
		backend, mockServer := newTestBurpBackend(t)

		_, err := backend.SendRequest(t.Context(), "sectool-abc123", SendRequestInput{
			RawRequest: []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			Target:     types.Target{Hostname: "example.com", Port: 443, UsesHTTPS: true},
		})
		require.NoError(t, err)

		log := mockServer.ToolCallLog()
		require.Len(t, log, 2)
		assert.Equal(t, "create_repeater_tab", log[0])
		assert.Equal(t, "send_http1_request", log[1])
	})

	t.Run("sets_modified_request", func(t *testing.T) {
		backend, _ := newTestBurpBackend(t)

		_, err := backend.AddRule(t.Context(), protocol.RuleEntry{
			Type:    wire.RuleTypeRequestHeader,
			Replace: "X-Injected: from-rule\r\n",
		})
		require.NoError(t, err)

		result, err := backend.SendRequest(t.Context(), "sectool-rule1", SendRequestInput{
			RawRequest: []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			Target:     types.Target{Hostname: "example.com", Port: 443, UsesHTTPS: true},
		})
		require.NoError(t, err)
		require.NotNil(t, result.ModifiedRequest)
		assert.Contains(t, string(result.ModifiedRequest), "X-Injected: from-rule")
	})

	t.Run("no_match_nil", func(t *testing.T) {
		backend, _ := newTestBurpBackend(t)

		_, err := backend.AddRule(t.Context(), protocol.RuleEntry{
			Type:    wire.RuleTypeRequestHeader,
			Find:    "X-Nonexistent: value",
			Replace: "X-Replaced: value",
		})
		require.NoError(t, err)

		result, err := backend.SendRequest(t.Context(), "sectool-rule2", SendRequestInput{
			RawRequest: []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			Target:     types.Target{Hostname: "example.com", Port: 443, UsesHTTPS: true},
		})
		require.NoError(t, err)
		assert.Nil(t, result.ModifiedRequest)
	})
}

func TestBurpBackendSendDomainShortening(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		hostname      string
		wantInTabName string
	}{
		{"two_part", "example.com", "example.com"},
		{"subdomain_stripped", "api.example.com", "example.com"},
		{"multipart_tld", "app.example.co.uk", "example.co.uk"},
		{"ip_passthrough", "192.168.1.1", "192.168.1.1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			backend, mockServer := newTestBurpBackend(t)

			_, err := backend.SendRequest(t.Context(), "sectool-dom1", SendRequestInput{
				RawRequest: []byte("GET /api HTTP/1.1\r\nHost: " + tc.hostname + "\r\n\r\n"),
				Target:     types.Target{Hostname: tc.hostname, Port: 443, UsesHTTPS: true},
			})
			require.NoError(t, err)
			assert.Contains(t, mockServer.LastTabName(), tc.wantInTabName)
		})
	}
}

func TestBurpFlowIndexRegisterOrLookup(t *testing.T) {
	t.Parallel()

	t.Run("net_new_mints_flow_id", func(t *testing.T) {
		storage := store.NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		idx := newBurpFlowIndex(storage)

		fid, ts := idx.RegisterOrLookup(0, "GET /a HTTP/1.1\r\n\r\n")
		assert.NotEmpty(t, fid)
		assert.False(t, ts.IsZero())
		assert.Equal(t, 1, idx.Count())
	})

	t.Run("same_offset_same_request_returns_cached", func(t *testing.T) {
		storage := store.NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		idx := newBurpFlowIndex(storage)

		fid1, ts1 := idx.RegisterOrLookup(0, "GET /a HTTP/1.1\r\n\r\n")
		fid2, ts2 := idx.RegisterOrLookup(0, "GET /a HTTP/1.1\r\n\r\n")
		assert.Equal(t, fid1, fid2)
		assert.Equal(t, ts1, ts2)
	})

	t.Run("drift_evicts_and_mints_new", func(t *testing.T) {
		storage := store.NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		idx := newBurpFlowIndex(storage)

		oldFID, _ := idx.RegisterOrLookup(0, "GET /old HTTP/1.1\r\n\r\n")
		newFID, _ := idx.RegisterOrLookup(0, "GET /new HTTP/1.1\r\n\r\n")
		assert.NotEqual(t, oldFID, newFID)

		_, ok := idx.OffsetFor(oldFID)
		assert.False(t, ok)
	})

	t.Run("fingerprint_relocation_preserves_flow_id", func(t *testing.T) {
		storage := store.NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		idx := newBurpFlowIndex(storage)

		// Initial state: offsets 0,1,2 with distinct content
		_, _ = idx.RegisterOrLookup(0, "GET /a HTTP/1.1\r\n\r\n")
		f1, _ := idx.RegisterOrLookup(1, "GET /b HTTP/1.1\r\n\r\n")
		f2, _ := idx.RegisterOrLookup(2, "GET /c HTTP/1.1\r\n\r\n")

		// Simulate Burp UI delete of original offset 1: /c shifts down to slot 1
		gotF1, _ := idx.RegisterOrLookup(1, "GET /c HTTP/1.1\r\n\r\n")
		assert.Equal(t, f2, gotF1)

		// f1's content is gone, so its flow_id is no longer in the cache
		_, ok := idx.OffsetFor(f1)
		assert.False(t, ok)
	})

	t.Run("relocation_clears_old_offset_mapping", func(t *testing.T) {
		storage := store.NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		idx := newBurpFlowIndex(storage)

		_, _ = idx.RegisterOrLookup(0, "GET /a HTTP/1.1\r\n\r\n")
		_, _ = idx.RegisterOrLookup(1, "GET /b HTTP/1.1\r\n\r\n")
		f2, _ := idx.RegisterOrLookup(2, "GET /c HTTP/1.1\r\n\r\n")

		// Burp UI delete shifts /c down from offset 2 to offset 1
		gotF2, _ := idx.RegisterOrLookup(1, "GET /c HTTP/1.1\r\n\r\n")
		require.Equal(t, f2, gotF2)
		off, ok := idx.OffsetFor(f2)
		require.True(t, ok)
		assert.Equal(t, 1, off)
		assert.Equal(t, 2, idx.Count()) // no orphan left at old offset 2

		// Fresh content lands on the vacated offset 2; must not evict the live /c fingerprint
		f3, _ := idx.RegisterOrLookup(2, "GET /d HTTP/1.1\r\n\r\n")
		assert.NotEqual(t, f2, f3)

		// Re-poll /c at offset 1: identity must be stable, not a freshly minted id
		reF2, _ := idx.RegisterOrLookup(1, "GET /c HTTP/1.1\r\n\r\n")
		assert.Equal(t, f2, reF2)
	})
}

func TestBurpFlowIndexSweepTail(t *testing.T) {
	t.Parallel()

	t.Run("partial_tail", func(t *testing.T) {
		storage := store.NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		idx := newBurpFlowIndex(storage)

		_, _ = idx.RegisterOrLookup(0, "GET /a HTTP/1.1\r\n\r\n")
		_, _ = idx.RegisterOrLookup(1, "GET /b HTTP/1.1\r\n\r\n")
		f2, _ := idx.RegisterOrLookup(2, "GET /c HTTP/1.1\r\n\r\n")

		idx.SweepTail(2) // live tail ends at offset 2 (only 0,1 remain)
		assert.Equal(t, 2, idx.Count())
		_, ok := idx.OffsetFor(f2)
		assert.False(t, ok)
	})

	t.Run("full_clear", func(t *testing.T) {
		storage := store.NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		idx := newBurpFlowIndex(storage)

		_, _ = idx.RegisterOrLookup(0, "GET /a HTTP/1.1\r\n\r\n")
		_, _ = idx.RegisterOrLookup(1, "GET /b HTTP/1.1\r\n\r\n")

		idx.SweepTail(0)
		assert.Equal(t, 0, idx.Count())
	})
}

func TestBurpClientClosePrompt(t *testing.T) {
	t.Parallel()

	mockServer := NewTestMCPServer(t)
	client := mcp.New(mockServer.URL(), mcp.WithHealthCheckInterval(200*time.Millisecond))
	require.NoError(t, client.Connect(t.Context()))

	done := make(chan error, 1)
	go func() { done <- client.Close() }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Close() did not complete within healthCheckTimeout")
	}
}

func TestBurpBackendGetProxyHistory(t *testing.T) {
	t.Parallel()

	t.Run("full_entries", func(t *testing.T) {
		backend, mockServer := newTestBurpBackend(t)
		mockServer.AddProxyEntry(
			"GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nfirst",
			"",
		)
		mockServer.AddProxyEntry(
			"POST /two HTTP/1.1\r\nHost: example.com\r\n\r\nbody",
			"HTTP/1.1 201 Created\r\n\r\nsecond",
			"note2",
		)

		entries, err := backend.GetProxyHistory(t.Context(), 10, "")
		require.NoError(t, err)
		require.Len(t, entries, 2)
		assert.Contains(t, entries[0].Request, "GET /one")
		assert.Contains(t, entries[0].Response, "200 OK")
		assert.NotEmpty(t, entries[0].FlowID)
		assert.Contains(t, entries[1].Request, "POST /two")
		assert.Equal(t, "note2", entries[1].Notes)
	})

	t.Run("cursor_and_count", func(t *testing.T) {
		backend, mockServer := newTestBurpBackend(t)
		mockServer.AddProxyEntry(
			"GET /a HTTP/1.1\r\nHost: a.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\na",
			"",
		)
		mockServer.AddProxyEntry(
			"GET /b HTTP/1.1\r\nHost: b.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\n\r\nb",
			"",
		)

		first, err := backend.GetProxyHistory(t.Context(), 1, "")
		require.NoError(t, err)
		require.Len(t, first, 1)
		assert.Contains(t, first[0].Request, "GET /a")

		entries, err := backend.GetProxyHistory(t.Context(), 1, first[0].FlowID)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Contains(t, entries[0].Request, "GET /b")
	})

	t.Run("empty_history", func(t *testing.T) {
		backend, _ := newTestBurpBackend(t)

		entries, err := backend.GetProxyHistory(t.Context(), 10, "")
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("meta", func(t *testing.T) {
		backend, mockServer := newTestBurpBackend(t)
		mockServer.AddProxyEntry(
			"GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>hi</html>",
			"",
		)
		mockServer.AddProxyEntry(
			"POST /api HTTP/1.1\r\nHost: api.example.com\r\n\r\n{\"x\":1}",
			"HTTP/1.1 201 Created\r\n\r\nok",
			"",
		)

		metas, err := backend.GetProxyHistoryMeta(t.Context(), 10, "")
		require.NoError(t, err)
		require.Len(t, metas, 2)

		assert.Equal(t, "GET", metas[0].Method)
		assert.Equal(t, "example.com", metas[0].Host)
		assert.Equal(t, "/page", metas[0].Path)
		assert.Equal(t, 200, metas[0].Status)
		assert.Equal(t, len("<html>hi</html>"), metas[0].RespLen)

		assert.Equal(t, "POST", metas[1].Method)
		assert.Equal(t, "api.example.com", metas[1].Host)
		assert.Equal(t, "/api", metas[1].Path)
		assert.Equal(t, 201, metas[1].Status)
	})

	t.Run("relocates_on_mid_delete", func(t *testing.T) {
		backend, mockServer := newTestBurpBackend(t)

		mockServer.AddProxyEntry("GET /a HTTP/1.1\r\nHost: a.com\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nA", "")
		mockServer.AddProxyEntry("GET /b HTTP/1.1\r\nHost: b.com\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nB", "")
		mockServer.AddProxyEntry("GET /c HTTP/1.1\r\nHost: c.com\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nC", "")

		entries, err := backend.GetProxyHistory(t.Context(), 100, "")
		require.NoError(t, err)
		require.Len(t, entries, 3)
		fA, fC := entries[0].FlowID, entries[2].FlowID

		// Burp UI deletes the middle entry. /c shifts into slot 1
		mockServer.RemoveProxyEntry(1)

		entries, err = backend.GetProxyHistory(t.Context(), 100, "")
		require.NoError(t, err)
		require.Len(t, entries, 2)

		// /a and /c retain their original flow_ids; /b's flow_id is gone
		gotIDs := []string{entries[0].FlowID, entries[1].FlowID}
		assert.ElementsMatch(t, []string{fA, fC}, gotIDs)
	})

	t.Run("tail_probe_sweeps_stale", func(t *testing.T) {
		backend, mockServer := newTestBurpBackend(t)

		mockServer.AddProxyEntry("GET /a HTTP/1.1\r\nHost: a.com\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nA", "")
		mockServer.AddProxyEntry("GET /b HTTP/1.1\r\nHost: b.com\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nB", "")
		mockServer.AddProxyEntry("GET /c HTTP/1.1\r\nHost: c.com\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nC", "")

		// Prime cache with all three offsets
		entries, err := backend.GetProxyHistory(t.Context(), 100, "")
		require.NoError(t, err)
		require.Len(t, entries, 3)
		fC := entries[2].FlowID
		assert.Equal(t, 3, backend.flowIndex.Count())

		// Burp UI deletes the tail entry; live history is now [/a, /b]
		mockServer.RemoveProxyEntry(2)

		// Re-fetch with count==live tail length. Without the +1 tail probe, the
		// stale offset 2 would linger in cache; with it, we detect the shrink.
		entries, err = backend.GetProxyHistory(t.Context(), 2, "")
		require.NoError(t, err)
		require.Len(t, entries, 2)
		assert.Equal(t, 2, backend.flowIndex.Count())
		_, ok := backend.flowIndex.OffsetFor(fC)
		assert.False(t, ok)
	})

	t.Run("sweeps_all_on_clear", func(t *testing.T) {
		backend, mockServer := newTestBurpBackend(t)

		mockServer.AddProxyEntry("GET /a HTTP/1.1\r\nHost: a.com\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nA", "")
		mockServer.AddProxyEntry("GET /b HTTP/1.1\r\nHost: b.com\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nB", "")

		entries, err := backend.GetProxyHistory(t.Context(), 100, "")
		require.NoError(t, err)
		require.Len(t, entries, 2)
		cursor := entries[1].FlowID
		assert.Equal(t, 2, backend.flowIndex.Count())

		// Burp UI is fully cleared while the client holds a cursor
		mockServer.ClearProxyHistory()

		entries, err = backend.GetProxyHistory(t.Context(), 100, cursor)
		require.NoError(t, err)
		assert.Empty(t, entries)
		assert.Equal(t, 0, backend.flowIndex.Count())
	})

	t.Run("corrupt_middle_line_keeps_offsets", func(t *testing.T) {
		backend, mockServer := newTestBurpBackend(t)

		mockServer.AddProxyEntries(
			testProxyEntry{Request: "GET /a HTTP/1.1\r\nHost: a.com\r\n\r\n", Response: "HTTP/1.1 200 OK\r\n\r\nA"},
			testProxyEntry{Raw: "{this is not json at all"}, // corrupt entry at true offset 1
			testProxyEntry{Request: "GET /c HTTP/1.1\r\nHost: c.com\r\n\r\n", Response: "HTTP/1.1 200 OK\r\n\r\nC"},
		)

		entries, err := backend.GetProxyHistory(t.Context(), 100, "")
		require.NoError(t, err)
		require.Len(t, entries, 3)
		assert.False(t, entries[0].Placeholder)
		assert.True(t, entries[1].Placeholder)
		assert.False(t, entries[2].Placeholder)
		fC := entries[2].FlowID

		// /c registered at its TRUE offset 2, not shifted down by the dropped line
		off, ok := backend.flowIndex.OffsetFor(fC)
		require.True(t, ok)
		assert.Equal(t, 2, off)
		assert.Equal(t, 2, backend.flowIndex.Count()) // placeholder not registered

		// Re-poll: identities stable, no eviction/churn from the corrupt offset
		entries, err = backend.GetProxyHistory(t.Context(), 100, "")
		require.NoError(t, err)
		require.Len(t, entries, 3)
		assert.Equal(t, fC, entries[2].FlowID)
	})
}

func TestParseBurpResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantErr    bool
		wantStatus string
		wantBody   string
	}{
		{
			"with_annotations",
			`HttpRequestResponse{httpRequest=GET / HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\n\r\nok, messageAnnotations=Annotations{}}`,
			false,
			"HTTP/1.1 ",
			"ok",
		},
		{
			"without_annotations",
			`HttpRequestResponse{httpRequest=GET / HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\n\r\nbody}`,
			false,
			"HTTP/1.1 ",
			"body",
		},
		{
			"missing_http_response",
			`HttpRequestResponse{httpRequest=GET / HTTP/1.1}`,
			true,
			"",
			"",
		},
		{
			"no_http_prefix",
			`HttpRequestResponse{httpResponse=garbage, messageAnnotations=Annotations{}}`,
			true,
			"",
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers, body, err := parseBurpResponse(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Contains(t, string(headers), tc.wantStatus)
			assert.Equal(t, tc.wantBody, string(body))
		})
	}
}

func TestRawRequestToH2Params(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		raw        string
		target     types.Target
		wantMethod string
		wantPath   string
		wantScheme string
		wantAuth   string
		wantBody   string
	}{
		{
			name:       "simple_get",
			raw:        "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
			target:     types.Target{Hostname: "example.com", Port: 443, UsesHTTPS: true},
			wantMethod: "GET",
			wantPath:   "/api",
			wantScheme: "https",
			wantAuth:   "example.com",
		},
		{
			name:       "post_with_body",
			raw:        "POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
			target:     types.Target{Hostname: "example.com", Port: 443, UsesHTTPS: true},
			wantMethod: "POST",
			wantPath:   "/data",
			wantScheme: "https",
			wantAuth:   "example.com",
			wantBody:   "hello",
		},
		{
			name:       "custom_port",
			raw:        "GET / HTTP/1.1\r\nHost: example.com:8443\r\n\r\n",
			target:     types.Target{Hostname: "example.com", Port: 8443, UsesHTTPS: true},
			wantMethod: "GET",
			wantPath:   "/",
			wantScheme: "https",
			wantAuth:   "example.com:8443",
		},
		{
			name:       "query_string",
			raw:        "GET /search?q=test&page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			target:     types.Target{Hostname: "example.com", Port: 443, UsesHTTPS: true},
			wantMethod: "GET",
			wantPath:   "/search?q=test&page=1",
			wantScheme: "https",
			wantAuth:   "example.com",
		},
		{
			name:       "no_host_header",
			raw:        "GET /path HTTP/1.1\r\n\r\n",
			target:     types.Target{Hostname: "fallback.com", Port: 8080, UsesHTTPS: false},
			wantMethod: "GET",
			wantPath:   "/path",
			wantScheme: "http",
			wantAuth:   "fallback.com:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := rawRequestToH2Params([]byte(tt.raw), tt.target)
			assert.Equal(t, tt.wantMethod, params.PseudoHeaders[":method"])
			assert.Equal(t, tt.wantPath, params.PseudoHeaders[":path"])
			assert.Equal(t, tt.wantScheme, params.PseudoHeaders[":scheme"])
			assert.Equal(t, tt.wantAuth, params.PseudoHeaders[":authority"])
			assert.Equal(t, tt.wantBody, params.RequestBody)
		})
	}
}

func TestApplyRequestRulesToRaw(t *testing.T) {
	t.Parallel()

	t.Run("header_literal", func(t *testing.T) {
		raw := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\nX-Old: value\r\n\r\n")
		rules := []protocol.RuleEntry{{
			Type:    wire.RuleTypeRequestHeader,
			Find:    "X-Old",
			Replace: "X-New",
		}}

		result := applyRequestRulesToRaw(raw, rules)
		assert.Contains(t, string(result), "X-New: value")
		assert.NotContains(t, string(result), "X-Old")
	})

	t.Run("header_append", func(t *testing.T) {
		raw := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
		rules := []protocol.RuleEntry{{
			Type:    wire.RuleTypeRequestHeader,
			Replace: "X-Added: injected\r\n",
		}}

		result := applyRequestRulesToRaw(raw, rules)
		assert.Contains(t, string(result), "X-Added: injected")
	})

	t.Run("body_regex", func(t *testing.T) {
		body := `{"token":"abc123"}`
		raw := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body)
		rules := []protocol.RuleEntry{{
			Type:    wire.RuleTypeRequestBody,
			IsRegex: true,
			Find:    `"token":"[^"]*"`,
			Replace: `"token":"REDACTED"`,
		}}

		result := applyRequestRulesToRaw(raw, rules)
		assert.Contains(t, string(result), `"token":"REDACTED"`)
		assert.NotContains(t, string(result), "abc123")
	})

	t.Run("no_request_rules", func(t *testing.T) {
		raw := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")
		rules := []protocol.RuleEntry{{
			Type:    wire.RuleTypeResponseHeader,
			Find:    "Server",
			Replace: "Hidden",
		}}

		result := applyRequestRulesToRaw(raw, rules)
		assert.Equal(t, raw, result)
	})

	t.Run("empty_rules", func(t *testing.T) {
		raw := []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n")

		result := applyRequestRulesToRaw(raw, nil)
		assert.Equal(t, raw, result)
	})
}

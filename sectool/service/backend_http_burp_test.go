package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/mcp"
)

func boolPtr(b bool) *bool { return &b }

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
					IsRegex: boolPtr(false),
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
					IsRegex: boolPtr(true),
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

func newTestBurpBackend(t *testing.T) (*BurpBackend, *TestMCPServer) {
	t.Helper()
	mockServer := NewTestMCPServer(t)
	client := mcp.New(mockServer.URL())
	require.NoError(t, client.Connect(t.Context()))
	t.Cleanup(func() { _ = client.Close() })
	return &BurpBackend{client: client}, mockServer
}

func TestBurpBackendSendCreatesRepeaterTab(t *testing.T) {
	t.Parallel()

	backend, mockServer := newTestBurpBackend(t)

	_, err := backend.SendRequest(t.Context(), "sectool-abc123", SendRequestInput{
		RawRequest: []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Target:     Target{Hostname: "example.com", Port: 443, UsesHTTPS: true},
	})
	require.NoError(t, err)

	log := mockServer.ToolCallLog()
	require.Len(t, log, 2)
	assert.Equal(t, "create_repeater_tab", log[0])
	assert.Equal(t, "send_http1_request", log[1])
}

func TestBurpBackendSendRedirectCreatesTabPerHop(t *testing.T) {
	t.Parallel()

	backend, mockServer := newTestBurpBackend(t)

	// First response: 302 redirect
	mockServer.SetSendResponse(
		`HttpRequestResponse{httpRequest=GET /old HTTP/1.1, httpResponse=HTTP/1.1 302 Found\r\nLocation: /new\r\n\r\n, messageAnnotations=Annotations{}}`,
	)
	// Second response: 200 OK
	mockServer.SetSendResponse(
		`HttpRequestResponse{httpRequest=GET /new HTTP/1.1, httpResponse=HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>OK</html>, messageAnnotations=Annotations{}}`,
	)

	_, err := backend.SendRequest(t.Context(), "sectool-redir1", SendRequestInput{
		RawRequest:      []byte("GET /old HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Target:          Target{Hostname: "example.com", Port: 443, UsesHTTPS: true},
		FollowRedirects: true,
	})
	require.NoError(t, err)

	log := mockServer.ToolCallLog()
	// Expect: create_repeater_tab, send, create_repeater_tab, send
	require.Len(t, log, 4)
	assert.Equal(t, "create_repeater_tab", log[0])
	assert.Equal(t, "send_http1_request", log[1])
	assert.Equal(t, "create_repeater_tab", log[2])
	assert.Equal(t, "send_http1_request", log[3])
}

func TestBurpBackendSendH2RoutesToH2(t *testing.T) {
	t.Parallel()

	backend, mockServer := newTestBurpBackend(t)

	_, err := backend.SendRequest(t.Context(), "sectool-h2test", SendRequestInput{
		RawRequest: []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Target:     Target{Hostname: "example.com", Port: 443, UsesHTTPS: true},
		Protocol:   "h2",
	})
	require.NoError(t, err)

	log := mockServer.ToolCallLog()
	require.Len(t, log, 2)
	assert.Equal(t, "create_repeater_tab", log[0])
	assert.Equal(t, "send_http2_request", log[1])
}

func TestRawRequestToH2Params(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		raw        string
		target     Target
		wantMethod string
		wantPath   string
		wantScheme string
		wantAuth   string
		wantBody   string
	}{
		{
			name:       "simple_get",
			raw:        "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
			target:     Target{Hostname: "example.com", Port: 443, UsesHTTPS: true},
			wantMethod: "GET",
			wantPath:   "/api",
			wantScheme: "https",
			wantAuth:   "example.com",
		},
		{
			name:       "post_with_body",
			raw:        "POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
			target:     Target{Hostname: "example.com", Port: 443, UsesHTTPS: true},
			wantMethod: "POST",
			wantPath:   "/data",
			wantScheme: "https",
			wantAuth:   "example.com",
			wantBody:   "hello",
		},
		{
			name:       "custom_port",
			raw:        "GET / HTTP/1.1\r\nHost: example.com:8443\r\n\r\n",
			target:     Target{Hostname: "example.com", Port: 8443, UsesHTTPS: true},
			wantMethod: "GET",
			wantPath:   "/",
			wantScheme: "https",
			wantAuth:   "example.com:8443",
		},
		{
			name:       "query_string",
			raw:        "GET /search?q=test&page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			target:     Target{Hostname: "example.com", Port: 443, UsesHTTPS: true},
			wantMethod: "GET",
			wantPath:   "/search?q=test&page=1",
			wantScheme: "https",
			wantAuth:   "example.com",
		},
		{
			name:       "no_host_header",
			raw:        "GET /path HTTP/1.1\r\n\r\n",
			target:     Target{Hostname: "fallback.com", Port: 8080, UsesHTTPS: false},
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

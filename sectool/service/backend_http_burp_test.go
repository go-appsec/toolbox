package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/mcp"
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
				rule, err := backend.AddRule(t.Context(), protocol.RuleEntry{
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
			Match: "old",
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
	t.Cleanup(func() { _ = client.Close() })
	return NewBurpBackend(client), mockServer
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

func TestBurpClientClosePrompt(t *testing.T) {
	t.Parallel()

	mockServer := NewTestMCPServer(t)
	client := mcp.New(mockServer.URL(), mcp.WithHealthCheckInterval(200*time.Millisecond))
	require.NoError(t, client.Connect(t.Context()))

	// Let the health loop fire at least once
	time.Sleep(300 * time.Millisecond)

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

		entries, err := backend.GetProxyHistory(t.Context(), 10, 0)
		require.NoError(t, err)
		require.Len(t, entries, 2)
		assert.Contains(t, entries[0].Request, "GET /one")
		assert.Contains(t, entries[0].Response, "200 OK")
		assert.Contains(t, entries[1].Request, "POST /two")
		assert.Equal(t, "note2", entries[1].Notes)
	})

	t.Run("offset_and_count", func(t *testing.T) {
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

		entries, err := backend.GetProxyHistory(t.Context(), 1, 1)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Contains(t, entries[0].Request, "GET /b")
	})

	t.Run("empty_history", func(t *testing.T) {
		backend, _ := newTestBurpBackend(t)

		entries, err := backend.GetProxyHistory(t.Context(), 10, 0)
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

		metas, err := backend.GetProxyHistoryMeta(t.Context(), 10, 0)
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
				Target:     Target{Hostname: tc.hostname, Port: 443, UsesHTTPS: true},
			})
			require.NoError(t, err)
			assert.Contains(t, mockServer.LastTabName(), tc.wantInTabName)
		})
	}
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

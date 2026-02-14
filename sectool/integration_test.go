package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/config"
	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/service"
	servicemcp "github.com/go-appsec/toolbox/sectool/service/mcp"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sectool/service/testutil"
)

// Integration tests for sectool MCP client → MCP server → real backends.
//
// These tests validate end-to-end functionality through the full stack:
//   mcpclient.Client → sectool MCP server → Burp MCP backend / OAST backend
//
// Skip automatically if:
//   - Running with -short flag
//   - Burp MCP is not available (for burp backend tests)

const wsUpgradeHeader = "websocket"

// httpBackendType identifies which HTTP backend to use for tests.
type httpBackendType string

const (
	backendBurp   httpBackendType = "burp"
	backendNative httpBackendType = "native"
)

var httpBackendTypes = []httpBackendType{backendBurp, backendNative}

// createBackend creates and starts the HTTP backend for the given type.
// Returns the backend and its proxy address. Skips if short mode or Burp unavailable.
func createBackend(t *testing.T, backendType httpBackendType) (service.HttpBackend, string) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	switch backendType {
	case backendBurp:
		burpClient := connectBurpOrSkip(t)
		return service.NewBurpBackend(burpClient), config.DefaultBurpProxyAddr

	case backendNative:
		backend, err := service.NewNativeProxyBackend(0, t.TempDir(), 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })
		go func() { _ = backend.Serve() }()
		require.NoError(t, backend.WaitReady(t.Context()))
		return backend, backend.Addr()
	}

	return nil, ""
}

// setupIntegrationEnv creates the MCP server with the specified backend, seeds proxy history,
// and returns a connected client.
func setupIntegrationEnv(t *testing.T, backendType httpBackendType) *mcpclient.Client {
	t.Helper()

	httpBackend, _ := createBackend(t, backendType)

	// seed backend with some dummy requests
	if nb, ok := httpBackend.(*service.NativeProxyBackend); ok {
		// Create a local test server
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "POST":
				body, _ := io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(body)
			default:
				w.Header().Set("X-Test-Header", "test-value")
				_, _ = io.WriteString(w, "test response")
			}
		}))
		t.Cleanup(ts.Close)

		// Configure client to use proxy
		proxyURL, err := url.Parse("http://" + nb.Addr())
		require.NoError(t, err)
		client := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		}

		// Seed with GET requests
		for i := 0; i < 3; i++ {
			resp, err := client.Get(ts.URL + fmt.Sprintf("/path%d?param=value%d", i, i))
			require.NoError(t, err)
			_ = resp.Body.Close()
		}

		// Seed with POST request
		resp, err := client.Post(ts.URL+"/post", "application/json", strings.NewReader(`{"test":"data"}`))
		require.NoError(t, err)
		_ = resp.Body.Close()

		testutil.WaitForCount(t, func() int {
			history, _ := nb.GetProxyHistory(t.Context(), 1, 0)
			return len(history)
		}, 1)
	}

	return startMCPServerAndClient(t, backendType, httpBackend)
}

func connectBurpOrSkip(t *testing.T) *servicemcp.BurpClient {
	t.Helper()

	testutil.AcquireBurpLock(t)

	client := servicemcp.New(config.DefaultBurpMCPURL)
	if err := client.Connect(t.Context()); err != nil {
		t.Skipf("Burp MCP not available at %s: %v", config.DefaultBurpMCPURL, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// runForAllBackends runs a test function for each backend type.
func runForAllBackends(t *testing.T, testFn func(t *testing.T, client *mcpclient.Client)) {
	t.Helper()

	for _, backendType := range httpBackendTypes {
		t.Run(string(backendType), func(t *testing.T) {
			testFn(t, setupIntegrationEnv(t, backendType))
		})
	}
}

// testEnv holds test infrastructure for dual-backend tests.
type testEnv struct {
	t           *testing.T
	backendType httpBackendType
	mcpClient   *mcpclient.Client
	backend     service.HttpBackend
	proxyAddr   string
	targetURL   string
}

// makeProxyClient returns an HTTP client configured to use the given proxy.
func makeProxyClient(proxyAddr string) *http.Client {
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
}

// runForAllBackendsWithHandler runs a test for each backend type with a custom target server handler.
// The handler receives requests that are routed through the proxy.
// Test isolation: each test gets unique test server port, filter history by that host.
func runForAllBackendsWithHandler(t *testing.T, handler http.HandlerFunc, testFn func(t *testing.T, env *testEnv)) {
	t.Helper()

	for _, backendType := range httpBackendTypes {
		t.Run(string(backendType), func(t *testing.T) {
			httpBackend, proxyAddr := createBackend(t, backendType)

			testServer := httptest.NewServer(handler)
			t.Cleanup(testServer.Close)

			mcpClient := startMCPServerAndClient(t, backendType, httpBackend)

			env := &testEnv{
				t:           t,
				backendType: backendType,
				mcpClient:   mcpClient,
				backend:     httpBackend,
				proxyAddr:   proxyAddr,
				targetURL:   testServer.URL,
			}

			testFn(t, env)
		})
	}
}

// findAvailablePort finds an available TCP port by briefly binding to port 0.
func findAvailablePort(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// startMCPServerAndClient creates an MCP server with the given backend, starts it, and returns a connected client.
func startMCPServerAndClient(t *testing.T, backendType httpBackendType, httpBackend service.HttpBackend) *mcpclient.Client {
	t.Helper()

	flags := service.MCPServerFlags{
		MCPPort:      findAvailablePort(t),
		WorkflowMode: service.WorkflowModeNone,
		ConfigPath:   filepath.Join(t.TempDir(), "config.json"),
	}
	if backendType == backendBurp {
		flags.RequireBurp = true
		flags.BurpMCPURL = config.DefaultBurpMCPURL
	}

	srv, err := service.NewServer(flags, httpBackend, nil, nil)
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() { serverErr <- srv.Run(t.Context()) }()
	srv.WaitTillStarted()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	client, err := mcpclient.New(ctx, fmt.Sprintf("http://127.0.0.1:%d/mcp", flags.MCPPort))
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = client.Close()
		srv.RequestShutdown()
		<-serverErr
	})

	return client
}

func TestIntegration_ProxySummary(t *testing.T) {
	runForAllBackends(t, func(t *testing.T, client *mcpclient.Client) {
		t.Helper()

		resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{})
		require.NoError(t, err)

		t.Logf("proxy_poll summary: %d aggregates", len(resp.Aggregates))
		for i, agg := range resp.Aggregates {
			if i >= 5 {
				t.Logf("  ... and %d more", len(resp.Aggregates)-5)
				break
			}
			t.Logf("  [%d] %s %s%s → %d (%d reqs)", i, agg.Method, agg.Host, agg.Path, agg.Status, agg.Count)
		}
	})
}

func TestIntegration_ProxySummaryWithFilters(t *testing.T) {
	runForAllBackends(t, func(t *testing.T, client *mcpclient.Client) {
		t.Helper()

		t.Run("filter_by_method", func(t *testing.T) {
			resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "summary", Method: "GET"})
			require.NoError(t, err)

			for _, agg := range resp.Aggregates {
				assert.Equal(t, "GET", agg.Method)
			}
			t.Logf("GET-only summary: %d aggregates", len(resp.Aggregates))
		})

		t.Run("filter_by_status", func(t *testing.T) {
			resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "summary", Status: "200"})
			require.NoError(t, err)

			for _, agg := range resp.Aggregates {
				assert.Equal(t, 200, agg.Status)
			}
			t.Logf("status=200 summary: %d aggregates", len(resp.Aggregates))
		})

		t.Run("filter_by_host", func(t *testing.T) {
			// First get any host from unfiltered summary
			allResp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{})
			require.NoError(t, err)

			if len(allResp.Aggregates) == 0 {
				t.Skip("no proxy history")
			}

			testHost := allResp.Aggregates[0].Host
			resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "summary", Host: testHost})
			require.NoError(t, err)

			for _, agg := range resp.Aggregates {
				assert.Equal(t, testHost, agg.Host)
			}
			t.Logf("host=%s summary: %d aggregates", testHost, len(resp.Aggregates))
		})

		t.Run("summary_does_not_return_flows", func(t *testing.T) {
			resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "summary"})
			require.NoError(t, err)

			// Summary mode should not return flows (flows should be nil/empty)
			assert.Empty(t, resp.Flows)
			t.Logf("summary mode: %d aggregates, %d flows", len(resp.Aggregates), len(resp.Flows))
		})
	})
}

func TestIntegration_ProxyList(t *testing.T) {
	runForAllBackends(t, func(t *testing.T, client *mcpclient.Client) {
		t.Helper()

		t.Run("list_requires_filters", func(t *testing.T) {
			_, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows"})
			require.Error(t, err)
		})

		t.Run("with_method_filter", func(t *testing.T) {
			resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Method: "GET", Limit: 10})
			require.NoError(t, err)

			for _, flow := range resp.Flows {
				assert.Equal(t, "GET", flow.Method)
			}
			t.Logf("GET flows: %d", len(resp.Flows))
		})

		t.Run("with_limit", func(t *testing.T) {
			resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Method: "GET", Limit: 3})
			require.NoError(t, err)
			assert.LessOrEqual(t, len(resp.Flows), 3)
		})

		t.Run("with_host_filter", func(t *testing.T) {
			// First get a host from the summary
			summary, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{})
			require.NoError(t, err)

			if len(summary.Aggregates) == 0 {
				t.Skip("no proxy history")
			}

			testHost := summary.Aggregates[0].Host
			resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Host: testHost, Limit: 5})
			require.NoError(t, err)

			for _, flow := range resp.Flows {
				assert.Contains(t, flow.Host, testHost)
			}
			t.Logf("host=%s: %d flows", testHost, len(resp.Flows))
		})

		t.Run("list_does_not_return_aggregates", func(t *testing.T) {
			resp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Method: "GET", Limit: 5})
			require.NoError(t, err)

			// List mode should not return aggregates (aggregates should be nil/empty)
			assert.Empty(t, resp.Aggregates)
			t.Logf("list mode: %d flows, %d aggregates", len(resp.Flows), len(resp.Aggregates))
		})
	})
}

func TestIntegration_ProxyGet(t *testing.T) {
	runForAllBackends(t, func(t *testing.T, client *mcpclient.Client) {
		t.Helper()

		// Get a flow ID first
		listResp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Method: "GET", Limit: 1})
		require.NoError(t, err)

		if len(listResp.Flows) == 0 {
			t.Skip("no GET requests in proxy history")
		}

		flowID := listResp.Flows[0].FlowID

		t.Run("valid_flow_id", func(t *testing.T) {
			resp, err := client.ProxyGet(t.Context(), flowID, mcpclient.ProxyGetOpts{})
			require.NoError(t, err)

			assert.Equal(t, flowID, resp.FlowID)
			assert.Equal(t, "GET", resp.Method)
			assert.NotEmpty(t, resp.URL)
			assert.NotEmpty(t, resp.ReqHeaders)
			assert.True(t, strings.HasPrefix(resp.ReqHeaders, "GET "))

			t.Logf("flow %s: %s status=%d req_size=%d resp_size=%d",
				flowID, resp.URL, resp.Status, resp.ReqSize, resp.RespSize)
		})

		t.Run("invalid_flow_id", func(t *testing.T) {
			_, err := client.ProxyGet(t.Context(), "nonexistent", mcpclient.ProxyGetOpts{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not found")
		})
	})
}

func TestIntegration_ProxyRules(t *testing.T) {
	t.Parallel()

	// only run on native backend, burp will fail if config writes are not enabled
	client := setupIntegrationEnv(t, backendNative)
	test := func(t *testing.T, client *mcpclient.Client) {
		t.Helper()

		testLabel := fmt.Sprintf("sectool-integ-test-%d", time.Now().UnixNano())
		var createdRuleID string

		t.Run("list_initial", func(t *testing.T) {
			resp, err := client.ProxyRuleList(t.Context(), "", 0)
			require.NoError(t, err)
			t.Logf("initial rules: %d", len(resp.Rules))
		})

		t.Run("add_rule", func(t *testing.T) {
			rule, err := client.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
				Type:    service.RuleTypeRequestHeader,
				Label:   testLabel,
				Replace: "X-Integration-Test: added",
			})
			require.NoError(t, err)

			assert.NotEmpty(t, rule.RuleID)
			assert.Equal(t, testLabel, rule.Label)
			assert.Equal(t, service.RuleTypeRequestHeader, rule.Type)
			assert.Equal(t, "X-Integration-Test: added", rule.Replace)
			createdRuleID = rule.RuleID

			t.Logf("created rule: %s (%s)", rule.RuleID, rule.Label)
		})

		// Ensure cleanup even if later subtests fail
		if createdRuleID != "" {
			t.Cleanup(func() { _ = client.ProxyRuleDelete(context.Background(), createdRuleID) })
		}

		t.Run("list_after_add", func(t *testing.T) {
			resp, err := client.ProxyRuleList(t.Context(), "", 0)
			require.NoError(t, err)

			var found bool
			for _, r := range resp.Rules {
				if r.RuleID == createdRuleID {
					found = true
					assert.Equal(t, testLabel, r.Label)
					break
				}
			}
			assert.True(t, found)
		})

		t.Run("update_rule", func(t *testing.T) {
			rule, err := client.ProxyRuleUpdate(t.Context(), createdRuleID, mcpclient.RuleUpdateOpts{
				Label:   testLabel + "-updated",
				Match:   "old-value",
				Replace: "new-value",
			})
			require.NoError(t, err)

			assert.Equal(t, createdRuleID, rule.RuleID)
			assert.Equal(t, testLabel+"-updated", rule.Label)
			assert.Equal(t, service.RuleTypeRequestHeader, rule.Type)
			assert.Equal(t, "old-value", rule.Match)
			assert.Equal(t, "new-value", rule.Replace)
		})

		t.Run("update_by_label", func(t *testing.T) {
			rule, err := client.ProxyRuleUpdate(t.Context(), testLabel+"-updated", mcpclient.RuleUpdateOpts{
				Replace: "X-Modified: true",
			})
			require.NoError(t, err)

			assert.Equal(t, createdRuleID, rule.RuleID)
			assert.Equal(t, service.RuleTypeRequestHeader, rule.Type)
		})

		t.Run("add_regex_rule", func(t *testing.T) {
			regexLabel := testLabel + "-regex"
			rule, err := client.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
				Type:    service.RuleTypeRequestHeader,
				Label:   regexLabel,
				IsRegex: true,
				Match:   "^X-Old:.*$",
				Replace: "X-New: replaced",
			})
			require.NoError(t, err)

			assert.True(t, rule.IsRegex)
			assert.Equal(t, "^X-Old:.*$", rule.Match)

			t.Cleanup(func() { _ = client.ProxyRuleDelete(context.Background(), rule.RuleID) })
		})

		t.Run("delete_rule", func(t *testing.T) {
			err := client.ProxyRuleDelete(t.Context(), createdRuleID)
			require.NoError(t, err)

			// Verify deleted
			resp, err := client.ProxyRuleList(t.Context(), "", 0)
			require.NoError(t, err)

			for _, r := range resp.Rules {
				assert.NotEqual(t, createdRuleID, r.RuleID)
			}
		})

		t.Run("delete_nonexistent", func(t *testing.T) {
			err := client.ProxyRuleDelete(t.Context(), "nonexistent-rule-id")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not found")
		})
	}
	test(t, client) // run directly so easily composed
}

func TestIntegration_Replay(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Header", "test-value")
		_, _ = io.WriteString(w, "test response")
	})

	runForAllBackendsWithHandler(t, handler, func(t *testing.T, env *testEnv) {
		t.Helper()

		// Seed proxy history with a request to our test server
		client := makeProxyClient(env.proxyAddr)
		resp, err := client.Get(env.targetURL + "/replay-test")
		require.NoError(t, err)
		_ = resp.Body.Close()
		testutil.WaitForCount(t, func() int {
			history, _ := env.backend.GetProxyHistory(t.Context(), 1, 0)
			return len(history)
		}, 1)

		// Parse host from target URL to filter flows
		targetURL, err := url.Parse(env.targetURL)
		require.NoError(t, err)

		// Get the flow we just seeded
		listResp, err := env.mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
			OutputMode: "flows",
			Method:     "GET",
			Host:       targetURL.Host,
			Limit:      1,
		})
		require.NoError(t, err)
		require.NotEmpty(t, listResp.Flows, "expected to find seeded flow")

		flowID := listResp.Flows[0].FlowID
		t.Logf("using flow %s for replay tests", flowID)

		var replayID string

		t.Run("send_basic", func(t *testing.T) {
			resp, err := env.mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID: flowID,
			})
			require.NoError(t, err)

			assert.NotEmpty(t, resp.ReplayID)
			assert.NotEmpty(t, resp.Duration)
			replayID = resp.ReplayID

			t.Logf("replay %s: status=%d duration=%s", resp.ReplayID, resp.Status, resp.Duration)
		})

		t.Run("get_replay_result", func(t *testing.T) {
			if replayID == "" {
				t.Skip("no replay ID from previous test")
			}

			resp, err := env.mcpClient.ReplayGet(t.Context(), replayID)
			require.NoError(t, err)

			assert.Equal(t, replayID, resp.ReplayID)
			assert.NotEmpty(t, resp.RespHeaders)
			assert.True(t, strings.HasPrefix(resp.RespHeaders, "HTTP/"),
				"unexpected prefix: %s", resp.RespHeaders)

			t.Logf("replay_get %s: status=%d body_size=%d", resp.ReplayID, resp.Status, resp.RespSize)
		})

		t.Run("send_with_header_mods", func(t *testing.T) {
			resp, err := env.mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID:        flowID,
				AddHeaders:    []string{"X-Integration-Test: modified"},
				RemoveHeaders: []string{"Accept-Encoding"},
			})
			require.NoError(t, err)
			assert.NotEmpty(t, resp.ReplayID)
			t.Logf("replay with mods: status=%d", resp.Status)
		})

		t.Run("send_invalid_flow", func(t *testing.T) {
			_, err := env.mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID: "nonexistent",
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not found")
		})

		t.Run("get_invalid_replay", func(t *testing.T) {
			_, err := env.mcpClient.ReplayGet(t.Context(), "nonexistent")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not found")
		})
	})
}

func TestIntegration_ReplayWithQueryMods(t *testing.T) {
	runForAllBackends(t, func(t *testing.T, client *mcpclient.Client) {
		t.Helper()

		// Find a flow with query params or just use any GET
		listResp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{OutputMode: "flows", Method: "GET", Limit: 1})
		require.NoError(t, err)

		if len(listResp.Flows) == 0 {
			t.Skip("no GET requests in proxy history")
		}

		flowID := listResp.Flows[0].FlowID

		t.Run("set_query_params", func(t *testing.T) {
			resp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID:   flowID,
				SetQuery: []string{"test_param=test_value", "another=123"},
			})
			require.NoError(t, err)
			assert.NotEmpty(t, resp.ReplayID)
		})

		t.Run("replace_query_string", func(t *testing.T) {
			resp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID: flowID,
				Query:  "completely=new&query=string",
			})
			require.NoError(t, err)
			assert.NotEmpty(t, resp.ReplayID)
		})
	})
}

func TestIntegration_ReplayQueryModsVerified(t *testing.T) {
	t.Parallel()

	// Channel to capture received query params
	receivedQuery := make(chan url.Values, 1)

	// Create target server that captures query params
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture the query params we received
		select {
		case receivedQuery <- r.URL.Query():
		default:
			// Channel full, ignore
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(targetServer.Close)

	// Setup native backend
	configDir := t.TempDir()
	backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	// Start proxy server in background
	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	// Make request through proxy to seed history
	proxyURL, err := url.Parse("http://" + backend.Addr())
	require.NoError(t, err)
	proxyClient := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := proxyClient.Get(targetServer.URL + "/test?keep=value&remove_me=secret")
	require.NoError(t, err)
	_ = resp.Body.Close()

	// Drain the initial request from the channel
	select {
	case <-receivedQuery:
	case <-time.After(time.Second):
		t.Fatal("target server didn't receive initial request")
	}

	testutil.WaitForCount(t, func() int {
		history, _ := backend.GetProxyHistory(t.Context(), 1, 0)
		return len(history)
	}, 1)

	client := startMCPServerAndClient(t, backendNative, backend)

	// Get flow ID
	listResp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
		OutputMode: "flows",
		Method:     "GET",
		Limit:      1,
	})
	require.NoError(t, err)
	require.NotEmpty(t, listResp.Flows)

	flowID := listResp.Flows[0].FlowID
	t.Logf("found flow %s with URL path containing query params", flowID)

	t.Run("remove_query_actually_removes", func(t *testing.T) {
		// Clear the channel
		select {
		case <-receivedQuery:
		default:
		}

		// Replay with remove_query
		replayResp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID:      flowID,
			RemoveQuery: []string{"remove_me"},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, replayResp.ReplayID)
		t.Logf("replay_send returned: status=%d", replayResp.Status)

		// Check what the server received
		select {
		case query := <-receivedQuery:
			t.Logf("server received query: %v", query)
			assert.Equal(t, "value", query.Get("keep"), "keep param should be present")
			assert.Empty(t, query.Get("remove_me"), "remove_me param should have been removed")
		case <-time.After(2 * time.Second):
			t.Fatal("target server didn't receive replayed request")
		}
	})

	t.Run("set_query_actually_sets", func(t *testing.T) {
		// Clear the channel
		select {
		case <-receivedQuery:
		default:
		}

		// Replay with set_query
		replayResp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID:   flowID,
			SetQuery: []string{"new_param=new_value"},
		})
		require.NoError(t, err)
		assert.NotEmpty(t, replayResp.ReplayID)

		// Check what the server received
		select {
		case query := <-receivedQuery:
			t.Logf("server received query: %v", query)
			assert.Equal(t, "new_value", query.Get("new_param"), "new_param should be set")
		case <-time.After(2 * time.Second):
			t.Fatal("target server didn't receive replayed request")
		}
	})
}

func TestIntegration_RequestSend(t *testing.T) {
	runForAllBackends(t, func(t *testing.T, client *mcpclient.Client) {
		t.Helper()

		t.Run("simple_get", func(t *testing.T) {
			resp, err := client.RequestSend(t.Context(), mcpclient.RequestSendOpts{
				URL:    "https://httpbin.org/get",
				Method: "GET",
			})
			require.NoError(t, err)

			assert.NotEmpty(t, resp.ReplayID)
			assert.Equal(t, 200, resp.Status)
			t.Logf("request_send GET: status=%d duration=%s", resp.Status, resp.Duration)
		})

		t.Run("with_headers", func(t *testing.T) {
			resp, err := client.RequestSend(t.Context(), mcpclient.RequestSendOpts{
				URL:    "https://httpbin.org/headers",
				Method: "GET",
				Headers: map[string]string{
					"X-Custom-Header": "integration-test",
					"Accept":          "application/json",
				},
			})
			require.NoError(t, err)
			assert.Equal(t, 200, resp.Status)
		})

		t.Run("post_with_body", func(t *testing.T) {
			resp, err := client.RequestSend(t.Context(), mcpclient.RequestSendOpts{
				URL:    "https://httpbin.org/post",
				Method: "POST",
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: `{"test": "data", "integration": true}`,
			})
			require.NoError(t, err)
			assert.Equal(t, 200, resp.Status)
			t.Logf("request_send POST: status=%d", resp.Status)
		})
	})
}

func TestIntegration_OAST(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	client := setupIntegrationEnv(t, backendNative) // only native since only one OAST backend
	testLabel := fmt.Sprintf("integ-test-%d", time.Now().UnixNano())
	var oastID string
	var oastDomain string

	t.Run("create_session", func(t *testing.T) {
		resp, err := client.OastCreate(t.Context(), testLabel)
		require.NoError(t, err)

		assert.NotEmpty(t, resp.OastID)
		assert.NotEmpty(t, resp.Domain)
		assert.Equal(t, testLabel, resp.Label)
		oastID = resp.OastID
		oastDomain = resp.Domain

		t.Logf("oast_create: id=%s domain=%s", resp.OastID, resp.Domain)
	})

	t.Run("list_sessions", func(t *testing.T) {
		if oastID == "" {
			t.Skip("no OAST session created")
		}

		resp, err := client.OastList(t.Context(), 0)
		require.NoError(t, err)

		var found bool
		for _, s := range resp.Sessions {
			if s.OastID == oastID {
				found = true
				assert.Equal(t, oastDomain, s.Domain)
				assert.Equal(t, testLabel, s.Label)
				break
			}
		}
		assert.True(t, found)
		t.Logf("oast_list: %d sessions", len(resp.Sessions))
	})

	t.Run("poll_no_events", func(t *testing.T) {
		if oastID == "" {
			t.Skip("no OAST session created")
		}

		resp, err := client.OastPoll(t.Context(), oastID, mcpclient.OastPollOpts{OutputMode: "events", Wait: "0s"})
		require.NoError(t, err)

		// May or may not have events depending on timing
		t.Logf("oast_poll: %d events", len(resp.Events))
	})

	t.Run("poll_with_wait", func(t *testing.T) {
		if oastID == "" {
			t.Skip("no OAST session created")
		}

		// Short wait - should return quickly with no events
		resp, err := client.OastPoll(t.Context(), oastID, mcpclient.OastPollOpts{OutputMode: "events", Wait: "200ms"})
		require.NoError(t, err)
		t.Logf("oast_poll: %d events", len(resp.Events))
	})

	t.Run("poll_invalid_session", func(t *testing.T) {
		_, err := client.OastPoll(t.Context(), "nonexistent", mcpclient.OastPollOpts{OutputMode: "events"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("delete_session", func(t *testing.T) {
		if oastID == "" {
			t.Skip("no OAST session created")
		}

		err := client.OastDelete(t.Context(), oastID)
		require.NoError(t, err)

		// Verify deleted
		resp, err := client.OastList(t.Context(), 0)
		require.NoError(t, err)

		for _, s := range resp.Sessions {
			assert.NotEqual(t, oastID, s.OastID)
		}
	})

	t.Run("delete_invalid_session", func(t *testing.T) {
		err := client.OastDelete(t.Context(), "nonexistent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestIntegration_HTTPSProxy(t *testing.T) {
	t.Parallel()

	// Create HTTPS test server
	testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Protocol", r.Proto)
		w.Header().Set("X-Secure", "true")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secure": true, "method": "` + r.Method + `"}`))
	}))
	t.Cleanup(testServer.Close)

	// Setup native backend
	configDir := t.TempDir()
	backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	// Get proxy's CA cert for client trust
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(backend.CACert())

	// Configure client to use proxy and trust proxy's CA
	proxyURL, err := url.Parse("http://" + backend.Addr())
	require.NoError(t, err)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:            caCertPool,
				InsecureSkipVerify: true,
			},
		},
	}

	t.Run("https_get_through_proxy", func(t *testing.T) {
		resp, err := client.Get(testServer.URL + "/secure-endpoint")
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, 200, resp.StatusCode)
		assert.Contains(t, string(body), `"secure": true`)
	})

	t.Run("https_post_through_proxy", func(t *testing.T) {
		resp, err := client.Post(testServer.URL+"/secure-post", "application/json", strings.NewReader(`{"data":"test"}`))
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })

		assert.Equal(t, 200, resp.StatusCode)
	})

	testutil.WaitForCount(t, func() int {
		history, _ := backend.GetProxyHistory(t.Context(), 1, 0)
		return len(history)
	}, 1)

	mcpClient := startMCPServerAndClient(t, backendNative, backend)

	t.Run("https_traffic_captured", func(t *testing.T) {
		listResp, err := mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
			OutputMode: "flows",
			Method:     "GET",
			Limit:      10,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, listResp.Flows)

		// Verify HTTPS flows are captured
		var foundSecure bool
		for _, flow := range listResp.Flows {
			if strings.Contains(flow.Path, "/secure-endpoint") {
				foundSecure = true
				break
			}
		}
		assert.True(t, foundSecure, "HTTPS traffic should be captured")
	})

	t.Run("https_replay", func(t *testing.T) {
		listResp, err := mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
			OutputMode: "flows",
			Path:       "/secure-endpoint",
			Limit:      1,
		})
		require.NoError(t, err)
		require.Len(t, listResp.Flows, 1)

		flowID := listResp.Flows[0].FlowID

		// Get the full URL which includes the https:// scheme
		flowDetails, err := mcpClient.ProxyGet(t.Context(), flowID, mcpclient.ProxyGetOpts{})
		require.NoError(t, err)

		// Pass the target URL explicitly to preserve HTTPS scheme
		replayResp, err := mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID: flowID,
			Target: flowDetails.URL,
		})
		require.NoError(t, err)
		assert.Equal(t, 200, replayResp.Status)
	})
}

func TestIntegration_RuleRequestHeaderVerification(t *testing.T) {
	receivedHeaders := make(chan http.Header, 10)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case receivedHeaders <- r.Header.Clone():
		default:
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})

	runForAllBackendsWithHandler(t, handler, func(t *testing.T, env *testEnv) {
		t.Helper()
		if env.backendType == backendBurp {
			t.Skip("rules require Burp proxy with config editing enabled")
		}
		labelSuffix := strconv.FormatInt(rand.Int63(), 10)

		t.Run("adds_header", func(t *testing.T) {
			label := "test-add-header-" + labelSuffix
			rule, err := env.mcpClient.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
				Type:    service.RuleTypeRequestHeader,
				Label:   label,
				Replace: "X-Injected-By-Rule: rule-value-123",
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = env.mcpClient.ProxyRuleDelete(context.Background(), rule.RuleID) })

			for len(receivedHeaders) > 0 {
				<-receivedHeaders
			}

			client := makeProxyClient(env.proxyAddr)
			resp, err := client.Get(env.targetURL + "/test-rule")
			require.NoError(t, err)
			_ = resp.Body.Close()

			select {
			case headers := <-receivedHeaders:
				assert.Equal(t, "rule-value-123", headers.Get("X-Injected-By-Rule"))
			case <-time.After(2 * time.Second):
				t.Fatal("target server didn't receive request")
			}
		})

		t.Run("modifies_header", func(t *testing.T) {
			label := "test-modify-ua-" + labelSuffix
			rule, err := env.mcpClient.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
				Type:    service.RuleTypeRequestHeader,
				Label:   label,
				IsRegex: true,
				Match:   `User-Agent: .*`,
				Replace: "User-Agent: Modified-By-Rule",
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = env.mcpClient.ProxyRuleDelete(context.Background(), rule.RuleID) })

			for len(receivedHeaders) > 0 {
				<-receivedHeaders
			}

			client := makeProxyClient(env.proxyAddr)
			resp, err := client.Get(env.targetURL + "/test-ua")
			require.NoError(t, err)
			_ = resp.Body.Close()

			select {
			case headers := <-receivedHeaders:
				assert.Equal(t, "Modified-By-Rule", headers.Get("User-Agent"))
			case <-time.After(2 * time.Second):
				t.Fatal("target server didn't receive request")
			}
		})
	})
}

func TestIntegration_RuleRequestBodyVerification(t *testing.T) {
	receivedBody := make(chan []byte, 10)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case receivedBody <- body:
		default:
		}
		w.WriteHeader(200)
	})

	runForAllBackendsWithHandler(t, handler, func(t *testing.T, env *testEnv) {
		t.Helper()
		if env.backendType == backendBurp {
			t.Skip("rules require Burp proxy with config editing enabled")
		}
		label := "test-body-rule-" + strconv.FormatInt(rand.Int63(), 10)

		t.Run("modifies_body", func(t *testing.T) {
			rule, err := env.mcpClient.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
				Type:    service.RuleTypeRequestBody,
				Label:   label,
				Match:   "ORIGINAL_VALUE",
				Replace: "MODIFIED_BY_RULE",
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = env.mcpClient.ProxyRuleDelete(context.Background(), rule.RuleID) })

			for len(receivedBody) > 0 {
				<-receivedBody
			}

			client := makeProxyClient(env.proxyAddr)
			resp, err := client.Post(env.targetURL+"/body-test", "text/plain",
				strings.NewReader("data=ORIGINAL_VALUE&other=test"))
			require.NoError(t, err)
			_ = resp.Body.Close()

			select {
			case body := <-receivedBody:
				assert.Contains(t, string(body), "MODIFIED_BY_RULE")
				assert.NotContains(t, string(body), "ORIGINAL_VALUE")
			case <-time.After(2 * time.Second):
				t.Fatal("target server didn't receive request")
			}
		})
	})
}

func TestIntegration_RuleResponseHeaderVerification(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Original-Header", "original-value")
		w.Header().Set("X-Server-Token", "secret-token-abc")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})

	runForAllBackendsWithHandler(t, handler, func(t *testing.T, env *testEnv) {
		t.Helper()
		if env.backendType == backendBurp {
			t.Skip("rules require Burp proxy with config editing enabled")
		}
		labelSuffix := strconv.FormatInt(rand.Int63(), 10)

		t.Run("modifies_header", func(t *testing.T) {
			label := "test-resp-header-" + labelSuffix
			rule, err := env.mcpClient.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
				Type:    service.RuleTypeResponseHeader,
				Label:   label,
				Match:   "X-Original-Header: original-value",
				Replace: "X-Original-Header: modified-by-rule",
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = env.mcpClient.ProxyRuleDelete(context.Background(), rule.RuleID) })

			client := makeProxyClient(env.proxyAddr)
			resp, err := client.Get(env.targetURL + "/resp-header-test")
			require.NoError(t, err)
			_ = resp.Body.Close()

			assert.Equal(t, "modified-by-rule", resp.Header.Get("X-Original-Header"))
		})

		t.Run("adds_header", func(t *testing.T) {
			label := "test-add-resp-header-" + labelSuffix
			rule, err := env.mcpClient.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
				Type:    service.RuleTypeResponseHeader,
				Label:   label,
				Replace: "X-Added-By-Proxy: injected",
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = env.mcpClient.ProxyRuleDelete(context.Background(), rule.RuleID) })

			client := makeProxyClient(env.proxyAddr)
			resp, err := client.Get(env.targetURL + "/resp-add-test")
			require.NoError(t, err)
			_ = resp.Body.Close()

			assert.Equal(t, "injected", resp.Header.Get("X-Added-By-Proxy"))
		})
	})
}

func TestIntegration_RuleResponseBodyVerification(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("Response contains SECRET_DATA that should be modified"))
	})

	runForAllBackendsWithHandler(t, handler, func(t *testing.T, env *testEnv) {
		t.Helper()
		if env.backendType == backendBurp {
			t.Skip("rules require Burp proxy with config editing enabled")
		}
		label := "test-resp-body-" + strconv.FormatInt(rand.Int63(), 10)

		t.Run("modifies_body", func(t *testing.T) {
			rule, err := env.mcpClient.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
				Type:    service.RuleTypeResponseBody,
				Label:   label,
				Match:   "SECRET_DATA",
				Replace: "REDACTED",
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = env.mcpClient.ProxyRuleDelete(context.Background(), rule.RuleID) })

			client := makeProxyClient(env.proxyAddr)
			resp, err := client.Get(env.targetURL + "/resp-body-test")
			require.NoError(t, err)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			assert.Contains(t, string(body), "REDACTED")
			assert.NotContains(t, string(body), "SECRET_DATA")
		})
	})
}

func TestIntegration_ReplayBodyReplacement(t *testing.T) {
	receivedBody := make(chan []byte, 10)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case receivedBody <- body:
		default:
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	})

	runForAllBackendsWithHandler(t, handler, func(t *testing.T, env *testEnv) {
		t.Helper()
		// Seed with a POST request
		client := makeProxyClient(env.proxyAddr)
		resp, err := client.Post(env.targetURL+"/body-test", "application/json",
			strings.NewReader(`{"original": "body"}`))
		require.NoError(t, err)
		_ = resp.Body.Close()

		// Drain initial body
		select {
		case <-receivedBody:
		case <-time.After(2 * time.Second):
			t.Fatal("didn't receive initial request")
		}

		testutil.WaitForCount(t, func() int {
			history, _ := env.backend.GetProxyHistory(t.Context(), 1, 0)
			return len(history)
		}, 1)

		// Get flow ID by filtering on target host
		targetURL, _ := url.Parse(env.targetURL)
		listResp, err := env.mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
			OutputMode: "flows",
			Method:     "POST",
			Host:       targetURL.Host,
			Limit:      1,
		})
		require.NoError(t, err)
		require.NotEmpty(t, listResp.Flows)

		flowID := listResp.Flows[0].FlowID

		t.Run("body_replacement", func(t *testing.T) {
			for len(receivedBody) > 0 {
				<-receivedBody
			}

			replayResp, err := env.mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID: flowID,
				Body:   `{"replaced": "completely"}`,
			})
			require.NoError(t, err)
			assert.Equal(t, 200, replayResp.Status)

			select {
			case body := <-receivedBody:
				assert.JSONEq(t, `{"replaced": "completely"}`, string(body))
			case <-time.After(2 * time.Second):
				t.Fatal("didn't receive replayed request")
			}
		})
	})
}

func TestIntegration_ReplayJSONModifications(t *testing.T) {
	receivedBody := make(chan []byte, 10)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case receivedBody <- body:
		default:
		}
		w.WriteHeader(200)
		_, _ = w.Write(body)
	})

	runForAllBackendsWithHandler(t, handler, func(t *testing.T, env *testEnv) {
		t.Helper()
		// Seed with JSON POST request
		client := makeProxyClient(env.proxyAddr)
		resp, err := client.Post(env.targetURL+"/json-test", "application/json",
			strings.NewReader(`{"user": "alice", "role": "viewer", "nested": {"key": "original"}}`))
		require.NoError(t, err)
		_ = resp.Body.Close()

		select {
		case <-receivedBody:
		case <-time.After(2 * time.Second):
			t.Fatal("didn't receive initial request")
		}

		targetURL, _ := url.Parse(env.targetURL)
		listResp, err := env.mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
			OutputMode: "flows",
			Method:     "POST",
			Host:       targetURL.Host,
			Path:       "/json-test",
			Limit:      1,
		})
		require.NoError(t, err)
		require.Len(t, listResp.Flows, 1)

		flowID := listResp.Flows[0].FlowID

		t.Run("set_json_fields", func(t *testing.T) {
			for len(receivedBody) > 0 {
				<-receivedBody
			}

			replayResp, err := env.mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID: flowID,
				SetJSON: map[string]interface{}{
					"role":       "admin",
					"nested.key": "modified",
					"new_field":  "added",
				},
			})
			require.NoError(t, err)
			assert.Equal(t, 200, replayResp.Status)

			select {
			case body := <-receivedBody:
				var data map[string]interface{}
				err := json.Unmarshal(body, &data)
				require.NoError(t, err)

				assert.Equal(t, "alice", data["user"])
				assert.Equal(t, "admin", data["role"])
				assert.Equal(t, "added", data["new_field"])

				nested, ok := data["nested"].(map[string]interface{})
				require.True(t, ok)
				assert.Equal(t, "modified", nested["key"])
			case <-time.After(2 * time.Second):
				t.Fatal("didn't receive replayed request")
			}
		})

		t.Run("remove_json_fields", func(t *testing.T) {
			for len(receivedBody) > 0 {
				<-receivedBody
			}

			replayResp, err := env.mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID:     flowID,
				RemoveJSON: []string{"role", "nested"},
			})
			require.NoError(t, err)
			assert.Equal(t, 200, replayResp.Status)

			select {
			case body := <-receivedBody:
				var data map[string]interface{}
				err := json.Unmarshal(body, &data)
				require.NoError(t, err)

				assert.Equal(t, "alice", data["user"])
				_, hasRole := data["role"]
				assert.False(t, hasRole, "role should be removed")
				_, hasNested := data["nested"]
				assert.False(t, hasNested, "nested should be removed")
			case <-time.After(2 * time.Second):
				t.Fatal("didn't receive replayed request")
			}
		})
	})
}

func TestIntegration_ReplayMethodOverride(t *testing.T) {
	receivedMethod := make(chan string, 10)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case receivedMethod <- r.Method:
		default:
		}
		w.WriteHeader(200)
	})

	runForAllBackendsWithHandler(t, handler, func(t *testing.T, env *testEnv) {
		t.Helper()
		client := makeProxyClient(env.proxyAddr)
		resp, err := client.Get(env.targetURL + "/method-test")
		require.NoError(t, err)
		_ = resp.Body.Close()

		select {
		case <-receivedMethod:
		case <-time.After(2 * time.Second):
			t.Fatal("didn't receive initial request")
		}

		targetURL, _ := url.Parse(env.targetURL)
		listResp, err := env.mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
			OutputMode: "flows",
			Method:     "GET",
			Host:       targetURL.Host,
			Path:       "/method-test",
			Limit:      1,
		})
		require.NoError(t, err)
		require.Len(t, listResp.Flows, 1)

		flowID := listResp.Flows[0].FlowID

		t.Run("change_get_to_post", func(t *testing.T) {
			for len(receivedMethod) > 0 {
				<-receivedMethod
			}

			replayResp, err := env.mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID: flowID,
				Method: "POST",
				Body:   "test body",
			})
			require.NoError(t, err)
			assert.Equal(t, 200, replayResp.Status)

			select {
			case method := <-receivedMethod:
				assert.Equal(t, "POST", method)
			case <-time.After(2 * time.Second):
				t.Fatal("didn't receive replayed request")
			}
		})

		t.Run("change_get_to_delete", func(t *testing.T) {
			for len(receivedMethod) > 0 {
				<-receivedMethod
			}

			replayResp, err := env.mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID: flowID,
				Method: "DELETE",
			})
			require.NoError(t, err)
			assert.Equal(t, 200, replayResp.Status)

			select {
			case method := <-receivedMethod:
				assert.Equal(t, "DELETE", method)
			case <-time.After(2 * time.Second):
				t.Fatal("didn't receive replayed request")
			}
		})
	})
}

func TestIntegration_ReplayFollowRedirects(t *testing.T) {
	var redirectCount int
	var mu sync.Mutex

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect-start":
			http.Redirect(w, r, "/redirect-middle", http.StatusFound)
		case "/redirect-middle":
			http.Redirect(w, r, "/final-destination", http.StatusMovedPermanently)
		case "/final-destination":
			mu.Lock()
			redirectCount++
			mu.Unlock()
			w.WriteHeader(200)
			_, _ = w.Write([]byte("final destination reached"))
		default:
			w.WriteHeader(404)
		}
	})

	runForAllBackendsWithHandler(t, handler, func(t *testing.T, env *testEnv) {
		t.Helper()
		// Seed history (don't follow redirects in seeding client)
		proxyURL, _ := url.Parse("http://" + env.proxyAddr)
		proxyClient := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := proxyClient.Get(env.targetURL + "/redirect-start")
		require.NoError(t, err)
		_ = resp.Body.Close()

		testutil.WaitForCount(t, func() int {
			history, _ := env.backend.GetProxyHistory(t.Context(), 1, 0)
			return len(history)
		}, 1)

		targetURL, _ := url.Parse(env.targetURL)
		listResp, err := env.mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
			OutputMode: "flows",
			Host:       targetURL.Host,
			Path:       "/redirect-start",
			Limit:      1,
		})
		require.NoError(t, err)
		require.Len(t, listResp.Flows, 1)

		flowID := listResp.Flows[0].FlowID

		t.Run("follow_redirects_enabled", func(t *testing.T) {
			mu.Lock()
			redirectCount = 0
			mu.Unlock()

			replayResp, err := env.mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID:          flowID,
				FollowRedirects: true,
			})
			require.NoError(t, err)

			assert.Equal(t, 200, replayResp.Status)
			mu.Lock()
			assert.Equal(t, 1, redirectCount)
			mu.Unlock()
		})

		t.Run("follow_redirects_disabled", func(t *testing.T) {
			replayResp, err := env.mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID:          flowID,
				FollowRedirects: false,
			})
			require.NoError(t, err)

			assert.Equal(t, 302, replayResp.Status)
		})
	})
}

func TestIntegration_HTTP2Proxy(t *testing.T) {
	t.Parallel()

	// Channel to capture POST bodies received by server
	receivedBody := make(chan []byte, 10)

	// Create HTTP/2 enabled test server that echoes POST bodies
	testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Protocol", r.Proto)
		w.Header().Set("X-H2-Test", "success")

		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			select {
			case receivedBody <- body:
			default:
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			_, _ = w.Write(body) // Echo back the body
		} else {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("HTTP/2 response body"))
		}
	}))
	testServer.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	testServer.StartTLS()
	t.Cleanup(testServer.Close)

	configDir := t.TempDir()
	backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(backend.CACert())

	proxyURL, _ := url.Parse("http://" + backend.Addr())
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	}
	proxyClient := &http.Client{Transport: transport}

	t.Run("h2_request_through_proxy", func(t *testing.T) {
		resp, err := proxyClient.Get(testServer.URL + "/h2-test")
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })

		body, _ := io.ReadAll(resp.Body)

		assert.Equal(t, 200, resp.StatusCode)
		assert.Equal(t, "success", resp.Header.Get("X-H2-Test"))
		assert.Equal(t, "HTTP/2 response body", string(body))
		assert.Equal(t, 2, resp.ProtoMajor, "response should be HTTP/2")
	})

	t.Run("h2_post_body_preserved", func(t *testing.T) {
		// Drain channel
		for len(receivedBody) > 0 {
			<-receivedBody
		}

		postBody := `{"h2":"post","data":"test-value-123"}`
		resp, err := proxyClient.Post(testServer.URL+"/h2-post", "application/json",
			strings.NewReader(postBody))
		require.NoError(t, err)

		// Read echoed body from response
		echoedBody, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)

		assert.Equal(t, 200, resp.StatusCode)
		assert.Equal(t, 2, resp.ProtoMajor)

		select {
		case serverReceived := <-receivedBody:
			assert.JSONEq(t, postBody, string(serverReceived))
		case <-time.After(2 * time.Second):
			t.Fatal("server didn't receive POST body")
		}

		assert.JSONEq(t, postBody, string(echoedBody))
	})

	testutil.WaitForCount(t, func() int {
		history, _ := backend.GetProxyHistory(t.Context(), 1, 0)
		return len(history)
	}, 1)

	client := startMCPServerAndClient(t, backendNative, backend)

	t.Run("h2_traffic_captured_in_history", func(t *testing.T) {
		listResp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
			OutputMode: "flows",
			Path:       "/h2-test",
			Limit:      1,
		})
		require.NoError(t, err)
		require.Len(t, listResp.Flows, 1)

		flow := listResp.Flows[0]
		assert.Equal(t, "GET", flow.Method)
	})

	t.Run("h2_flow_details", func(t *testing.T) {
		listResp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
			OutputMode: "flows",
			Path:       "/h2-test",
			Limit:      1,
		})
		require.NoError(t, err)
		require.Len(t, listResp.Flows, 1)

		flowResp, err := client.ProxyGet(t.Context(), listResp.Flows[0].FlowID, mcpclient.ProxyGetOpts{})
		require.NoError(t, err)

		assert.Equal(t, "GET", flowResp.Method)
		assert.Contains(t, flowResp.URL, "/h2-test")
		assert.Equal(t, 200, flowResp.Status)
	})
}

// TestIntegration_HTTP2Rules tests that proxy rules are correctly applied to HTTP/2 traffic.
// Rules should work on both request and response headers/bodies over H2 connections.
func TestIntegration_HTTP2Rules(t *testing.T) {
	t.Parallel()

	// Channels to capture what server receives
	receivedHeaders := make(chan http.Header, 10)
	receivedBody := make(chan []byte, 10)

	// Create HTTP/2 enabled test server
	testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture request headers
		select {
		case receivedHeaders <- r.Header.Clone():
		default:
		}

		// Capture request body for POST
		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			select {
			case receivedBody <- body:
			default:
			}
		}

		// Send response with content that rules can modify
		w.Header().Set("X-Server-Secret", "original-secret-value")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("Response contains SENSITIVE_DATA that should be modified"))
	}))
	testServer.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	testServer.StartTLS()
	t.Cleanup(testServer.Close)

	configDir := t.TempDir()
	backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	mcpClient := startMCPServerAndClient(t, backendNative, backend)

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(backend.CACert())

	proxyURL, _ := url.Parse("http://" + backend.Addr())
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	}
	proxyClient := &http.Client{Transport: transport}

	t.Run("h2_request_header_rule", func(t *testing.T) {
		// Add rule to inject header into requests
		rule, err := mcpClient.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
			Type:    service.RuleTypeRequestHeader,
			Label:   "h2-req-header-test",
			Replace: "X-Injected-H2: injected-value",
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = mcpClient.ProxyRuleDelete(context.Background(), rule.RuleID) })

		// Drain channel
		for len(receivedHeaders) > 0 {
			<-receivedHeaders
		}

		resp, err := proxyClient.Get(testServer.URL + "/h2-rule-test")
		require.NoError(t, err)
		_ = resp.Body.Close()

		assert.Equal(t, 2, resp.ProtoMajor)

		select {
		case headers := <-receivedHeaders:
			assert.Equal(t, "injected-value", headers.Get("X-Injected-H2"))
		case <-time.After(2 * time.Second):
			t.Fatal("server didn't receive request")
		}
	})

	t.Run("h2_request_body_rule", func(t *testing.T) {
		rule, err := mcpClient.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
			Type:    service.RuleTypeRequestBody,
			Label:   "h2-req-body-test",
			Match:   "ORIGINAL_VALUE",
			Replace: "MODIFIED_BY_RULE",
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = mcpClient.ProxyRuleDelete(context.Background(), rule.RuleID) })

		for len(receivedBody) > 0 {
			<-receivedBody
		}

		resp, err := proxyClient.Post(testServer.URL+"/h2-body-rule", "text/plain",
			strings.NewReader("data=ORIGINAL_VALUE&other=test"))
		require.NoError(t, err)
		_ = resp.Body.Close()

		assert.Equal(t, 2, resp.ProtoMajor)

		select {
		case body := <-receivedBody:
			assert.Contains(t, string(body), "MODIFIED_BY_RULE")
			assert.NotContains(t, string(body), "ORIGINAL_VALUE")
		case <-time.After(2 * time.Second):
			t.Fatal("server didn't receive request")
		}
	})

	t.Run("h2_response_header_rule", func(t *testing.T) {
		rule, err := mcpClient.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
			Type:    service.RuleTypeResponseHeader,
			Label:   "h2-resp-header-test",
			Match:   "X-Server-Secret: original-secret-value",
			Replace: "X-Server-Secret: modified-by-proxy",
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = mcpClient.ProxyRuleDelete(context.Background(), rule.RuleID) })

		resp, err := proxyClient.Get(testServer.URL + "/h2-resp-header-test")
		require.NoError(t, err)
		_ = resp.Body.Close()

		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Equal(t, "modified-by-proxy", resp.Header.Get("X-Server-Secret"))
	})

	t.Run("h2_response_body_rule", func(t *testing.T) {
		rule, err := mcpClient.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
			Type:    service.RuleTypeResponseBody,
			Label:   "h2-resp-body-test",
			Match:   "SENSITIVE_DATA",
			Replace: "REDACTED",
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = mcpClient.ProxyRuleDelete(context.Background(), rule.RuleID) })

		resp, err := proxyClient.Get(testServer.URL + "/h2-resp-body-test")
		require.NoError(t, err)

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)

		assert.Equal(t, 2, resp.ProtoMajor)
		assert.Contains(t, string(body), "REDACTED")
		assert.NotContains(t, string(body), "SENSITIVE_DATA")
	})
}

func TestIntegration_WebSocketProxy(t *testing.T) {
	t.Parallel()

	// Create WebSocket echo server
	wsMessages := make(chan string, 100)
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != wsUpgradeHeader {
			w.WriteHeader(400)
			return
		}

		// Perform WebSocket handshake
		key := r.Header.Get("Sec-WebSocket-Key")
		acceptKey := computeWebSocketAcceptKey(key)

		w.Header().Set("Upgrade", wsUpgradeHeader)
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", acceptKey)
		w.WriteHeader(101)

		// Hijack the connection
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, bufrw, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = bufrw.Flush()

		// Echo loop
		for {
			frame, err := readWebSocketFrame(conn)
			if err != nil {
				return
			}

			if frame.opcode == 8 { // close
				return
			}

			if frame.opcode == 1 { // text
				wsMessages <- string(frame.payload)

				// Echo back
				responseFrame := encodeWebSocketFrame(frame.payload, 1, false)
				_, _ = conn.Write(responseFrame)
			}
		}
	}))
	t.Cleanup(testServer.Close)

	configDir := t.TempDir()
	backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	t.Run("websocket_upgrade_through_proxy", func(t *testing.T) {
		// Connect through proxy
		proxyAddr := backend.Addr()
		conn, err := net.Dial("tcp", proxyAddr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		serverURL, _ := url.Parse(testServer.URL)

		// Send WebSocket upgrade request through proxy
		wsKey := base64.StdEncoding.EncodeToString([]byte("test-ws-key-1234"))
		req := fmt.Sprintf(
			"GET /ws HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Key: %s\r\n"+
				"Sec-WebSocket-Version: 13\r\n"+
				"\r\n",
			serverURL.Host, wsKey)

		_, err = conn.Write([]byte(req))
		require.NoError(t, err)

		// Read response
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 101, resp.StatusCode)
		assert.Equal(t, wsUpgradeHeader, strings.ToLower(resp.Header.Get("Upgrade")))

		// Send a text frame
		message := "Hello WebSocket!"
		frame := encodeWebSocketFrame([]byte(message), 1, true) // text frame, masked
		_, err = conn.Write(frame)
		require.NoError(t, err)

		// Verify message was received by server
		select {
		case received := <-wsMessages:
			assert.Equal(t, message, received)
		case <-time.After(2 * time.Second):
			t.Fatal("WebSocket message not received")
		}
		assert.Empty(t, wsMessages)

		// Read echo response
		responseFrame, err := readWebSocketFrame(conn)
		require.NoError(t, err)
		assert.Equal(t, byte(1), responseFrame.opcode)
		assert.Equal(t, message, string(responseFrame.payload))
	})
}

func TestIntegration_ChunkedEncoding(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Transfer-Encoding", "chunked")
		w.Header().Set("Content-Type", "text/plain")

		chunks := []string{"chunk1-", "chunk2-", "chunk3"}
		for _, chunk := range chunks {
			_, _ = w.Write([]byte(chunk))
			flusher.Flush()
		}
	})

	runForAllBackendsWithHandler(t, handler, func(t *testing.T, env *testEnv) {
		t.Helper()
		client := makeProxyClient(env.proxyAddr)

		t.Run("chunked_response_through_proxy", func(t *testing.T) {
			resp, err := client.Get(env.targetURL + "/chunked-test")
			require.NoError(t, err)
			t.Cleanup(func() { _ = resp.Body.Close() })

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			assert.Equal(t, 200, resp.StatusCode)
			assert.Equal(t, "chunk1-chunk2-chunk3", string(body))
		})

		testutil.WaitForCount(t, func() int {
			history, _ := env.backend.GetProxyHistory(t.Context(), 1, 0)
			return len(history)
		}, 1)

		t.Run("chunked_flow_captured", func(t *testing.T) {
			targetURL, _ := url.Parse(env.targetURL)
			listResp, err := env.mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
				OutputMode: "flows",
				Host:       targetURL.Host,
				Path:       "/chunked-test",
				Limit:      1,
			})
			require.NoError(t, err)
			require.Len(t, listResp.Flows, 1)

			flowResp, err := env.mcpClient.ProxyGet(t.Context(), listResp.Flows[0].FlowID, mcpclient.ProxyGetOpts{})
			require.NoError(t, err)
			assert.Equal(t, 200, flowResp.Status)
		})
	})
}

func TestIntegration_ForceFlag(t *testing.T) {
	t.Parallel()

	receivedRequests := make(chan *http.Request, 10)

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case receivedRequests <- r:
		default:
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(testServer.Close)

	configDir := t.TempDir()
	backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	// Seed with normal request
	proxyURL, _ := url.Parse("http://" + backend.Addr())
	proxyClient := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := proxyClient.Get(testServer.URL + "/force-test")
	require.NoError(t, err)
	_ = resp.Body.Close()

	<-receivedRequests
	testutil.WaitForCount(t, func() int {
		history, _ := backend.GetProxyHistory(t.Context(), 1, 0)
		return len(history)
	}, 1)

	client := startMCPServerAndClient(t, backendNative, backend)

	listResp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
		OutputMode: "flows",
		Path:       "/force-test",
		Limit:      1,
	})
	require.NoError(t, err)
	require.Len(t, listResp.Flows, 1)

	flowID := listResp.Flows[0].FlowID

	t.Run("force_allows_unusual_method", func(t *testing.T) {
		for len(receivedRequests) > 0 {
			<-receivedRequests
		}

		// Without force, unusual modifications might be rejected
		// With force, they should be allowed
		replayResp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID: flowID,
			Method: "CUSTOM",
			Force:  true,
		})
		require.NoError(t, err)
		assert.Equal(t, 200, replayResp.Status)

		select {
		case req := <-receivedRequests:
			assert.Equal(t, "CUSTOM", req.Method)
		case <-time.After(2 * time.Second):
			t.Fatal("didn't receive request")
		}
	})
}

func TestIntegration_MalformedRequests(t *testing.T) {
	t.Parallel()

	// Use raw TCP server to receive malformed requests without HTTP parsing
	receivedData := make(chan []byte, 10)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	tcpAddr := listener.Addr().String()

	// Raw TCP server that captures incoming data and sends HTTP response
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()

				// Read incoming data
				buf := make([]byte, 8192)
				n, err := c.Read(buf)
				if err != nil {
					return
				}

				// Send captured data to channel
				select {
				case receivedData <- buf[:n]:
				default:
				}

				// Send minimal HTTP response
				response := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
				_, _ = c.Write([]byte(response))
			}(conn)
		}
	}()

	// Also need a normal HTTP server for seeding the flow
	normalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(normalServer.Close)

	configDir := t.TempDir()
	backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	// Seed with normal request
	proxyURL, _ := url.Parse("http://" + backend.Addr())
	proxyClient := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := proxyClient.Get(normalServer.URL + "/malformed-test")
	require.NoError(t, err)
	_ = resp.Body.Close()

	testutil.WaitForCount(t, func() int {
		history, _ := backend.GetProxyHistory(t.Context(), 1, 0)
		return len(history)
	}, 1)

	client := startMCPServerAndClient(t, backendNative, backend)

	listResp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
		OutputMode: "flows",
		Path:       "/malformed-test",
		Limit:      1,
	})
	require.NoError(t, err)
	require.Len(t, listResp.Flows, 1)

	flowID := listResp.Flows[0].FlowID

	t.Run("invalid_method_with_space_rejected_without_force", func(t *testing.T) {
		// Method with space should fail validation
		_, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID: flowID,
			Method: "GET POST", // Invalid: contains space
			Target: "http://" + tcpAddr,
			Force:  false,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})

	t.Run("invalid_method_with_space_sent_with_force", func(t *testing.T) {
		// Clear channel
		for len(receivedData) > 0 {
			<-receivedData
		}

		// With force=true, validation is bypassed and request is sent
		replayResp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID: flowID,
			Method: "GET POST", // Invalid method with space
			Target: "http://" + tcpAddr,
			Force:  true,
		})
		require.NoError(t, err)
		assert.Equal(t, 200, replayResp.Status)

		select {
		case data := <-receivedData:
			// Verify the raw request contains the malformed method
			assert.True(t, bytes.HasPrefix(data, []byte("GET POST ")),
				"request should start with 'GET POST', got: %s", string(data[:min(50, len(data))]))
		case <-time.After(2 * time.Second):
			t.Fatal("didn't receive request")
		}
	})

	t.Run("header_with_nul_byte_rejected_without_force", func(t *testing.T) {
		// Header with NUL byte should fail validation
		_, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID:     flowID,
			AddHeaders: []string{"X-Evil: value\x00injected"},
			Target:     "http://" + tcpAddr,
			Force:      false,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})

	t.Run("header_with_nul_byte_sent_with_force", func(t *testing.T) {
		// Clear channel
		for len(receivedData) > 0 {
			<-receivedData
		}

		// With force=true, NUL byte validation is bypassed
		replayResp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID:     flowID,
			AddHeaders: []string{"X-Evil: value\x00injected"},
			Target:     "http://" + tcpAddr,
			Force:      true,
		})
		require.NoError(t, err)
		assert.Equal(t, 200, replayResp.Status)

		select {
		case data := <-receivedData:
			// Verify the raw request contains the header with NUL byte
			assert.Contains(t, string(data), "X-Evil: value\x00injected",
				"request should contain header with NUL byte")
		case <-time.After(2 * time.Second):
			t.Fatal("didn't receive request")
		}
	})

	t.Run("special_chars_in_method_rejected_without_force", func(t *testing.T) {
		// Method with tab character should fail
		_, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID: flowID,
			Method: "GET\tPOST",
			Target: "http://" + tcpAddr,
			Force:  false,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})

	t.Run("special_chars_in_method_sent_with_force", func(t *testing.T) {
		// Clear channel
		for len(receivedData) > 0 {
			<-receivedData
		}

		// With force=true, special chars are allowed
		replayResp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID: flowID,
			Method: "GET\tPOST",
			Target: "http://" + tcpAddr,
			Force:  true,
		})
		require.NoError(t, err)
		assert.Equal(t, 200, replayResp.Status)

		select {
		case data := <-receivedData:
			// Verify the raw request contains the method with tab
			assert.True(t, bytes.HasPrefix(data, []byte("GET\tPOST ")),
				"request should start with 'GET<tab>POST', got: %q", string(data[:min(50, len(data))]))
		case <-time.After(2 * time.Second):
			t.Fatal("didn't receive request")
		}
	})

	t.Run("unusual_http_methods_sent_to_raw_server", func(t *testing.T) {
		// Test various unusual but technically valid HTTP methods
		unusualMethods := []string{"PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}

		for _, method := range unusualMethods {
			// Clear channel
			for len(receivedData) > 0 {
				<-receivedData
			}

			replayResp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID: flowID,
				Method: method,
				Target: "http://" + tcpAddr,
				Force:  true,
			})
			require.NoError(t, err, "method %s should work with force", method)
			assert.Equal(t, 200, replayResp.Status, "method %s should succeed", method)

			select {
			case data := <-receivedData:
				assert.True(t, bytes.HasPrefix(data, []byte(method+" ")),
					"request should start with '%s ', got: %s", method, string(data[:min(50, len(data))]))
			case <-time.After(2 * time.Second):
				t.Fatalf("didn't receive request for method %s", method)
			}
		}
	})
}

// TestIntegration_ContentLengthMismatch tests handling of requests where Content-Length
// doesn't match the actual body size. This is important for security testing scenarios.
func TestIntegration_ContentLengthMismatch(t *testing.T) {
	t.Parallel()

	// Raw TCP server to capture exact bytes received
	receivedData := make(chan []byte, 10)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	tcpAddr := listener.Addr().String()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()

				buf := make([]byte, 8192)
				n, err := c.Read(buf)
				if err != nil {
					return
				}

				select {
				case receivedData <- buf[:n]:
				default:
				}

				response := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
				_, _ = c.Write([]byte(response))
			}(conn)
		}
	}()

	// Normal server for seeding
	normalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(normalServer.Close)

	configDir := t.TempDir()
	backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	// Seed with normal request
	proxyURL, _ := url.Parse("http://" + backend.Addr())
	proxyClient := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}
	resp, err := proxyClient.Post(normalServer.URL+"/cl-test", "text/plain",
		strings.NewReader("original body"))
	require.NoError(t, err)
	_ = resp.Body.Close()

	testutil.WaitForCount(t, func() int {
		history, _ := backend.GetProxyHistory(t.Context(), 1, 0)
		return len(history)
	}, 1)

	client := startMCPServerAndClient(t, backendNative, backend)

	listResp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
		OutputMode: "flows",
		Path:       "/cl-test",
		Limit:      1,
	})
	require.NoError(t, err)
	require.Len(t, listResp.Flows, 1)

	flowID := listResp.Flows[0].FlowID

	t.Run("content_length_less_than_body_rejected", func(t *testing.T) {
		// Content-Length says 5, but body is longer - should be rejected
		_, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID:     flowID,
			Body:       "this is a much longer body than content-length says",
			AddHeaders: []string{"Content-Length: 5"},
			Target:     "http://" + tcpAddr,
			Force:      false,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})

	t.Run("content_length_mismatch_sent_with_force", func(t *testing.T) {
		for len(receivedData) > 0 {
			<-receivedData
		}

		// With force, Content-Length mismatch is allowed
		replayResp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID:     flowID,
			Body:       "actual body content here",
			AddHeaders: []string{"Content-Length: 5"},
			Target:     "http://" + tcpAddr,
			Force:      true,
		})
		require.NoError(t, err)
		assert.Equal(t, 200, replayResp.Status)

		select {
		case data := <-receivedData:
			// Verify Content-Length header says 5
			assert.Contains(t, string(data), "Content-Length: 5")
			// But actual body is longer
			assert.Contains(t, string(data), "actual body content here")
		case <-time.After(2 * time.Second):
			t.Fatal("didn't receive request")
		}
	})

	t.Run("content_length_greater_than_body_rejected", func(t *testing.T) {
		// Content-Length says 1000, but body is only 10 bytes
		_, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID:     flowID,
			Body:       "short body",
			AddHeaders: []string{"Content-Length: 1000"},
			Target:     "http://" + tcpAddr,
			Force:      false,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})

	t.Run("zero_content_length_with_body_sent_with_force", func(t *testing.T) {
		for len(receivedData) > 0 {
			<-receivedData
		}

		// Content-Length: 0 but there's a body - useful for request smuggling tests
		replayResp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID:     flowID,
			Body:       "hidden body",
			AddHeaders: []string{"Content-Length: 0"},
			Target:     "http://" + tcpAddr,
			Force:      true,
		})
		require.NoError(t, err)
		assert.Equal(t, 200, replayResp.Status)

		select {
		case data := <-receivedData:
			assert.Contains(t, string(data), "Content-Length: 0")
			assert.Contains(t, string(data), "hidden body")
		case <-time.After(2 * time.Second):
			t.Fatal("didn't receive request")
		}
	})
}

func TestIntegration_LargeBodies(t *testing.T) {
	const bodySize = 1024 * 1024 // 1MB
	largeBody := strings.Repeat("X", bodySize)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Body-Size", strconv.Itoa(len(body)))
		w.WriteHeader(200)
		_, _ = w.Write([]byte(largeBody))
	})

	runForAllBackendsWithHandler(t, handler, func(t *testing.T, env *testEnv) {
		t.Helper()
		client := makeProxyClient(env.proxyAddr)

		t.Run("large_request_body", func(t *testing.T) {
			resp, err := client.Post(env.targetURL+"/large-req", "application/octet-stream",
				strings.NewReader(largeBody))
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()

			assert.Equal(t, 200, resp.StatusCode)
			assert.Equal(t, strconv.Itoa(bodySize), resp.Header.Get("X-Body-Size"))
		})

		t.Run("large_response_body", func(t *testing.T) {
			resp, err := client.Get(env.targetURL + "/large-resp")
			require.NoError(t, err)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			assert.Equal(t, 200, resp.StatusCode)
			assert.Len(t, body, bodySize)
		})
	})
}

func TestIntegration_BinaryContent(t *testing.T) {
	// Create binary data with all byte values
	binaryData := make([]byte, 256)
	for i := range binaryData {
		binaryData[i] = byte(i)
	}

	receivedData := make(chan []byte, 1)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case receivedData <- body:
		default:
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		_, _ = w.Write(binaryData)
	})

	runForAllBackendsWithHandler(t, handler, func(t *testing.T, env *testEnv) {
		t.Helper()
		client := makeProxyClient(env.proxyAddr)

		t.Run("binary_request_body", func(t *testing.T) {
			// Drain channel from any previous test runs
			for len(receivedData) > 0 {
				<-receivedData
			}

			resp, err := client.Post(env.targetURL+"/binary", "application/octet-stream",
				strings.NewReader(string(binaryData)))
			require.NoError(t, err)
			_ = resp.Body.Close()

			select {
			case received := <-receivedData:
				assert.Equal(t, binaryData, received)
			case <-time.After(2 * time.Second):
				t.Fatal("didn't receive request")
			}
		})

		t.Run("binary_response_body", func(t *testing.T) {
			resp, err := client.Get(env.targetURL + "/binary-resp")
			require.NoError(t, err)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			assert.Equal(t, binaryData, body)
		})
	})
}

func TestIntegration_ConnectionErrors(t *testing.T) {
	t.Parallel()

	configDir := t.TempDir()
	backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	proxyURL, _ := url.Parse("http://" + backend.Addr())
	proxyClient := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   2 * time.Second,
	}

	t.Run("connection_refused", func(t *testing.T) {
		// Connect to a port that's not listening
		// Proxy returns 502 Bad Gateway for connection errors
		resp, err := proxyClient.Get("http://127.0.0.1:1/should-fail")
		if err != nil {
			// Client error is acceptable
			return
		}
		defer func() { _ = resp.Body.Close() }()
		// Proxy should return an error status (5xx)
		assert.GreaterOrEqual(t, resp.StatusCode, 500, "proxy should return error status for connection refused")
	})

	t.Run("dns_failure", func(t *testing.T) {
		resp, err := proxyClient.Get("http://this-domain-should-not-exist-xyz123.invalid/test")
		if err != nil {
			// Client error is acceptable
			return
		}
		defer func() { _ = resp.Body.Close() }()
		// Proxy should return an error status (5xx)
		assert.GreaterOrEqual(t, resp.StatusCode, 500, "proxy should return error status for DNS failure")
	})
}

func TestIntegration_TimeoutHandling(t *testing.T) {
	t.Parallel()

	// Create slow server (delay just needs to exceed client timeout of 500ms)
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second)
		w.WriteHeader(200)
	}))
	t.Cleanup(testServer.Close)

	configDir := t.TempDir()
	backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	proxyURL, _ := url.Parse("http://" + backend.Addr())
	proxyClient := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   500 * time.Millisecond,
	}

	t.Run("client_timeout", func(t *testing.T) {
		_, err := proxyClient.Get(testServer.URL + "/slow")
		require.Error(t, err)
		// Should be a timeout error
		assert.True(t, strings.Contains(err.Error(), "timeout") ||
			strings.Contains(err.Error(), "deadline") ||
			strings.Contains(err.Error(), "canceled"))
	})
}

func computeWebSocketAcceptKey(key string) string {
	const magicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

type wsFrame struct {
	fin     bool
	opcode  byte
	payload []byte
}

func readWebSocketFrame(conn net.Conn) (*wsFrame, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	fin := header[0]&0x80 != 0
	opcode := header[0] & 0x0F
	masked := header[1]&0x80 != 0
	payloadLen := int(header[1] & 0x7F)

	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, err
		}
		payloadLen = int(ext[0])<<8 | int(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, err
		}
		payloadLen = int(ext[4])<<24 | int(ext[5])<<16 | int(ext[6])<<8 | int(ext[7])
	}

	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(conn, mask[:]); err != nil {
			return nil, err
		}
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}

	return &wsFrame{fin: fin, opcode: opcode, payload: payload}, nil
}

func encodeWebSocketFrame(payload []byte, opcode byte, masked bool) []byte {
	var frame []byte
	frame = append(frame, 0x80|opcode) // FIN + opcode

	payloadLen := len(payload)
	var mask [4]byte

	if masked {
		// Generate random mask
		mask = [4]byte{0x12, 0x34, 0x56, 0x78}
	}

	if payloadLen < 126 {
		lenByte := byte(payloadLen)
		if masked {
			lenByte |= 0x80
		}
		frame = append(frame, lenByte)
	} else if payloadLen < 65536 {
		lenByte := byte(126)
		if masked {
			lenByte |= 0x80
		}
		frame = append(frame, lenByte, byte(payloadLen>>8), byte(payloadLen))
	} else {
		lenByte := byte(127)
		if masked {
			lenByte |= 0x80
		}
		frame = append(frame, lenByte, 0, 0, 0, 0,
			byte(payloadLen>>24), byte(payloadLen>>16), byte(payloadLen>>8), byte(payloadLen))
	}

	if masked {
		frame = append(frame, mask[:]...)
		maskedPayload := make([]byte, payloadLen)
		for i := range payload {
			maskedPayload[i] = payload[i] ^ mask[i%4]
		}
		frame = append(frame, maskedPayload...)
	} else {
		frame = append(frame, payload...)
	}

	return frame
}

func TestIntegration_ReplayPathModification(t *testing.T) {
	receivedPath := make(chan string, 10)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case receivedPath <- r.URL.Path:
		default:
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("path: " + r.URL.Path))
	})

	runForAllBackendsWithHandler(t, handler, func(t *testing.T, env *testEnv) {
		t.Helper()
		client := makeProxyClient(env.proxyAddr)
		resp, err := client.Get(env.targetURL + "/original-path")
		require.NoError(t, err)
		_ = resp.Body.Close()

		select {
		case <-receivedPath:
		case <-time.After(2 * time.Second):
			t.Fatal("didn't receive initial request")
		}

		targetURL, _ := url.Parse(env.targetURL)
		listResp, err := env.mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
			OutputMode: "flows",
			Host:       targetURL.Host,
			Path:       "/original-path",
			Limit:      1,
		})
		require.NoError(t, err)
		require.Len(t, listResp.Flows, 1)

		flowID := listResp.Flows[0].FlowID

		t.Run("path_modification_works", func(t *testing.T) {
			for len(receivedPath) > 0 {
				<-receivedPath
			}

			replayResp, err := env.mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID: flowID,
				Path:   "/modified-path",
			})
			require.NoError(t, err)
			assert.Equal(t, 200, replayResp.Status)

			select {
			case path := <-receivedPath:
				assert.Equal(t, "/modified-path", path)
			case <-time.After(2 * time.Second):
				t.Fatal("didn't receive replayed request")
			}
		})

		t.Run("path_with_query_preserved", func(t *testing.T) {
			for len(receivedPath) > 0 {
				<-receivedPath
			}

			replayResp, err := env.mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID:   flowID,
				Path:     "/new-path",
				SetQuery: []string{"param=value"},
			})
			require.NoError(t, err)
			assert.Equal(t, 200, replayResp.Status)

			select {
			case path := <-receivedPath:
				assert.Equal(t, "/new-path", path)
			case <-time.After(2 * time.Second):
				t.Fatal("didn't receive replayed request")
			}
		})
	})
}

func TestIntegration_WebSocketRules(t *testing.T) {
	t.Parallel()

	// Channel to capture messages received by server
	serverReceived := make(chan string, 100)

	// Server that echoes messages with SERVER_SECRET prefix
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != wsUpgradeHeader {
			w.WriteHeader(400)
			return
		}

		key := r.Header.Get("Sec-WebSocket-Key")
		acceptKey := computeWebSocketAcceptKey(key)

		w.Header().Set("Upgrade", wsUpgradeHeader)
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", acceptKey)
		w.WriteHeader(101)

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, bufrw, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = bufrw.Flush()

		// Echo loop - receive message and send back with SERVER_SECRET
		for {
			frame, err := readWebSocketFrame(conn)
			if err != nil {
				return
			}
			if frame.opcode == 8 { // close
				return
			}
			if frame.opcode == 1 { // text
				serverReceived <- string(frame.payload)
				// Echo back with SERVER_SECRET prefix (this will be modified by to-client rule)
				response := "SERVER_SECRET: " + string(frame.payload)
				responseFrame := encodeWebSocketFrame([]byte(response), 1, false)
				_, _ = conn.Write(responseFrame)
			}
		}
	}))
	t.Cleanup(testServer.Close)

	configDir := t.TempDir()
	backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	mcpClient := startMCPServerAndClient(t, backendNative, backend)

	t.Run("ws_to_server_rule_modifies_client_message", func(t *testing.T) {
		// Add rule to modify client→server messages
		rule, err := mcpClient.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
			Type:    service.RuleTypeWSToServer,
			Label:   "test-ws-to-server",
			Match:   "CLIENT_SECRET",
			Replace: "CLIENT_MODIFIED",
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = mcpClient.ProxyRuleDelete(context.Background(), rule.RuleID) })

		// Drain any existing messages
		for len(serverReceived) > 0 {
			<-serverReceived
		}

		// Connect through proxy
		proxyAddr := backend.Addr()
		conn, err := net.Dial("tcp", proxyAddr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		serverURL, _ := url.Parse(testServer.URL)

		// WebSocket handshake
		wsKey := base64.StdEncoding.EncodeToString([]byte("test-ws-key-rule1"))
		req := fmt.Sprintf(
			"GET /ws-rule-test HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Key: %s\r\n"+
				"Sec-WebSocket-Version: 13\r\n"+
				"\r\n",
			serverURL.Host, wsKey)

		_, err = conn.Write([]byte(req))
		require.NoError(t, err)

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, 101, resp.StatusCode)

		// Send message with CLIENT_SECRET
		message := "Hello CLIENT_SECRET World"
		frame := encodeWebSocketFrame([]byte(message), 1, true)
		_, err = conn.Write(frame)
		require.NoError(t, err)

		// Verify server received modified message
		select {
		case received := <-serverReceived:
			assert.Contains(t, received, "CLIENT_MODIFIED")
			assert.NotContains(t, received, "CLIENT_SECRET")
		case <-time.After(2 * time.Second):
			t.Fatal("server didn't receive message")
		}
		assert.Empty(t, serverReceived)
	})

	t.Run("ws_to_client_rule_modifies_server_message", func(t *testing.T) {
		// Add rule to modify server→client messages
		rule, err := mcpClient.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
			Type:    service.RuleTypeWSToClient,
			Label:   "test-ws-to-client",
			Match:   "SERVER_SECRET",
			Replace: "SERVER_MODIFIED",
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = mcpClient.ProxyRuleDelete(context.Background(), rule.RuleID) })

		// Connect through proxy
		proxyAddr := backend.Addr()
		conn, err := net.Dial("tcp", proxyAddr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		serverURL, _ := url.Parse(testServer.URL)

		wsKey := base64.StdEncoding.EncodeToString([]byte("test-ws-key-rule2"))
		req := fmt.Sprintf(
			"GET /ws-rule-test2 HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Key: %s\r\n"+
				"Sec-WebSocket-Version: 13\r\n"+
				"\r\n",
			serverURL.Host, wsKey)

		_, err = conn.Write([]byte(req))
		require.NoError(t, err)

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, 101, resp.StatusCode)

		// Send a message to trigger echo response (server will prefix with SERVER_SECRET)
		triggerMsg := "trigger echo"
		frame := encodeWebSocketFrame([]byte(triggerMsg), 1, true)
		_, err = conn.Write(frame)
		require.NoError(t, err)

		// Read frame from client side (through proxy) - server echoes with SERVER_SECRET prefix
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		receivedFrame, err := readWebSocketFrame(conn)
		require.NoError(t, err)

		// Verify the message was modified by the rule (SERVER_SECRET -> SERVER_MODIFIED)
		assert.Contains(t, string(receivedFrame.payload), "SERVER_MODIFIED")
		assert.NotContains(t, string(receivedFrame.payload), "SERVER_SECRET")
	})
}

func TestIntegration_Redirect307BodyPreservation(t *testing.T) {
	receivedBody := make(chan []byte, 10)
	receivedMethod := make(chan string, 10)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect-307":
			http.Redirect(w, r, "/final-307", http.StatusTemporaryRedirect)
		case "/redirect-308":
			http.Redirect(w, r, "/final-308", http.StatusPermanentRedirect)
		case "/final-307", "/final-308":
			body, _ := io.ReadAll(r.Body)
			select {
			case receivedBody <- body:
			default:
			}
			select {
			case receivedMethod <- r.Method:
			default:
			}
			w.WriteHeader(200)
			_, _ = w.Write([]byte("received"))
		default:
			w.WriteHeader(404)
		}
	})

	runForAllBackendsWithHandler(t, handler, func(t *testing.T, env *testEnv) {
		t.Helper()
		// Seed with POST request (don't follow redirects when seeding)
		proxyURL, _ := url.Parse("http://" + env.proxyAddr)
		proxyClient := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		resp, err := proxyClient.Post(env.targetURL+"/redirect-307", "application/json",
			strings.NewReader(`{"important":"data"}`))
		require.NoError(t, err)
		_ = resp.Body.Close()

		resp, err = proxyClient.Post(env.targetURL+"/redirect-308", "application/json",
			strings.NewReader(`{"critical":"payload"}`))
		require.NoError(t, err)
		_ = resp.Body.Close()

		testutil.WaitForCount(t, func() int {
			history, _ := env.backend.GetProxyHistory(t.Context(), 1, 0)
			return len(history)
		}, 1)

		targetURL, _ := url.Parse(env.targetURL)

		t.Run("307_preserves_method_and_body", func(t *testing.T) {
			listResp, err := env.mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
				OutputMode: "flows",
				Host:       targetURL.Host,
				Path:       "/redirect-307",
				Limit:      1,
			})
			require.NoError(t, err)
			require.Len(t, listResp.Flows, 1)

			flowID := listResp.Flows[0].FlowID

			for len(receivedBody) > 0 {
				<-receivedBody
			}
			for len(receivedMethod) > 0 {
				<-receivedMethod
			}

			replayResp, err := env.mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID:          flowID,
				FollowRedirects: true,
			})
			require.NoError(t, err)
			assert.Equal(t, 200, replayResp.Status)

			select {
			case method := <-receivedMethod:
				assert.Equal(t, "POST", method, "307 should preserve POST method")
			case <-time.After(2 * time.Second):
				t.Fatal("didn't receive request")
			}

			select {
			case body := <-receivedBody:
				assert.Contains(t, string(body), "important")
			case <-time.After(2 * time.Second):
				t.Fatal("didn't receive body")
			}
		})

		t.Run("308_preserves_method_and_body", func(t *testing.T) {
			listResp, err := env.mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
				OutputMode: "flows",
				Host:       targetURL.Host,
				Path:       "/redirect-308",
				Limit:      1,
			})
			require.NoError(t, err)
			require.Len(t, listResp.Flows, 1)

			flowID := listResp.Flows[0].FlowID

			for len(receivedBody) > 0 {
				<-receivedBody
			}
			for len(receivedMethod) > 0 {
				<-receivedMethod
			}

			replayResp, err := env.mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID:          flowID,
				FollowRedirects: true,
			})
			require.NoError(t, err)
			assert.Equal(t, 200, replayResp.Status)

			select {
			case method := <-receivedMethod:
				assert.Equal(t, "POST", method, "308 should preserve POST method")
			case <-time.After(2 * time.Second):
				t.Fatal("didn't receive request")
			}

			select {
			case body := <-receivedBody:
				assert.Contains(t, string(body), "critical")
			case <-time.After(2 * time.Second):
				t.Fatal("didn't receive body")
			}
		})
	})
}

// TestIntegration_CrossOriginRedirectAuthPreserved tests that Authorization headers are preserved on cross-origin redirects.
func TestIntegration_CrossOriginRedirectAuthPreserved(t *testing.T) {
	receivedAuth := make(chan string, 10)

	// Create target server that captures Authorization header
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case receivedAuth <- r.Header.Get("Authorization"):
		default:
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("final"))
	}))
	t.Cleanup(targetServer.Close)

	// Create origin server that redirects to target (cross-origin)
	originHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetServer.URL+"/cross-origin-target", http.StatusFound)
	})

	runForAllBackendsWithHandler(t, originHandler, func(t *testing.T, env *testEnv) {
		t.Helper()

		// Seed with request containing Authorization header (don't follow redirect)
		proxyURL, _ := url.Parse("http://" + env.proxyAddr)
		proxyClient := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		req, _ := http.NewRequest("GET", env.targetURL+"/start", nil)
		req.Header.Set("Authorization", "Bearer secret-token-12345")
		resp, err := proxyClient.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()

		testutil.WaitForCount(t, func() int {
			history, _ := env.backend.GetProxyHistory(t.Context(), 1, 0)
			return len(history)
		}, 1)

		originURL, _ := url.Parse(env.targetURL)
		listResp, err := env.mcpClient.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
			OutputMode: "flows",
			Host:       originURL.Host,
			Path:       "/start",
			Limit:      1,
		})
		require.NoError(t, err)
		require.Len(t, listResp.Flows, 1)

		flowID := listResp.Flows[0].FlowID

		t.Run("authorization_preserved", func(t *testing.T) {
			for len(receivedAuth) > 0 {
				<-receivedAuth
			}

			replayResp, err := env.mcpClient.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
				FlowID:          flowID,
				FollowRedirects: true,
			})
			require.NoError(t, err)
			assert.Equal(t, 200, replayResp.Status)

			select {
			case auth := <-receivedAuth:
				assert.Equal(t, "Bearer secret-token-12345", auth, "Authorization header should be preserved on cross-origin redirect")
			case <-time.After(2 * time.Second):
				t.Fatal("didn't receive request at target server")
			}
		})
	})
}

func TestIntegration_SecureWebSocket(t *testing.T) {
	t.Parallel()

	wsMessages := make(chan string, 100)

	// Create TLS WebSocket server
	testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != wsUpgradeHeader {
			w.WriteHeader(400)
			return
		}

		key := r.Header.Get("Sec-WebSocket-Key")
		acceptKey := computeWebSocketAcceptKey(key)

		w.Header().Set("Upgrade", wsUpgradeHeader)
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", acceptKey)
		w.WriteHeader(101)

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, bufrw, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = bufrw.Flush()

		for {
			frame, err := readWebSocketFrame(conn)
			if err != nil {
				return
			}
			if frame.opcode == 8 {
				return
			}
			if frame.opcode == 1 {
				wsMessages <- string(frame.payload)
				responseFrame := encodeWebSocketFrame(frame.payload, 1, false)
				_, _ = conn.Write(responseFrame)
			}
		}
	}))
	testServer.TLS = &tls.Config{
		NextProtos: []string{"http/1.1"},
	}
	testServer.StartTLS()
	t.Cleanup(testServer.Close)

	configDir := t.TempDir()
	backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	// Get proxy CA cert for trust
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(backend.CACert())

	t.Run("wss_upgrade_through_proxy", func(t *testing.T) {
		// For wss://, we need to CONNECT first, then do TLS, then WebSocket
		proxyAddr := backend.Addr()
		conn, err := net.Dial("tcp", proxyAddr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		serverURL, _ := url.Parse(testServer.URL)

		// Send CONNECT request
		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
			serverURL.Host, serverURL.Host)
		_, err = conn.Write([]byte(connectReq))
		require.NoError(t, err)

		// Read CONNECT response
		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, 200, resp.StatusCode)

		// Upgrade to TLS
		tlsConn := tls.Client(conn, &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
			ServerName:         serverURL.Hostname(),
		})
		err = tlsConn.Handshake()
		require.NoError(t, err)

		// Now do WebSocket upgrade over TLS
		wsKey := base64.StdEncoding.EncodeToString([]byte("test-wss-key-123"))
		wsReq := fmt.Sprintf(
			"GET /wss-test HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Key: %s\r\n"+
				"Sec-WebSocket-Version: 13\r\n"+
				"\r\n",
			serverURL.Host, wsKey)

		_, err = tlsConn.Write([]byte(wsReq))
		require.NoError(t, err)

		tlsReader := bufio.NewReader(tlsConn)
		wsResp, err := http.ReadResponse(tlsReader, nil)
		require.NoError(t, err)
		defer func() { _ = wsResp.Body.Close() }()

		assert.Equal(t, 101, wsResp.StatusCode)
		assert.Equal(t, wsUpgradeHeader, strings.ToLower(wsResp.Header.Get("Upgrade")))

		// Send a text frame
		message := "Hello Secure WebSocket!"
		frame := encodeWebSocketFrame([]byte(message), 1, true)
		_, err = tlsConn.Write(frame)
		require.NoError(t, err)

		// Verify message received
		select {
		case received := <-wsMessages:
			assert.Equal(t, message, received)
		case <-time.After(2 * time.Second):
			t.Fatal("wss message not received")
		}

		// Read echo response
		_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		responseFrame, err := readWebSocketFrame(tlsConn)
		require.NoError(t, err)
		assert.Equal(t, message, string(responseFrame.payload))
	})
}

func TestIntegration_HTTP2Replay(t *testing.T) {
	t.Parallel()

	receivedProto := make(chan string, 10)
	receivedPath := make(chan string, 10)

	// Create HTTP/2 enabled test server
	testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case receivedProto <- r.Proto:
		default:
		}
		select {
		case receivedPath <- r.URL.Path:
		default:
		}
		w.Header().Set("X-Protocol", r.Proto)
		w.WriteHeader(200)
		_, _ = w.Write([]byte("H2 response"))
	}))
	testServer.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	testServer.StartTLS()
	t.Cleanup(testServer.Close)

	configDir := t.TempDir()
	backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(backend.CACert())

	// Make H2 request through proxy to seed history
	proxyURL, _ := url.Parse("http://" + backend.Addr())
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	}
	proxyClient := &http.Client{Transport: transport}

	resp, err := proxyClient.Get(testServer.URL + "/h2-replay-test")
	require.NoError(t, err)
	_ = resp.Body.Close()

	// Drain initial
	<-receivedProto
	<-receivedPath

	testutil.WaitForCount(t, func() int {
		history, _ := backend.GetProxyHistory(t.Context(), 1, 0)
		return len(history)
	}, 1)

	client := startMCPServerAndClient(t, backendNative, backend)

	listResp, err := client.ProxyPoll(t.Context(), mcpclient.ProxyPollOpts{
		OutputMode: "flows",
		Path:       "/h2-replay-test",
		Limit:      1,
	})
	require.NoError(t, err)
	require.Len(t, listResp.Flows, 1)

	flowID := listResp.Flows[0].FlowID

	// Get full flow details to get the target URL
	flowDetails, err := client.ProxyGet(t.Context(), flowID, mcpclient.ProxyGetOpts{})
	require.NoError(t, err)

	t.Run("h2_request_replayed_as_h2", func(t *testing.T) {
		for len(receivedProto) > 0 {
			<-receivedProto
		}
		for len(receivedPath) > 0 {
			<-receivedPath
		}

		// Replay the H2 request - should use H2 protocol
		replayResp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID: flowID,
			Target: flowDetails.URL,
		})
		require.NoError(t, err)
		assert.Equal(t, 200, replayResp.Status)

		// Verify request was received with correct path
		select {
		case path := <-receivedPath:
			assert.Equal(t, "/h2-replay-test", path)
		case <-time.After(2 * time.Second):
			t.Fatal("didn't receive replayed request")
		}

		// Verify H2 protocol was used for replay
		select {
		case proto := <-receivedProto:
			assert.Equal(t, "HTTP/2.0", proto)
		case <-time.After(2 * time.Second):
			t.Fatal("didn't receive protocol info")
		}
	})

	t.Run("h2_replay_with_modifications", func(t *testing.T) {
		for len(receivedPath) > 0 {
			<-receivedPath
		}

		// Replay with path modification
		replayResp, err := client.ReplaySend(t.Context(), mcpclient.ReplaySendOpts{
			FlowID: flowID,
			Target: flowDetails.URL,
			Path:   "/h2-modified-path",
		})
		require.NoError(t, err)
		assert.Equal(t, 200, replayResp.Status)

		select {
		case path := <-receivedPath:
			assert.Equal(t, "/h2-modified-path", path)
		case <-time.After(2 * time.Second):
			t.Fatal("didn't receive modified request")
		}
	})
}

func TestIntegration_WebSocketBinaryFrames(t *testing.T) {
	t.Parallel()

	// Channel to capture binary messages received by server
	wsBinaryMessages := make(chan []byte, 100)

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != wsUpgradeHeader {
			w.WriteHeader(400)
			return
		}

		key := r.Header.Get("Sec-WebSocket-Key")
		acceptKey := computeWebSocketAcceptKey(key)

		w.Header().Set("Upgrade", wsUpgradeHeader)
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", acceptKey)
		w.WriteHeader(101)

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, bufrw, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = bufrw.Flush()

		// Echo loop for binary frames
		for {
			frame, err := readWebSocketFrame(conn)
			if err != nil {
				return
			}

			if frame.opcode == 8 { // close
				return
			}

			if frame.opcode == 2 { // binary
				wsBinaryMessages <- frame.payload
				// Echo back as binary
				responseFrame := encodeWebSocketFrame(frame.payload, 2, false)
				_, _ = conn.Write(responseFrame)
			}
		}
	}))
	t.Cleanup(testServer.Close)

	configDir := t.TempDir()
	backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	t.Run("binary_frame_through_proxy", func(t *testing.T) {
		proxyAddr := backend.Addr()
		conn, err := net.Dial("tcp", proxyAddr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		serverURL, _ := url.Parse(testServer.URL)

		wsKey := base64.StdEncoding.EncodeToString([]byte("test-ws-binary-key"))
		req := fmt.Sprintf(
			"GET /ws-binary HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Key: %s\r\n"+
				"Sec-WebSocket-Version: 13\r\n"+
				"\r\n",
			serverURL.Host, wsKey)

		_, err = conn.Write([]byte(req))
		require.NoError(t, err)

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 101, resp.StatusCode)

		// Send a binary frame with all byte values 0-255
		binaryData := make([]byte, 256)
		for i := range binaryData {
			binaryData[i] = byte(i)
		}
		frame := encodeWebSocketFrame(binaryData, 2, true) // opcode 2 = binary, masked
		_, err = conn.Write(frame)
		require.NoError(t, err)

		// Verify message was received by server
		select {
		case received := <-wsBinaryMessages:
			assert.Equal(t, binaryData, received)
		case <-time.After(2 * time.Second):
			t.Fatal("binary WebSocket message not received")
		}
		assert.Empty(t, wsBinaryMessages)

		// Read echo response
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		responseFrame, err := readWebSocketFrame(conn)
		require.NoError(t, err)
		assert.Equal(t, byte(2), responseFrame.opcode)
		assert.Equal(t, binaryData, responseFrame.payload)
	})
}

func TestIntegration_WebSocketPingPong(t *testing.T) {
	t.Parallel()

	// Channel to capture ping messages received by server
	wsPings := make(chan []byte, 100)

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != wsUpgradeHeader {
			w.WriteHeader(400)
			return
		}

		key := r.Header.Get("Sec-WebSocket-Key")
		acceptKey := computeWebSocketAcceptKey(key)

		w.Header().Set("Upgrade", wsUpgradeHeader)
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", acceptKey)
		w.WriteHeader(101)

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			return
		}
		conn, bufrw, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = bufrw.Flush()

		for {
			frame, err := readWebSocketFrame(conn)
			if err != nil {
				return
			}

			switch frame.opcode {
			case 8: // close
				return
			case 9: // ping
				wsPings <- frame.payload
				// Respond with pong (opcode 10) with same payload
				pongFrame := encodeWebSocketFrame(frame.payload, 10, false)
				_, _ = conn.Write(pongFrame)
			case 1: // text - echo back
				responseFrame := encodeWebSocketFrame(frame.payload, 1, false)
				_, _ = conn.Write(responseFrame)
			}
		}
	}))
	t.Cleanup(testServer.Close)

	configDir := t.TempDir()
	backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	go func() { _ = backend.Serve() }()
	require.NoError(t, backend.WaitReady(t.Context()))

	t.Run("ping_pong_through_proxy", func(t *testing.T) {
		proxyAddr := backend.Addr()
		conn, err := net.Dial("tcp", proxyAddr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		serverURL, _ := url.Parse(testServer.URL)

		wsKey := base64.StdEncoding.EncodeToString([]byte("test-ws-ping-key1"))
		req := fmt.Sprintf(
			"GET /ws-ping HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Key: %s\r\n"+
				"Sec-WebSocket-Version: 13\r\n"+
				"\r\n",
			serverURL.Host, wsKey)

		_, err = conn.Write([]byte(req))
		require.NoError(t, err)

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 101, resp.StatusCode)

		// Send a ping frame (opcode 9)
		pingPayload := []byte("ping-test-data")
		pingFrame := encodeWebSocketFrame(pingPayload, 9, true)
		_, err = conn.Write(pingFrame)
		require.NoError(t, err)

		// Verify ping was received by server
		select {
		case received := <-wsPings:
			assert.Equal(t, pingPayload, received)
		case <-time.After(2 * time.Second):
			t.Fatal("ping not received by server")
		}
		assert.Empty(t, wsPings)

		// Read pong response (opcode 10)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		pongFrame, err := readWebSocketFrame(conn)
		require.NoError(t, err)
		assert.Equal(t, byte(10), pongFrame.opcode)
		assert.Equal(t, pingPayload, pongFrame.payload)
	})

	t.Run("server_initiated_ping", func(t *testing.T) {
		proxyAddr := backend.Addr()
		conn, err := net.Dial("tcp", proxyAddr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		serverURL, _ := url.Parse(testServer.URL)

		wsKey := base64.StdEncoding.EncodeToString([]byte("test-ws-ping-key2"))
		req := fmt.Sprintf(
			"GET /ws-ping2 HTTP/1.1\r\n"+
				"Host: %s\r\n"+
				"Upgrade: websocket\r\n"+
				"Connection: Upgrade\r\n"+
				"Sec-WebSocket-Key: %s\r\n"+
				"Sec-WebSocket-Version: 13\r\n"+
				"\r\n",
			serverURL.Host, wsKey)

		_, err = conn.Write([]byte(req))
		require.NoError(t, err)

		reader := bufio.NewReader(conn)
		resp, err := http.ReadResponse(reader, nil)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		assert.Equal(t, 101, resp.StatusCode)

		// Send a text message to trigger echo (verifies connection works)
		textMsg := []byte("hello")
		textFrame := encodeWebSocketFrame(textMsg, 1, true)
		_, err = conn.Write(textFrame)
		require.NoError(t, err)

		// Read echo response
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		echoFrame, err := readWebSocketFrame(conn)
		require.NoError(t, err)
		assert.Equal(t, byte(1), echoFrame.opcode)
		assert.Equal(t, textMsg, echoFrame.payload)
	})
}

// TestIntegration_CompressedRequestBodyRule tests that proxy rules correctly
// handle compressed request bodies by decompressing, applying rules, and recompressing.
func TestIntegration_CompressedRequestBodyRule(t *testing.T) {
	t.Parallel()

	receivedBody := make(chan []byte, 10)
	receivedEncoding := make(chan string, 10)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		encoding := r.Header.Get("Content-Encoding")
		body, _ := io.ReadAll(r.Body)
		select {
		case receivedBody <- body:
		case <-time.After(100 * time.Millisecond):
		}
		select {
		case receivedEncoding <- encoding:
		case <-time.After(100 * time.Millisecond):
		}
		w.WriteHeader(200)
	})

	// Only test with native backend (Burp may handle compression differently)
	t.Run("native", func(t *testing.T) {
		configDir := t.TempDir()
		backend, err := service.NewNativeProxyBackend(0, configDir, 0, store.NewMemStorage(), store.NewMemStorage(), proxy.TimeoutConfig{})
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })

		go func() { _ = backend.Serve() }()
		require.NoError(t, backend.WaitReady(t.Context()))

		// Start test server
		testServer := httptest.NewServer(handler)
		t.Cleanup(testServer.Close)

		mcpClient := startMCPServerAndClient(t, backendNative, backend)

		t.Run("gzip_request_body_rule", func(t *testing.T) {
			label := "gzip-req-body-test-" + strconv.FormatInt(rand.Int63(), 10)
			rule, err := mcpClient.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
				Type:    service.RuleTypeRequestBody,
				Label:   label,
				Match:   "SECRET_TOKEN",
				Replace: "REDACTED",
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = mcpClient.ProxyRuleDelete(context.Background(), rule.RuleID) })

			// Drain channels
			for len(receivedBody) > 0 {
				<-receivedBody
			}
			for len(receivedEncoding) > 0 {
				<-receivedEncoding
			}

			// Create gzip-compressed body
			originalBody := []byte(`{"password":"SECRET_TOKEN","data":"test"}`)
			var buf bytes.Buffer
			gw := gzip.NewWriter(&buf)
			_, _ = gw.Write(originalBody)
			_ = gw.Close()
			compressedBody := buf.Bytes()

			// Send through proxy
			serverURL, _ := url.Parse(testServer.URL)
			proxyURL, _ := url.Parse("http://" + backend.Addr())
			client := &http.Client{
				Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			}

			req, _ := http.NewRequest("POST", testServer.URL+"/test", bytes.NewReader(compressedBody))
			req.Header.Set("Host", serverURL.Host)
			req.Header.Set("Content-Encoding", "gzip")
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			require.NoError(t, err)
			_ = resp.Body.Close()

			// Verify server received modified, recompressed body
			select {
			case body := <-receivedBody:
				encoding := <-receivedEncoding
				assert.Equal(t, "gzip", encoding, "Content-Encoding should be preserved")

				// Decompress received body
				gr, err := gzip.NewReader(bytes.NewReader(body))
				require.NoError(t, err)
				decompressed, err := io.ReadAll(gr)
				require.NoError(t, err)

				assert.Contains(t, string(decompressed), "REDACTED")
				assert.NotContains(t, string(decompressed), "SECRET_TOKEN")
			case <-time.After(2 * time.Second):
				t.Fatal("target server didn't receive request")
			}
		})

		t.Run("unsupported_encoding_skips_rules", func(t *testing.T) {
			label := "br-req-body-test-" + strconv.FormatInt(rand.Int63(), 10)
			rule, err := mcpClient.ProxyRuleAdd(t.Context(), mcpclient.RuleAddOpts{
				Type:    service.RuleTypeRequestBody,
				Label:   label,
				Match:   "SHOULD_NOT_MATCH",
				Replace: "MODIFIED",
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = mcpClient.ProxyRuleDelete(context.Background(), rule.RuleID) })

			// Drain channels
			for len(receivedBody) > 0 {
				<-receivedBody
			}
			for len(receivedEncoding) > 0 {
				<-receivedEncoding
			}

			// Create fake brotli body (just raw bytes, not real brotli)
			fakeBody := []byte("SHOULD_NOT_MATCH - raw data")

			// Send through proxy
			proxyURL, _ := url.Parse("http://" + backend.Addr())
			client := &http.Client{
				Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
			}

			req, _ := http.NewRequest("POST", testServer.URL+"/test", bytes.NewReader(fakeBody))
			req.Header.Set("Content-Encoding", "br") // unsupported
			req.Header.Set("Content-Type", "application/octet-stream")

			resp, err := client.Do(req)
			require.NoError(t, err)
			_ = resp.Body.Close()

			// Verify body passed through unchanged (rules skipped for unsupported encoding)
			select {
			case body := <-receivedBody:
				encoding := <-receivedEncoding
				assert.Equal(t, "br", encoding, "Content-Encoding should be preserved")
				// Body should be unchanged since we can't decompress brotli
				assert.Equal(t, fakeBody, body)
			case <-time.After(2 * time.Second):
				t.Fatal("target server didn't receive request")
			}
		})
	})
}

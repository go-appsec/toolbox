package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

func TestHandleDiffFlow(t *testing.T) {
	t.Parallel()

	t.Run("scopes", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		mockMCP.AddProxyEntry(
			"GET /api/v1/users?page=1 HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nAuthorization: Bearer tok1\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Request-Id: aaa\r\n\r\n"+`{"user":{"name":"alice","role":"admin","active":true},"count":10}`,
			"",
		)
		mockMCP.AddProxyEntry(
			"POST /api/v2/users?page=2&debug=true HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nX-Custom: test\r\n\r\n",
			"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nX-Request-Id: bbb\r\n\r\n"+`{"user":{"name":"alice","role":"viewer","mfa":true},"count":10}`,
			"",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"host":        "example.com",
		})
		require.Len(t, listResp.Flows, 2)

		flowA := listResp.Flows[0].FlowID
		flowB := listResp.Flows[1].FlowID

		t.Run("request", func(t *testing.T) {
			resp := CallMCPToolJSONOK[protocol.DiffFlowResponse](t, mcpClient, "diff_flow", map[string]interface{}{
				"flow_a": flowA,
				"flow_b": flowB,
				"scope":  "request",
			})

			assert.False(t, resp.Same)
			require.NotNil(t, resp.Request)
			assert.Nil(t, resp.Response)

			require.NotNil(t, resp.Request.Method)
			assert.Equal(t, "GET", resp.Request.Method.A)
			assert.Equal(t, "POST", resp.Request.Method.B)

			require.NotNil(t, resp.Request.Path)
			assert.Equal(t, "/api/v1/users", resp.Request.Path.A)
			assert.Equal(t, "/api/v2/users", resp.Request.Path.B)

			require.NotNil(t, resp.Request.Query)
			assert.NotEmpty(t, resp.Request.Query.Added)
			assert.NotEmpty(t, resp.Request.Query.Changed)

			require.NotNil(t, resp.Request.Headers)
		})

		t.Run("response", func(t *testing.T) {
			resp := CallMCPToolJSONOK[protocol.DiffFlowResponse](t, mcpClient, "diff_flow", map[string]interface{}{
				"flow_a": flowA,
				"flow_b": flowB,
				"scope":  "response",
			})

			assert.False(t, resp.Same)
			assert.Nil(t, resp.Request)
			require.NotNil(t, resp.Response)

			require.NotNil(t, resp.Response.Status)
			assert.Equal(t, 200, resp.Response.Status.A)
			assert.Equal(t, 403, resp.Response.Status.B)

			require.NotNil(t, resp.Response.Body)
			assert.Equal(t, "json", resp.Response.Body.Format)
		})

		t.Run("request_headers", func(t *testing.T) {
			resp := CallMCPToolJSONOK[protocol.DiffFlowResponse](t, mcpClient, "diff_flow", map[string]interface{}{
				"flow_a": flowA,
				"flow_b": flowB,
				"scope":  "request_headers",
			})

			assert.False(t, resp.Same)
			require.NotNil(t, resp.Request)
			assert.Nil(t, resp.Request.Body)
			require.NotNil(t, resp.Request.Headers)
		})

		t.Run("response_headers", func(t *testing.T) {
			resp := CallMCPToolJSONOK[protocol.DiffFlowResponse](t, mcpClient, "diff_flow", map[string]interface{}{
				"flow_a": flowA,
				"flow_b": flowB,
				"scope":  "response_headers",
			})

			assert.False(t, resp.Same)
			require.NotNil(t, resp.Response)
			assert.Nil(t, resp.Response.Body)
			require.NotNil(t, resp.Response.Status)
		})

		t.Run("request_body", func(t *testing.T) {
			resp := CallMCPToolJSONOK[protocol.DiffFlowResponse](t, mcpClient, "diff_flow", map[string]interface{}{
				"flow_a": flowA,
				"flow_b": flowB,
				"scope":  "request_body",
			})

			// Both requests have empty bodies
			assert.True(t, resp.Same)
		})

		t.Run("response_body", func(t *testing.T) {
			resp := CallMCPToolJSONOK[protocol.DiffFlowResponse](t, mcpClient, "diff_flow", map[string]interface{}{
				"flow_a": flowA,
				"flow_b": flowB,
				"scope":  "response_body",
			})

			assert.False(t, resp.Same)
			require.NotNil(t, resp.Response)
			require.NotNil(t, resp.Response.Body)
			assert.Equal(t, "json", resp.Response.Body.Format)
		})

		t.Run("missing_flow_a", func(t *testing.T) {
			result := CallMCPTool(t, mcpClient, "diff_flow", map[string]interface{}{
				"flow_b": flowB,
				"scope":  "request",
			})
			assert.True(t, result.IsError)
			assert.Contains(t, ExtractMCPText(t, result), "flow_a is required")
		})

		t.Run("missing_flow_b", func(t *testing.T) {
			result := CallMCPTool(t, mcpClient, "diff_flow", map[string]interface{}{
				"flow_a": flowA,
				"scope":  "request",
			})
			assert.True(t, result.IsError)
			assert.Contains(t, ExtractMCPText(t, result), "flow_b is required")
		})

		t.Run("missing_scope", func(t *testing.T) {
			result := CallMCPTool(t, mcpClient, "diff_flow", map[string]interface{}{
				"flow_a": flowA,
				"flow_b": flowB,
			})
			assert.True(t, result.IsError)
			assert.Contains(t, ExtractMCPText(t, result), "scope is required")
		})

		t.Run("flow_not_found", func(t *testing.T) {
			result := CallMCPTool(t, mcpClient, "diff_flow", map[string]interface{}{
				"flow_a": "nonexistent",
				"flow_b": flowB,
				"scope":  "request",
			})
			assert.True(t, result.IsError)
			assert.Contains(t, ExtractMCPText(t, result), "flow_id not found")
		})
	})

	t.Run("identical_flows", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		mockMCP.AddProxyEntry(
			"GET /api/test HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello world",
			"",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"host":        "example.com",
		})
		require.Len(t, listResp.Flows, 1)
		flowID := listResp.Flows[0].FlowID

		t.Run("request", func(t *testing.T) {
			resp := CallMCPToolJSONOK[protocol.DiffFlowResponse](t, mcpClient, "diff_flow", map[string]interface{}{
				"flow_a": flowID,
				"flow_b": flowID,
				"scope":  "request",
			})
			assert.True(t, resp.Same)
		})

		t.Run("response", func(t *testing.T) {
			resp := CallMCPToolJSONOK[protocol.DiffFlowResponse](t, mcpClient, "diff_flow", map[string]interface{}{
				"flow_a": flowID,
				"flow_b": flowID,
				"scope":  "response",
			})
			assert.True(t, resp.Same)
		})
	})

	t.Run("text_body_diff", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		mockMCP.AddProxyEntry(
			"GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Hello</body></html>",
			"",
		)
		mockMCP.AddProxyEntry(
			"GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Goodbye</body></html>",
			"",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"host":        "example.com",
		})
		require.Len(t, listResp.Flows, 2)

		resp := CallMCPToolJSONOK[protocol.DiffFlowResponse](t, mcpClient, "diff_flow", map[string]interface{}{
			"flow_a": listResp.Flows[0].FlowID,
			"flow_b": listResp.Flows[1].FlowID,
			"scope":  "response_body",
		})

		assert.False(t, resp.Same)
		require.NotNil(t, resp.Response)
		require.NotNil(t, resp.Response.Body)
		assert.Equal(t, "text", resp.Response.Body.Format)
		assert.NotEmpty(t, resp.Response.Body.Diff)
		assert.NotEmpty(t, resp.Response.Body.Summary)
	})

	t.Run("json_body_diff", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		mockMCP.AddProxyEntry(
			"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"+`{"user":{"name":"alice","role":"admin"},"active":true}`,
			"",
		)
		mockMCP.AddProxyEntry(
			"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"+`{"user":{"name":"alice","role":"viewer","mfa":true},"count":5}`,
			"",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"host":        "example.com",
		})
		require.Len(t, listResp.Flows, 2)

		resp := CallMCPToolJSONOK[protocol.DiffFlowResponse](t, mcpClient, "diff_flow", map[string]interface{}{
			"flow_a": listResp.Flows[0].FlowID,
			"flow_b": listResp.Flows[1].FlowID,
			"scope":  "response_body",
		})

		assert.False(t, resp.Same)
		require.NotNil(t, resp.Response)
		require.NotNil(t, resp.Response.Body)
		assert.Equal(t, "json", resp.Response.Body.Format)

		// user.role changed from admin to viewer
		var foundRoleChange bool
		for _, c := range resp.Response.Body.Changed {
			if c.Path == "user.role" {
				foundRoleChange = true
				assert.Equal(t, "admin", c.A)
				assert.Equal(t, "viewer", c.B)
			}
		}
		assert.True(t, foundRoleChange)

		// user.mfa added
		var foundMfaAdd bool
		for _, a := range resp.Response.Body.Added {
			if a.Path == "user.mfa" {
				foundMfaAdd = true
				break
			}
		}
		assert.True(t, foundMfaAdd)

		// active removed
		var foundActiveRemove bool
		for _, r := range resp.Response.Body.Removed {
			if r.Path == "active" {
				foundActiveRemove = true
				break
			}
		}
		assert.True(t, foundActiveRemove)
	})

	t.Run("json_auto_detect", func(t *testing.T) {
		_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

		mockMCP.AddProxyEntry(
			"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"+`{"user":"alice","role":"admin"}`,
			"",
		)
		mockMCP.AddProxyEntry(
			"GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"+`{"user":"alice","role":"viewer"}`,
			"",
		)

		listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
			"output_mode": "flows",
			"host":        "example.com",
		})
		require.Len(t, listResp.Flows, 2)

		resp := CallMCPToolJSONOK[protocol.DiffFlowResponse](t, mcpClient, "diff_flow", map[string]interface{}{
			"flow_a": listResp.Flows[0].FlowID,
			"flow_b": listResp.Flows[1].FlowID,
			"scope":  "response_body",
		})

		assert.False(t, resp.Same)
		require.NotNil(t, resp.Response)
		require.NotNil(t, resp.Response.Body)
		// Should auto-detect JSON despite text/html content-type
		assert.Equal(t, "json", resp.Response.Body.Format)
	})
}

func TestDetectContentType(t *testing.T) {
	t.Parallel()

	t.Run("prefers_a", func(t *testing.T) {
		a := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n")
		b := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
		assert.Equal(t, "application/json", detectContentType(a, b))
	})

	t.Run("falls_back_to_b", func(t *testing.T) {
		a := []byte("HTTP/1.1 200 OK\r\n\r\n")
		b := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n")
		assert.Equal(t, "text/plain", detectContentType(a, b))
	})

	t.Run("both_empty", func(t *testing.T) {
		a := []byte("HTTP/1.1 200 OK\r\n\r\n")
		b := []byte("HTTP/1.1 200 OK\r\n\r\n")
		assert.Empty(t, detectContentType(a, b))
	})
}

func TestIsDiffJSONContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ct   string
		want bool
	}{
		{"application_json", "application/json", true},
		{"application_json_charset", "application/json; charset=utf-8", true},
		{"vnd_plus_json", "application/vnd.api+json", true},
		{"text_html", "text/html", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isDiffJSONContentType(tt.ct))
		})
	}
}

func TestIsDiffTextContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ct   string
		want bool
	}{
		{"text_plain", "text/plain", true},
		{"text_html", "text/html", true},
		{"application_xml", "application/xml", true},
		{"application_form", "application/x-www-form-urlencoded", true},
		{"application_json", "application/json", false},
		{"image_png", "image/png", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isDiffTextContentType(tt.ct))
		})
	}
}

func TestDiffBodies(t *testing.T) {
	t.Parallel()

	t.Run("identical_json", func(t *testing.T) {
		body := []byte(`{"key":"value"}`)
		assert.Nil(t, diffBodies(body, body, "application/json", 0))
	})

	t.Run("identical_text", func(t *testing.T) {
		body := []byte("hello world")
		assert.Nil(t, diffBodies(body, body, "text/plain", 0))
	})

	t.Run("binary_different", func(t *testing.T) {
		bodyA := []byte{0x00, 0xFF, 0xFE, 0x01}
		bodyB := []byte{0x00, 0xFF, 0xFE, 0x01, 0x02}

		result := diffBodies(bodyA, bodyB, "application/octet-stream", 0)
		require.NotNil(t, result)
		assert.Equal(t, "binary", result.Format)
		require.NotNil(t, result.Same)
		assert.False(t, *result.Same)
		assert.Equal(t, 4, result.ASize)
		assert.Equal(t, 5, result.BSize)
	})

	t.Run("binary_identical", func(t *testing.T) {
		body := []byte{0x00, 0xFF, 0xFE}
		assert.Nil(t, diffBodies(body, body, "application/octet-stream", 0))
	})

	t.Run("json_content_type", func(t *testing.T) {
		bodyA := []byte(`{"a":1}`)
		bodyB := []byte(`{"a":2}`)
		result := diffBodies(bodyA, bodyB, "application/json", 0)
		require.NotNil(t, result)
		assert.Equal(t, "json", result.Format)
	})

	t.Run("text_content_type", func(t *testing.T) {
		bodyA := []byte("line one")
		bodyB := []byte("line two")
		result := diffBodies(bodyA, bodyB, "text/plain", 0)
		require.NotNil(t, result)
		assert.Equal(t, "text", result.Format)
	})

	t.Run("utf8_fallback_to_text", func(t *testing.T) {
		bodyA := []byte("abc")
		bodyB := []byte("def")
		result := diffBodies(bodyA, bodyB, "", 0)
		require.NotNil(t, result)
		assert.Equal(t, "text", result.Format)
	})

	t.Run("non_utf8_binary_fallback", func(t *testing.T) {
		bodyA := []byte{0x80, 0x81, 0x82}
		bodyB := []byte{0x90, 0x91}
		result := diffBodies(bodyA, bodyB, "", 0)
		require.NotNil(t, result)
		assert.Equal(t, "binary", result.Format)
	})
}

func TestDiffTextBodies(t *testing.T) {
	t.Parallel()

	t.Run("basic_diff", func(t *testing.T) {
		bodyA := []byte("line one\nline two\n")
		bodyB := []byte("line one\nline changed\n")
		result := diffTextBodies(bodyA, bodyB, 0)
		require.NotNil(t, result)
		assert.Equal(t, "text", result.Format)
		assert.NotEmpty(t, result.Diff)
		assert.NotEmpty(t, result.Summary)
		assert.False(t, result.Truncated)
	})

	t.Run("truncation", func(t *testing.T) {
		var linesA, linesB []string
		for i := 0; i < 100; i++ {
			linesA = append(linesA, fmt.Sprintf("line %d\n", i))
			linesB = append(linesB, fmt.Sprintf("changed line %d\n", i))
		}

		bodyA := []byte(strings.Join(linesA, ""))
		bodyB := []byte(strings.Join(linesB, ""))

		result := diffTextBodies(bodyA, bodyB, 10)
		require.NotNil(t, result)
		assert.True(t, result.Truncated)
		assert.Equal(t, "text", result.Format)
	})

	t.Run("identical", func(t *testing.T) {
		body := []byte("same content\n")
		result := diffTextBodies(body, body, 0)
		require.NotNil(t, result)
		// diffTextBodies always returns a BodyDiff (even if empty diff)
		assert.Equal(t, "text", result.Format)
	})
}

func TestDiffJSONBodies(t *testing.T) {
	t.Parallel()

	t.Run("added_removed_changed", func(t *testing.T) {
		bodyA := []byte(`{"name":"alice","role":"admin","active":true}`)
		bodyB := []byte(`{"name":"alice","role":"viewer","mfa":true}`)

		result := diffJSONBodies(bodyA, bodyB, 0)
		require.NotNil(t, result)
		assert.Equal(t, "json", result.Format)
		assert.NotEmpty(t, result.Changed)        // role changed
		assert.NotEmpty(t, result.Added)          // mfa added
		assert.NotEmpty(t, result.Removed)        // active removed
		assert.Equal(t, 1, result.UnchangedCount) // name unchanged
	})

	t.Run("truncation", func(t *testing.T) {
		objA := make(map[string]interface{})
		objB := make(map[string]interface{})
		for i := 0; i < 50; i++ {
			key := fmt.Sprintf("key_%03d", i)
			objA[key] = i
			objB[key] = i + 1
		}

		bodyA, _ := json.Marshal(objA)
		bodyB, _ := json.Marshal(objB)

		result := diffJSONBodies(bodyA, bodyB, 5)
		require.NotNil(t, result)
		assert.True(t, result.Truncated)
		assert.Equal(t, "json", result.Format)
		totalReported := len(result.Added) + len(result.Removed) + len(result.Changed)
		assert.Equal(t, 5, totalReported)
	})

	t.Run("invalid_json_fallback", func(t *testing.T) {
		bodyA := []byte("not json")
		bodyB := []byte("also not json")
		result := diffJSONBodies(bodyA, bodyB, 0)
		require.NotNil(t, result)
		// Falls back to text diff
		assert.Equal(t, "text", result.Format)
	})

	t.Run("identical", func(t *testing.T) {
		body := []byte(`{"key":"value"}`)
		result := diffJSONBodies(body, body, 0)
		require.NotNil(t, result)
		assert.Equal(t, "json", result.Format)
		assert.Empty(t, result.Added)
		assert.Empty(t, result.Removed)
		assert.Empty(t, result.Changed)
		assert.Equal(t, 1, result.UnchangedCount)
	})
}

func TestDiffNameValues(t *testing.T) {
	t.Parallel()

	t.Run("identical", func(t *testing.T) {
		a := map[string][]string{"Content-Type": {"text/html"}}
		b := map[string][]string{"Content-Type": {"text/html"}}
		assert.Nil(t, diffNameValues(a, b))
	})

	t.Run("added", func(t *testing.T) {
		a := map[string][]string{}
		b := map[string][]string{"X-New": {"value"}}
		result := diffNameValues(a, b)
		require.NotNil(t, result)
		require.Len(t, result.Added, 1)
		assert.Equal(t, "X-New", result.Added[0].Name)
	})

	t.Run("removed", func(t *testing.T) {
		a := map[string][]string{"X-Old": {"value"}}
		b := map[string][]string{}
		result := diffNameValues(a, b)
		require.NotNil(t, result)
		require.Len(t, result.Removed, 1)
		assert.Equal(t, "X-Old", result.Removed[0].Name)
	})

	t.Run("changed", func(t *testing.T) {
		a := map[string][]string{"Content-Type": {"text/plain"}}
		b := map[string][]string{"Content-Type": {"application/json"}}
		result := diffNameValues(a, b)
		require.NotNil(t, result)
		require.Len(t, result.Changed, 1)
		assert.Equal(t, "Content-Type", result.Changed[0].Name)
		assert.Equal(t, "text/plain", result.Changed[0].A)
		assert.Equal(t, "application/json", result.Changed[0].B)
	})

	t.Run("multi_value_collision", func(t *testing.T) {
		a := map[string][]string{"X-Multi": {"a, b", "c"}}
		b := map[string][]string{"X-Multi": {"a", "b, c"}}
		result := diffNameValues(a, b)
		require.NotNil(t, result)
		require.Len(t, result.Changed, 1)
		assert.Equal(t, "X-Multi", result.Changed[0].Name)
	})
}

func TestDiffQueryStrings(t *testing.T) {
	t.Parallel()

	t.Run("identical", func(t *testing.T) {
		assert.Nil(t, diffQueryStrings("a=1&b=2", "a=1&b=2"))
	})

	t.Run("param_added", func(t *testing.T) {
		result := diffQueryStrings("a=1", "a=1&b=2")
		require.NotNil(t, result)
		require.Len(t, result.Added, 1)
		assert.Equal(t, "b", result.Added[0].Name)
	})

	t.Run("param_changed", func(t *testing.T) {
		result := diffQueryStrings("a=1", "a=2")
		require.NotNil(t, result)
		require.Len(t, result.Changed, 1)
		assert.Equal(t, "a", result.Changed[0].Name)
	})

	t.Run("both_empty", func(t *testing.T) {
		assert.Nil(t, diffQueryStrings("", ""))
	})
}

func TestLooksLikeJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
		want bool
	}{
		{"object", `{"key": "value"}`, true},
		{"array", `[1, 2, 3]`, true},
		{"whitespace_object", "  \t\n{\"key\": 1}", true},
		{"whitespace_array", "  \n[1]", true},
		{"html", "<html>hello</html>", false},
		{"text", "plain text", false},
		{"empty", "", false},
		{"whitespace_only", "   ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, looksLikeJSON([]byte(tt.data)))
		})
	}
}

package service

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

func TestHandleFindReflected(t *testing.T) {
	t.Parallel()

	_, mcpClient, mockMCP, _, _ := setupMockMCPServer(t)

	// Entry 0: query reflected as HTML-encoded in body, redirect in Location header, cookie in Set-Cookie
	mockMCP.AddProxyEntry(
		"GET /search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&redirect=https://evil.com&page=2 HTTP/1.1\r\n"+
			"Host: example.com\r\n"+
			"Cookie: session=abc123test; lang=en\r\n"+
			"Referer: https://evil.com\r\n\r\n",
		"HTTP/1.1 302 Found\r\n"+
			"Content-Type: text/html\r\n"+
			"Location: https://evil.com\r\n"+
			"Set-Cookie: session=abc123test; Path=/\r\n\r\n"+
			"<html>Results for &lt;script&gt;alert(1)&lt;/script&gt;</html>",
		"",
	)

	// Entry 1: JSON body with nested values reflected in response
	mockMCP.AddProxyEntry(
		"POST /api/users HTTP/1.1\r\n"+
			"Host: api.example.com\r\n"+
			"Content-Type: application/json\r\n\r\n"+
			`{"user":{"email":"test@example.com","role":"admin","id":12345},"tags":["security","testing"]}`,
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/html\r\n\r\n"+
			`<p>User 12345 test@example.com has role admin. Tags: security, testing</p>`,
		"",
	)

	// Entry 2: no reflections
	mockMCP.AddProxyEntry(
		"GET /safe?token=abcdef HTTP/1.1\r\n"+
			"Host: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/html\r\n\r\n"+
			"<html>Welcome</html>",
		"",
	)

	// Entry 3: form-encoded body
	mockMCP.AddProxyEntry(
		"POST /login HTTP/1.1\r\n"+
			"Host: example.com\r\n"+
			"Content-Type: application/x-www-form-urlencoded\r\n\r\n"+
			"username=admin%40example.com&password=secret1234",
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/html\r\n\r\n"+
			"<html>Welcome admin@example.com</html>",
		"",
	)

	// Entry 4: JS Unicode escaped reflection
	mockMCP.AddProxyEntry(
		"GET /api?callback=test<script> HTTP/1.1\r\n"+
			"Host: example.com\r\n\r\n",
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: application/javascript\r\n\r\n"+
			`test\u003cscript\u003e({"data":1})`,
		"",
	)

	listResp := CallMCPToolJSONOK[protocol.ProxyPollResponse](t, mcpClient, "proxy_poll", map[string]interface{}{
		"output_mode": "flows",
		"limit":       10,
	})
	require.Len(t, listResp.Flows, 5)

	t.Run("query_cookie_header_reflection", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.FindReflectedResponse](t, mcpClient, "find_reflected", map[string]interface{}{
			"flow_id": listResp.Flows[0].FlowID,
		})

		// q should be reflected in body (HTML-encoded match)
		qRef := findReflectionByName(resp.Reflections, "q")
		require.NotNil(t, qRef)
		assert.Equal(t, "query", qRef.Source)
		assert.Contains(t, qRef.Locations, "body")
		require.NotEmpty(t, qRef.Contexts)
		assert.Equal(t, "html_text", qRef.Contexts[0].Context)
		assert.Equal(t, "html_entity", qRef.Contexts[0].Encoding)

		// redirect should be reflected in Location header
		redirectRef := findReflectionByName(resp.Reflections, "redirect")
		require.NotNil(t, redirectRef)
		assert.Equal(t, "query", redirectRef.Source)
		assert.Contains(t, redirectRef.Locations, "header:Location")

		// session cookie should be reflected in Set-Cookie header
		sessionRef := findReflectionByName(resp.Reflections, "session")
		require.NotNil(t, sessionRef)
		assert.Equal(t, "cookie", sessionRef.Source)
		assert.Contains(t, sessionRef.Locations, "header:Set-Cookie")

		// page=2 is too short (1 char), should be skipped
		assert.Nil(t, findReflectionByName(resp.Reflections, "page"))

		// lang=en is too short (2 chars), should be skipped
		assert.Nil(t, findReflectionByName(resp.Reflections, "lang"))

		// Referer header value should also match Location header
		refererRef := findReflectionByName(resp.Reflections, "Referer")
		require.NotNil(t, refererRef)
		assert.Equal(t, "header", refererRef.Source)
		assert.Contains(t, refererRef.Locations, "header:Location")
	})

	t.Run("json_body_reflection", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.FindReflectedResponse](t, mcpClient, "find_reflected", map[string]interface{}{
			"flow_id": listResp.Flows[1].FlowID,
		})

		emailRef := findReflectionByName(resp.Reflections, "user.email")
		require.NotNil(t, emailRef)
		assert.Equal(t, "json", emailRef.Source)
		assert.Equal(t, "test@example.com", emailRef.Value)
		assert.Contains(t, emailRef.Locations, "body")

		roleRef := findReflectionByName(resp.Reflections, "user.role")
		require.NotNil(t, roleRef)
		assert.Equal(t, "json", roleRef.Source)
		assert.Equal(t, "admin", roleRef.Value)

		idRef := findReflectionByName(resp.Reflections, "user.id")
		require.NotNil(t, idRef)
		assert.Equal(t, "json", idRef.Source)
		assert.Equal(t, "12345", idRef.Value)
		assert.Contains(t, idRef.Locations, "body")

		tag0Ref := findReflectionByName(resp.Reflections, "tags[0]")
		require.NotNil(t, tag0Ref)
		assert.Equal(t, "json", tag0Ref.Source)
		assert.Equal(t, "security", tag0Ref.Value)

		tag1Ref := findReflectionByName(resp.Reflections, "tags[1]")
		require.NotNil(t, tag1Ref)
		assert.Equal(t, "json", tag1Ref.Source)
		assert.Equal(t, "testing", tag1Ref.Value)
	})

	t.Run("no_reflections", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.FindReflectedResponse](t, mcpClient, "find_reflected", map[string]interface{}{
			"flow_id": listResp.Flows[2].FlowID,
		})

		assert.Empty(t, resp.Reflections)
	})

	t.Run("form_body_reflection", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.FindReflectedResponse](t, mcpClient, "find_reflected", map[string]interface{}{
			"flow_id": listResp.Flows[3].FlowID,
		})

		usernameRef := findReflectionByName(resp.Reflections, "username")
		require.NotNil(t, usernameRef)
		assert.Equal(t, "body", usernameRef.Source)
		assert.Equal(t, "admin@example.com", usernameRef.Value)
		assert.Contains(t, usernameRef.Locations, "body")

		// password is 12 chars but not in response
		assert.Nil(t, findReflectionByName(resp.Reflections, "password"))
	})

	t.Run("js_unicode_reflection", func(t *testing.T) {
		resp := CallMCPToolJSONOK[protocol.FindReflectedResponse](t, mcpClient, "find_reflected", map[string]interface{}{
			"flow_id": listResp.Flows[4].FlowID,
		})

		callbackRef := findReflectionByName(resp.Reflections, "callback")
		require.NotNil(t, callbackRef)
		assert.Equal(t, "query", callbackRef.Source)
		assert.Contains(t, callbackRef.Locations, "body")
		require.NotEmpty(t, callbackRef.Contexts)
		assert.Equal(t, "js_unicode", callbackRef.Contexts[0].Encoding)
	})

	t.Run("missing_flow_id", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "find_reflected", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "flow_id is required")
	})

	t.Run("flow_not_found", func(t *testing.T) {
		result := CallMCPTool(t, mcpClient, "find_reflected", map[string]interface{}{
			"flow_id": "nonexistent",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, ExtractMCPText(t, result), "flow_id not found")
	})
}

func TestExtractParams(t *testing.T) {
	t.Parallel()

	t.Run("query_params", func(t *testing.T) {
		raw := []byte("GET /search?q=hello&page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
		params := extractParams(raw)

		var found bool
		for _, p := range params {
			if p.Name == "q" && p.Source == "query" && p.Value == "hello" {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("url_decoded_query", func(t *testing.T) {
		raw := []byte("GET /search?q=%3Cscript%3E HTTP/1.1\r\nHost: example.com\r\n\r\n")
		params := extractParams(raw)

		var found bool
		for _, p := range params {
			if p.Name == "q" && p.Source == "query" && p.Value == "<script>" {
				found = true
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("form_body", func(t *testing.T) {
		raw := []byte("POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=alice&pass=secret")
		params := extractParams(raw)

		var userFound, passFound bool
		for _, p := range params {
			if p.Name == "user" && p.Source == "body" && p.Value == "alice" {
				userFound = true
			} else if p.Name == "pass" && p.Source == "body" && p.Value == "secret" {
				passFound = true
			}
		}
		assert.True(t, userFound)
		assert.True(t, passFound)
	})

	t.Run("json_body", func(t *testing.T) {
		raw := []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n" +
			`{"user":{"name":"alice","active":true},"count":5,"items":["one","two"]}`)
		params := extractParams(raw)

		paramMap := make(map[string]protocol.Reflection)
		for _, p := range params {
			if p.Source == "json" {
				paramMap[p.Name] = p
			}
		}

		assert.Equal(t, "alice", paramMap["user.name"].Value)
		assert.Equal(t, "one", paramMap["items[0]"].Value)
		assert.Equal(t, "two", paramMap["items[1]"].Value)
		assert.Equal(t, "true", paramMap["user.active"].Value)
		assert.Equal(t, "5", paramMap["count"].Value)
	})

	t.Run("cookies", func(t *testing.T) {
		raw := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nCookie: session=abc123; theme=dark\r\n\r\n")
		params := extractParams(raw)

		var sessionFound, themeFound bool
		for _, p := range params {
			if p.Source != "cookie" {
				continue
			}
			if p.Name == "session" && p.Value == "abc123" {
				sessionFound = true
			} else if p.Name == "theme" && p.Value == "dark" {
				themeFound = true
			}
		}
		assert.True(t, sessionFound)
		assert.True(t, themeFound)
	})

	t.Run("headers", func(t *testing.T) {
		raw := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nReferer: https://evil.com\r\nX-Custom: test-value\r\n\r\n")
		params := extractParams(raw)

		var refererFound, customFound bool
		for _, p := range params {
			if p.Source != "header" {
				continue
			}
			if p.Name == "Referer" && p.Value == "https://evil.com" {
				refererFound = true
			} else if p.Name == "X-Custom" && p.Value == "test-value" {
				customFound = true
			}
		}
		assert.True(t, refererFound)
		assert.True(t, customFound)
	})

	t.Run("multipart_body", func(t *testing.T) {
		body := "--boundary\r\nContent-Disposition: form-data; name=\"field1\"\r\n\r\nvalue1\r\n" +
			"--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\nContent-Type: text/plain\r\n\r\nfile content\r\n" +
			"--boundary\r\nContent-Disposition: form-data; name=\"field2\"\r\n\r\nvalue2\r\n" +
			"--boundary--\r\n"
		raw := []byte("POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: multipart/form-data; boundary=boundary\r\n\r\n" + body)
		params := extractParams(raw)

		var field1Found, field2Found, fileFound bool
		for _, p := range params {
			if p.Source != "body" {
				continue
			}
			if p.Name == "field1" && p.Value == "value1" {
				field1Found = true
			} else if p.Name == "field2" && p.Value == "value2" {
				field2Found = true
			} else if p.Name == "file" {
				fileFound = true
			}
		}
		assert.True(t, field1Found)
		assert.True(t, field2Found)
		assert.False(t, fileFound) // file uploads should be skipped
	})

	t.Run("no_body", func(t *testing.T) {
		raw := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		params := extractParams(raw)

		for _, p := range params {
			assert.NotEqual(t, "body", p.Source)
			assert.NotEqual(t, "json", p.Source)
		}
	})
}

func TestFindReflections(t *testing.T) {
	t.Parallel()

	t.Run("literal_match", func(t *testing.T) {
		params := []protocol.Reflection{{Name: "q", Source: "query", Value: "hello world"}}
		resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<p>hello world</p>")

		reflections := findReflections(params, resp)
		require.Len(t, reflections, 1)
		assert.Equal(t, "q", reflections[0].Name)
		assert.Contains(t, reflections[0].Locations, "body")
		require.NotEmpty(t, reflections[0].Contexts)
		assert.Equal(t, "raw", reflections[0].Contexts[0].Encoding)
		assert.Equal(t, "html_text", reflections[0].Contexts[0].Context)
	})

	t.Run("html_encoded_match", func(t *testing.T) {
		params := []protocol.Reflection{{Name: "q", Source: "query", Value: "<script>alert(1)</script>"}}
		resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
			"<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>")

		reflections := findReflections(params, resp)
		require.Len(t, reflections, 1)
		assert.Contains(t, reflections[0].Locations, "body")
		require.NotEmpty(t, reflections[0].Contexts)
		assert.Equal(t, "html_entity", reflections[0].Contexts[0].Encoding)
	})

	t.Run("url_encoded_match", func(t *testing.T) {
		params := []protocol.Reflection{{Name: "path", Source: "query", Value: "/foo bar/baz"}}
		resp := []byte("HTTP/1.1 200 OK\r\n\r\nRedirect to %2Ffoo+bar%2Fbaz")

		reflections := findReflections(params, resp)
		require.Len(t, reflections, 1)
		assert.Contains(t, reflections[0].Locations, "body")
	})

	t.Run("js_unicode_match", func(t *testing.T) {
		params := []protocol.Reflection{{Name: "cb", Source: "query", Value: "test<img>"}}
		resp := []byte("HTTP/1.1 200 OK\r\n\r\ntest\\u003cimg\\u003e({\"data\":1})")

		reflections := findReflections(params, resp)
		require.Len(t, reflections, 1)
		assert.Contains(t, reflections[0].Locations, "body")
		require.NotEmpty(t, reflections[0].Contexts)
		assert.Equal(t, "js_unicode", reflections[0].Contexts[0].Encoding)
	})

	t.Run("js_unicode_uppercase_match", func(t *testing.T) {
		params := []protocol.Reflection{{Name: "cb", Source: "query", Value: "test<img>"}}
		resp := []byte("HTTP/1.1 200 OK\r\n\r\ntest\\u003Cimg\\u003E({\"data\":1})")

		reflections := findReflections(params, resp)
		require.Len(t, reflections, 1)
		assert.Contains(t, reflections[0].Locations, "body")
	})

	t.Run("js_hex_escape_match", func(t *testing.T) {
		params := []protocol.Reflection{{Name: "cb", Source: "query", Value: "test<img>"}}
		resp := []byte("HTTP/1.1 200 OK\r\n\r\ntest\\x3cimg\\x3e({\"data\":1})")

		reflections := findReflections(params, resp)
		require.Len(t, reflections, 1)
		assert.Contains(t, reflections[0].Locations, "body")
	})

	t.Run("html_decimal_entity_match", func(t *testing.T) {
		params := []protocol.Reflection{{Name: "q", Source: "query", Value: "<b>test</b>"}}
		resp := []byte("HTTP/1.1 200 OK\r\n\r\n&#60;b&#62;test&#60;&#47;b&#62;")

		reflections := findReflections(params, resp)
		require.Len(t, reflections, 1)
		assert.Contains(t, reflections[0].Locations, "body")
	})

	t.Run("html_hex_entity_match", func(t *testing.T) {
		params := []protocol.Reflection{{Name: "q", Source: "query", Value: "<b>test</b>"}}
		resp := []byte("HTTP/1.1 200 OK\r\n\r\n&#x3c;b&#x3e;test&#x3c;&#x2f;b&#x3e;")

		reflections := findReflections(params, resp)
		require.Len(t, reflections, 1)
		assert.Contains(t, reflections[0].Locations, "body")
	})

	t.Run("header_reflection", func(t *testing.T) {
		params := []protocol.Reflection{{Name: "redirect", Source: "query", Value: "https://evil.com"}}
		resp := []byte("HTTP/1.1 302 Found\r\nLocation: https://evil.com\r\n\r\n")

		reflections := findReflections(params, resp)
		require.Len(t, reflections, 1)
		assert.Contains(t, reflections[0].Locations, "header:Location")
	})

	t.Run("encoded_header_reflection", func(t *testing.T) {
		// url.PathEscape encodes space as %20 while url.QueryEscape uses +
		params := []protocol.Reflection{{Name: "next", Source: "query", Value: "/foo bar"}}
		resp := []byte("HTTP/1.1 302 Found\r\nLocation: /redir?next=%2Ffoo%20bar\r\n\r\n")

		reflections := findReflections(params, resp)
		require.Len(t, reflections, 1)
		assert.Contains(t, reflections[0].Locations, "header:Location")
	})

	t.Run("body_and_header", func(t *testing.T) {
		params := []protocol.Reflection{{Name: "val", Source: "query", Value: "reflected_value"}}
		resp := []byte("HTTP/1.1 200 OK\r\nX-Echo: reflected_value\r\n\r\nBody: reflected_value")

		reflections := findReflections(params, resp)
		require.Len(t, reflections, 1)
		assert.Contains(t, reflections[0].Locations, "body")
		assert.Contains(t, reflections[0].Locations, "header:X-Echo")
	})

	t.Run("multiple_body_contexts", func(t *testing.T) {
		// Raw value in script, HTML-encoded in text — both should appear in contexts
		params := []protocol.Reflection{{Name: "q", Source: "query", Value: "<img src=x>"}}
		resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" +
			"<script>var x = '<img src=x>';</script>" +
			"<p>&lt;img src=x&gt;</p>")

		reflections := findReflections(params, resp)
		require.Len(t, reflections, 1)
		assert.Contains(t, reflections[0].Locations, "body")
		require.GreaterOrEqual(t, len(reflections[0].Contexts), 2)

		encodings := make(map[string]bool)
		for _, c := range reflections[0].Contexts {
			encodings[c.Encoding] = true
		}
		assert.True(t, encodings["raw"])
		assert.True(t, encodings["html_entity"])
	})

	t.Run("short_values_skipped", func(t *testing.T) {
		params := []protocol.Reflection{
			{Name: "a", Source: "query", Value: "ab"},
			{Name: "b", Source: "query", Value: "abc"},
			{Name: "c", Source: "query", Value: "abcd"},
		}
		resp := []byte("HTTP/1.1 200 OK\r\n\r\nab abc abcd")

		reflections := findReflections(params, resp)
		require.Len(t, reflections, 1)
		assert.Equal(t, "c", reflections[0].Name)
	})

	t.Run("no_match", func(t *testing.T) {
		params := []protocol.Reflection{{Name: "q", Source: "query", Value: "not-in-response"}}
		resp := []byte("HTTP/1.1 200 OK\r\n\r\nsomething else entirely")

		reflections := findReflections(params, resp)
		assert.Empty(t, reflections)
	})

	t.Run("sorted_output", func(t *testing.T) {
		params := []protocol.Reflection{
			{Name: "z_param", Source: "query", Value: "test_value"},
			{Name: "a_param", Source: "query", Value: "test_value"},
			{Name: "cookie_val", Source: "cookie", Value: "test_value"},
		}
		resp := []byte("HTTP/1.1 200 OK\r\n\r\ntest_value")

		reflections := findReflections(params, resp)
		require.Len(t, reflections, 3)
		// Sorted by source then name: cookie < query, and a_param < z_param
		assert.Equal(t, "cookie", reflections[0].Source)
		assert.Equal(t, "query", reflections[1].Source)
		assert.Equal(t, "a_param", reflections[1].Name)
		assert.Equal(t, "z_param", reflections[2].Name)
	})
}

func TestClassifyReflectionContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		body   string
		offset int // offset of the "MATCH" marker
		want   string
	}{
		{
			name: "html_text",
			body: "<p>MATCH</p>",
			want: "html_text",
		},
		{
			name: "html_attribute",
			body: `<div class="MATCH">`,
			want: "html_attribute",
		},
		{
			name: "url_attribute",
			body: `<a href="MATCH">link</a>`,
			want: "url",
		},
		{
			name: "src_attribute",
			body: `<img src="MATCH">`,
			want: "url",
		},
		{
			name: "action_attribute",
			body: `<form action="MATCH">`,
			want: "url",
		},
		{
			name: "script_block",
			body: `<script>var x = "MATCH";</script>`,
			want: "script",
		},
		{
			name: "css_block",
			body: `<style>.cls { background: MATCH; }</style>`,
			want: "css",
		},
		{
			name: "html_comment",
			body: `<!-- MATCH -->`,
			want: "html_comment",
		},
		{
			name: "json_context",
			body: `{"key": "MATCH`,
			want: "json",
		},
		{
			name: "closed_script",
			body: `<script>var a=1;</script><p>MATCH</p>`,
			want: "html_text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx := strings.Index(tt.body, "MATCH")
			require.GreaterOrEqual(t, idx, 0)
			if tt.offset > 0 {
				idx = tt.offset
			}
			assert.Equal(t, tt.want, classifyReflectionContext(tt.body, idx))
		})
	}
}

func TestEncodingVariants(t *testing.T) {
	t.Parallel()

	t.Run("plain_value", func(t *testing.T) {
		variants := encodingVariants("hello")
		// Should have raw + url_query + url_path + html_entity (most deduplicate for plain values)
		labels := make([]string, 0, len(variants))
		for _, v := range variants {
			labels = append(labels, v.encoding)
		}
		assert.Contains(t, labels, "raw")
		// Verify the raw value is correct
		for _, v := range variants {
			if v.encoding == "raw" {
				assert.Equal(t, "hello", v.encoded)
			}
		}
	})

	t.Run("special_chars", func(t *testing.T) {
		variants := encodingVariants("<script>")
		labelSet := make(map[string]bool)
		for _, v := range variants {
			labelSet[v.encoding] = true
		}
		assert.True(t, labelSet["raw"])
		assert.True(t, labelSet["html_entity"])
		assert.True(t, labelSet["url_query"])
		assert.True(t, labelSet["js_unicode"])
		assert.True(t, labelSet["js_hex"])
		assert.True(t, labelSet["html_decimal"])
		assert.True(t, labelSet["html_hex"])
	})

	t.Run("raw_is_first", func(t *testing.T) {
		variants := encodingVariants("test<value>")
		require.NotEmpty(t, variants)
		assert.Equal(t, "raw", variants[0].encoding)
		assert.Equal(t, "test<value>", variants[0].encoded)
	})
}

func findReflectionByName(reflections []protocol.Reflection, name string) *protocol.Reflection {
	for i := range reflections {
		if reflections[i].Name == name {
			return &reflections[i]
		}
	}
	return nil
}

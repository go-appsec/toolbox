package service

import (
	"bytes"
	"compress/gzip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/config"
)

func TestAggregateByTuple(t *testing.T) {
	t.Parallel()

	t.Run("basic_grouping", func(t *testing.T) {
		entries := []flowEntry{
			{method: "GET", host: "example.com", path: "/api", status: 200},
			{method: "GET", host: "example.com", path: "/api", status: 200},
			{method: "GET", host: "example.com", path: "/api", status: 200},
			{method: "POST", host: "example.com", path: "/api", status: 201},
			{method: "GET", host: "other.com", path: "/", status: 200},
		}

		result := aggregateByTuple(entries, func(e flowEntry) (string, string, string, int) {
			return e.host, e.path, e.method, e.status
		})

		// Should have 3 unique tuples
		assert.Len(t, result, 3)

		// First entry should have highest count (3)
		assert.Equal(t, 3, result[0].Count)
		assert.Equal(t, "GET", result[0].Method)
		assert.Equal(t, "example.com", result[0].Host)
		assert.Equal(t, 200, result[0].Status)
	})

	t.Run("path_normalization", func(t *testing.T) {
		entries := []flowEntry{
			{method: "GET", host: "example.com", path: "/api/users/1", status: 200},
			{method: "GET", host: "example.com", path: "/api/users/2", status: 200},
			{method: "GET", host: "example.com", path: "/api/users/999", status: 200},
			{method: "GET", host: "example.com", path: "/api/posts/42", status: 200},
		}

		result := aggregateByTuple(entries, func(e flowEntry) (string, string, string, int) {
			return e.host, e.path, e.method, e.status
		})

		// /api/users/1, /api/users/2, /api/users/999 should group into /api/users/*
		// /api/posts/42 should be /api/posts/*
		assert.Len(t, result, 2)

		// First entry should have highest count (3 user requests)
		assert.Equal(t, 3, result[0].Count)
		assert.Equal(t, "/api/users/*", result[0].Path)

		// Second entry should be the posts request
		assert.Equal(t, 1, result[1].Count)
		assert.Equal(t, "/api/posts/*", result[1].Path)
	})
}

func TestParseHeaderArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  interface{}
		want []string
	}{
		{
			name: "object_format",
			raw: map[string]interface{}{
				"X-Custom": "value",
				"Accept":   "application/json",
			},
			want: []string{"X-Custom: value", "Accept: application/json"},
		},
		{
			name: "array_format",
			raw:  []interface{}{"X-Custom: value", "Accept: application/json"},
			want: []string{"X-Custom: value", "Accept: application/json"},
		},
		{
			name: "nil_input",
			raw:  nil,
			want: nil,
		},
		{
			name: "wrong_type",
			raw:  42,
			want: nil,
		},
		{
			name: "string_plain_text",
			raw:  "not a JSON structure",
			want: nil,
		},
		{
			name: "string_encoded_array",
			raw:  `["X-Custom: value", "Accept: application/json"]`,
			want: []string{"X-Custom: value", "Accept: application/json"},
		},
		{
			name: "string_encoded_object",
			raw:  `{"Accept": "application/json", "X-Custom": "value"}`,
			want: []string{"Accept: application/json", "X-Custom: value"},
		},
		{
			name: "string_encoded_duplicates",
			raw:  `["Content-Length: 5", "Content-Length: 10"]`,
			want: []string{"Content-Length: 5", "Content-Length: 10"},
		},
		{
			name: "string_encoded_empty_array",
			raw:  `[]`,
			want: []string{},
		},
		{
			name: "string_encoded_invalid_json",
			raw:  `[invalid`,
			want: nil,
		},
		{
			name: "empty_object",
			raw:  map[string]interface{}{},
			want: []string{},
		},
		{
			name: "empty_array",
			raw:  []interface{}{},
			want: []string{},
		},
		{
			name: "object_non_string_values_skipped",
			raw: map[string]interface{}{
				"X-Good": "value",
				"X-Bad":  42,
			},
			want: []string{"X-Good: value"},
		},
		{
			name: "array_non_string_items_skipped",
			raw:  []interface{}{"X-Good: value", 42, true},
			want: []string{"X-Good: value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHeaderArg(tt.raw)
			if tt.want == nil {
				assert.Nil(t, got)
				return
			}
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestExtractRequestMeta(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		raw    string
		method string
		host   string
		path   string
	}{
		{
			name:   "simple_get",
			raw:    "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
			method: "GET",
			host:   "example.com",
			path:   "/api/users",
		},
		{
			name:   "post_with_port",
			raw:    "POST /login HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n",
			method: "POST",
			host:   "api.example.com:8080",
			path:   "/login",
		},
		{
			name:   "with_query_string",
			raw:    "GET /search?q=test&page=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n",
			method: "GET",
			host:   "example.com",
			path:   "/search?q=test&page=1",
		},
		{
			name:   "lowercase_host_header",
			raw:    "GET / HTTP/1.1\r\nhost: lowercase.com\r\n\r\n",
			method: "GET",
			host:   "lowercase.com",
			path:   "/",
		},
		{
			name:   "proxy_form_http",
			raw:    "GET http://127.0.0.1:8080/path?q=1 HTTP/1.1\r\nUser-Agent: test\r\n\r\n",
			method: "GET",
			host:   "127.0.0.1:8080",
			path:   "/path?q=1",
		},
		{
			name:   "proxy_form_https",
			raw:    "GET https://example.com/api/v1 HTTP/1.1\r\n\r\n",
			method: "GET",
			host:   "example.com",
			path:   "/api/v1",
		},
		{
			name:   "proxy_form_root",
			raw:    "GET http://localhost:3000/ HTTP/1.1\r\n\r\n",
			method: "GET",
			host:   "localhost:3000",
			path:   "/",
		},
		{
			name:   "proxy_form_no_path",
			raw:    "GET http://example.com HTTP/1.1\r\n\r\n",
			method: "GET",
			host:   "example.com",
			path:   "/",
		},
		{
			name:   "host_space_before_colon",
			raw:    "GET /path HTTP/1.1\r\nHost : example.com\r\n\r\n",
			method: "GET",
			host:   "example.com",
			path:   "/path",
		},
		{
			name:   "bare_lf_simple",
			raw:    "GET /api/users HTTP/1.1\nHost: example.com\n\n",
			method: "GET",
			host:   "example.com",
			path:   "/api/users",
		},
		{
			name:   "bare_lf_proxy_form",
			raw:    "GET http://127.0.0.1:8080/path?q=1 HTTP/1.1\nUser-Agent: test\n\n",
			method: "GET",
			host:   "127.0.0.1:8080",
			path:   "/path?q=1",
		},
		{
			name:   "malformed_no_crash",
			raw:    "garbage",
			method: "",
			host:   "",
			path:   "",
		},
		{
			name:   "empty_string",
			raw:    "",
			method: "",
			host:   "",
			path:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, host, path := extractRequestMeta(tt.raw)
			assert.Equal(t, tt.method, method)
			assert.Equal(t, tt.host, host)
			assert.Equal(t, tt.path, path)
		})
	}
}

func TestSplitHeadersBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		raw         string
		wantHeaders string
		wantBody    string
	}{
		{
			name:        "request_with_body",
			raw:         "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody here",
			wantHeaders: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantBody:    "body here",
		},
		{
			name:        "no_body",
			raw:         "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantHeaders: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantBody:    "",
		},
		{
			name:        "binary_body",
			raw:         "POST / HTTP/1.1\r\n\r\n\x00\x01\x02",
			wantHeaders: "POST / HTTP/1.1\r\n\r\n",
			wantBody:    "\x00\x01\x02",
		},
		{
			name:        "no_separator",
			raw:         "malformed request",
			wantHeaders: "malformed request",
			wantBody:    "",
		},
		{
			name:        "bare_lf_with_body",
			raw:         "GET / HTTP/1.1\nHost: example.com\n\nbody here",
			wantHeaders: "GET / HTTP/1.1\nHost: example.com\n\n",
			wantBody:    "body here",
		},
		{
			name:        "bare_lf_no_body",
			raw:         "POST / HTTP/1.1\nHost: x\n\n",
			wantHeaders: "POST / HTTP/1.1\nHost: x\n\n",
			wantBody:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers, body := splitHeadersBody([]byte(tt.raw))
			assert.Equal(t, tt.wantHeaders, string(headers))
			assert.Equal(t, tt.wantBody, string(body))
		})
	}
}

func TestReadResponseStatusCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		expected int
	}{
		{
			name:     "http_1_1_200",
			input:    []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"),
			expected: 200,
		},
		{
			name:     "http_1_0_404",
			input:    []byte("HTTP/1.0 404 Not Found\r\n\r\n"),
			expected: 404,
		},
		{
			name:     "http_2_200",
			input:    []byte("HTTP/2 200\r\nContent-Type: application/json\r\n\r\n{}"),
			expected: 200,
		},
		{
			name:     "http_2_0_500",
			input:    []byte("HTTP/2.0 500 Internal Server Error\r\n\r\n"),
			expected: 500,
		},
		{
			name:     "lf_only_line_ending",
			input:    []byte("HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>"),
			expected: 200,
		},
		{
			name:     "binary_body_after_headers",
			input:    append([]byte("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n"), []byte{0x89, 0x50, 0x4E, 0x47}...),
			expected: 200,
		},
		{
			name:     "truncated_after_status_line",
			input:    []byte("HTTP/1.1 200 OK\r\n"),
			expected: 200,
		},
		{
			name:     "status_only_no_reason",
			input:    []byte("HTTP/1.1 200\r\n\r\n"),
			expected: 200,
		},
		{
			name:     "empty_input",
			input:    []byte{},
			expected: 0,
		},
		{
			name:     "no_http_prefix",
			input:    []byte("GET / HTTP/1.1\r\n"),
			expected: 0,
		},
		{
			name:     "malformed_no_space",
			input:    []byte("HTTP/1.1200OK\r\n"),
			expected: 0,
		},
		{
			name:     "invalid_status_code_letters",
			input:    []byte("HTTP/1.1 ABC OK\r\n"),
			expected: 0,
		},
		{
			name:     "status_code_too_low",
			input:    []byte("HTTP/1.1 99 Too Low\r\n"),
			expected: 0,
		},
		{
			name:     "status_code_too_high",
			input:    []byte("HTTP/1.1 600 Too High\r\n"),
			expected: 0,
		},
		{
			name:     "partial_status_code",
			input:    []byte("HTTP/1.1 20"),
			expected: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, readResponseStatusCode(tc.input))
		})
	}
}

func TestTransformRequestForValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "http_2_to_http_1_1",
			input:    []byte("POST /api/example HTTP/2\r\nHost: example.com\r\n\r\n"),
			expected: []byte("POST /api/example HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "http_1_1_unchanged",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "http_2_with_body",
			input:    []byte("POST /api HTTP/2\r\nHost: test.com\r\nContent-Length: 4\r\n\r\ntest"),
			expected: []byte("POST /api HTTP/1.1\r\nHost: test.com\r\nContent-Length: 4\r\n\r\ntest"),
		},
		{
			name:     "no_line_ending",
			input:    []byte("GET / HTTP/2"),
			expected: []byte("GET / HTTP/2"),
		},
		{
			name:     "bare_lf_http_2",
			input:    []byte("POST /api HTTP/2\nHost: test.com\n\n"),
			expected: []byte("POST /api HTTP/1.1\nHost: test.com\n\n"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := transformRequestForValidation(tc.input)
			require.Equal(t, string(tc.expected), string(result))
		})
	}
}

func TestModifyRequestLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		opts     *PathQueryOpts
		expected string
	}{
		{
			name:     "nil_opts",
			input:    []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     nil,
			expected: "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "empty_opts",
			input:    []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{},
			expected: "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "replace_path",
			input:    []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{Path: "/api/v2/accounts"},
			expected: "GET /api/v2/accounts HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "replace_path_preserves_query",
			input:    []byte("GET /api/users?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{Path: "/api/v2/accounts"},
			expected: "GET /api/v2/accounts?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "replace_query",
			input:    []byte("GET /api/users?old=value HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{Query: "new=param&foo=bar"},
			expected: "GET /api/users?new=param&foo=bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "add_query_to_path_without_query",
			input:    []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{Query: "id=123"},
			expected: "GET /api/users?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "set_query_param",
			input:    []byte("GET /api/users?id=123&role=user HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{SetQuery: []string{"role=admin"}},
			expected: "GET /api/users?id=123&role=admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "remove_query_param",
			input:    []byte("GET /api/users?id=123&secret=abc HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{RemoveQuery: []string{"secret"}},
			expected: "GET /api/users?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:  "combined_operations",
			input: []byte("GET /old/path?a=1&b=2&c=3 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts: &PathQueryOpts{
				Path:        "/new/path",
				RemoveQuery: []string{"b"},
				SetQuery:    []string{"a=changed", "d=4"},
			},
			expected: "GET /new/path?a=changed&c=3&d=4 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "preserves_body",
			input:    []byte("POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest"),
			opts:     &PathQueryOpts{Path: "/api/v2/data"},
			expected: "POST /api/v2/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest",
		},
		{
			name:     "http_2_version_preserved",
			input:    []byte("GET /api/test HTTP/2\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{Path: "/api/v2/test"},
			expected: "GET /api/v2/test HTTP/2\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "replace_method",
			input:    []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{Method: "POST"},
			expected: "POST /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "replace_method_with_path",
			input:    []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{Method: "DELETE", Path: "/api/users/123"},
			expected: "DELETE /api/users/123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "replace_method_preserves_body",
			input:    []byte("GET /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest"),
			opts:     &PathQueryOpts{Method: "PUT"},
			expected: "PUT /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest",
		},
		// Proxy-form URL tests (what proxy captures when client uses HTTP proxy)
		{
			name:     "proxy_form_remove_query",
			input:    []byte("GET http://127.0.0.1:8080/path?foo=bar&remove=this HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"),
			opts:     &PathQueryOpts{RemoveQuery: []string{"remove"}},
			expected: "GET http://127.0.0.1:8080/path?foo=bar HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n",
		},
		{
			name:     "proxy_form_remove_all_query_params",
			input:    []byte("GET http://example.com/path?only=param HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{RemoveQuery: []string{"only"}},
			expected: "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "proxy_form_set_query",
			input:    []byte("GET http://example.com/path?existing=value HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{SetQuery: []string{"new=added"}},
			expected: "GET http://example.com/path?existing=value&new=added HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		// Edge case: remove non-existent param (should be no-op)
		{
			name:     "remove_nonexistent_param",
			input:    []byte("GET /api?keep=value HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{RemoveQuery: []string{"nonexistent"}},
			expected: "GET /api?keep=value HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		// Edge case: remove from request with no query string
		{
			name:     "remove_from_no_query",
			input:    []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{RemoveQuery: []string{"anything"}},
			expected: "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		// Edge case: remove multiple params at once
		{
			name:     "remove_multiple_params",
			input:    []byte("GET /api?a=1&b=2&c=3&d=4 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{RemoveQuery: []string{"b", "d"}},
			expected: "GET /api?a=1&c=3 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		// Encoding preservation: existing percent-encoding is not normalized
		{
			name:     "encoding_preservation",
			input:    []byte("GET /api?foo=%2F&bar=hello HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{SetQuery: []string{"baz=new"}},
			expected: "GET /api?foo=%2F&bar=hello&baz=new HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		// Order preservation on set: existing param order is maintained
		{
			name:     "order_preservation_on_set",
			input:    []byte("GET /api?z=1&a=2&m=3 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{SetQuery: []string{"a=changed"}},
			expected: "GET /api?z=1&a=changed&m=3 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		// Bare-LF line endings
		{
			name:     "bare_lf_replace_path",
			input:    []byte("GET /old HTTP/1.1\nHost: example.com\n\n"),
			opts:     &PathQueryOpts{Path: "/new"},
			expected: "GET /new HTTP/1.1\nHost: example.com\n\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := modifyRequestLine(tc.input, tc.opts)
			assert.Equal(t, tc.expected, string(result))
		})
	}
}

func TestPathQueryOptsHasModifications(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		opts     PathQueryOpts
		expected bool
	}{
		{
			name:     "empty",
			opts:     PathQueryOpts{},
			expected: false,
		},
		{
			name:     "method_set",
			opts:     PathQueryOpts{Method: "POST"},
			expected: true,
		},
		{
			name:     "path_set",
			opts:     PathQueryOpts{Path: "/new"},
			expected: true,
		},
		{
			name:     "query_set",
			opts:     PathQueryOpts{Query: "a=1"},
			expected: true,
		},
		{
			name:     "set_query_set",
			opts:     PathQueryOpts{SetQuery: []string{"a=1"}},
			expected: true,
		},
		{
			name:     "remove_query_set",
			opts:     PathQueryOpts{RemoveQuery: []string{"a"}},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.opts.HasModifications())
		})
	}
}

func TestParseResponseStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		input          []byte
		expectedCode   int
		expectedStatus string
	}{
		{
			name:           "http_1_1_200",
			input:          []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"),
			expectedCode:   200,
			expectedStatus: "HTTP/1.1 200 OK",
		},
		{
			name:           "http_1_0_404",
			input:          []byte("HTTP/1.0 404 Not Found\r\n\r\n"),
			expectedCode:   404,
			expectedStatus: "HTTP/1.0 404 Not Found",
		},
		{
			name:           "empty_input",
			input:          []byte{},
			expectedCode:   0,
			expectedStatus: "",
		},
		{
			name:           "malformed_response",
			input:          []byte("not an http response"),
			expectedCode:   0,
			expectedStatus: "",
		},
		{
			name:           "truncated_status",
			input:          []byte("HTTP/1.1"),
			expectedCode:   0,
			expectedStatus: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, statusLine := parseResponseStatus(tc.input)
			assert.Equal(t, tc.expectedCode, code)
			assert.Equal(t, tc.expectedStatus, statusLine)
		})
	}
}

func TestReadResponseBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantStatus int
		wantProto  string
		wantErr    bool
	}{
		{
			name:       "http_1_1",
			input:      "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
			wantStatus: 200,
			wantProto:  "HTTP/1.1",
		},
		{
			name:       "http_1_0",
			input:      "HTTP/1.0 404 Not Found\r\n\r\n",
			wantStatus: 404,
			wantProto:  "HTTP/1.0",
		},
		{
			name:       "http_2_normalized",
			input:      "HTTP/2 200\r\nContent-Type: text/html\r\n\r\n",
			wantStatus: 200,
			wantProto:  "HTTP/2.0",
		},
		{
			name:       "http_2_reason_phrase",
			input:      "HTTP/2 301 Moved Permanently\r\nLocation: /new\r\n\r\n",
			wantStatus: 301,
			wantProto:  "HTTP/2.0",
		},
		{
			name:       "http_2_0_normalized",
			input:      "HTTP/2.0 204 No Content\r\n\r\n",
			wantStatus: 204,
			wantProto:  "HTTP/2.0",
		},
		{
			name:    "empty_input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "malformed_response",
			input:   "not a valid http response",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := readResponseBytes([]byte(tt.input))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equal(t, tt.wantStatus, resp.StatusCode)
			assert.Equal(t, tt.wantProto, resp.Proto)
		})
	}
}

func TestPreviewBody(t *testing.T) {
	t.Parallel()

	// Create invalid UTF-8 binary data
	binaryLarge := make([]byte, 1024)
	for i := range binaryLarge {
		binaryLarge[i] = 0xff // 0xff is invalid UTF-8
	}

	tests := []struct {
		name        string
		body        []byte
		maxLen      int
		contentType string
		want        string
	}{
		{"empty", []byte{}, 100, "", ""},
		{"utf8_short", []byte("hello world"), 100, "", "hello world"},
		{"utf8_truncate", []byte("hello world"), 5, "", "hello..."},
		{"binary_small", []byte{0x80, 0x81, 0xff}, 100, "", "<BINARY:3 Bytes>"},
		{"binary_large", binaryLarge, 100, "", "<BINARY:1024 Bytes>"},
		{"utf8_exact_limit", []byte("hello"), 5, "", "hello"},
		{"multibyte_truncate", []byte("hello\u4e16\u754c"), 6, "", "hello\u4e16..."},
		{"emoji_truncate", []byte("test\U0001F389\U0001F38A\U0001F381"), 5, "", "test\U0001F389..."},
		{"cjk_only", []byte("\u65e5\u672c\u8a9e\u30c6\u30b9\u30c8"), 3, "", "\u65e5\u672c\u8a9e..."},
		{"nul_bytes", []byte("hello\x00world"), 100, "", "<BINARY:11 Bytes>"},
		{"control_chars_high", makeControlBody(100), 1000, "", "<BINARY:100 Bytes>"},
		{"binary_content_type", []byte("mostly text"), 100, "image/png", "<BINARY:11 Bytes>"},
		{"binary_ct_with_params", []byte("text"), 100, "application/octet-stream; charset=utf-8", "<BINARY:4 Bytes>"},
		{"text_ct_no_heuristic", []byte("hello world"), 100, "text/plain", "hello world"},
		{"empty_ct_fallback", []byte("hello world"), 100, "", "hello world"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, previewBody(tt.body, tt.maxLen, tt.contentType))
		})
	}
}

func TestIsBinaryContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{"empty", "", false},
		{"text_plain", "text/plain", false},
		{"application_json", "application/json", false},
		{"image_png", "image/png", true},
		{"audio_mpeg", "audio/mpeg", true},
		{"video_mp4", "video/mp4", true},
		{"font_woff2", "font/woff2", true},
		{"octet_stream", "application/octet-stream", true},
		{"wasm", "application/wasm", true},
		{"with_charset", "image/png; charset=utf-8", true},
		{"case_insensitive", "Image/PNG", true},
		{"application_javascript", "application/javascript", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isBinaryContentType(tt.contentType))
		})
	}
}

func TestHasBinarySignature(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body []byte
		want bool
	}{
		{"empty", []byte{}, false},
		{"plain_text", []byte("Hello, World!"), false},
		{"nul_byte", []byte("hello\x00world"), true},
		{"nul_at_start", []byte("\x00hello"), true},
		{"tabs_and_newlines", []byte("line1\tvalue\nline2\r\n"), false},
		{"high_control_density", makeControlBody(100), true},
		{"low_control_density", makeLowControlBody(100), false},
		{"single_control_char", []byte("hello\x01world, this is a long enough string"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasBinarySignature(tt.body))
		})
	}
}

// makeControlBody creates a body where >10% of bytes are control characters.
func makeControlBody(size int) []byte {
	body := make([]byte, size)
	for i := range body {
		if i%5 == 0 {
			body[i] = 0x01 // control char every 5th byte = 20%
		} else {
			body[i] = 'A'
		}
	}
	return body
}

// makeLowControlBody creates a body with control chars well below the 10% threshold.
func makeLowControlBody(size int) []byte {
	body := make([]byte, size)
	for i := range body {
		body[i] = 'A'
	}
	body[0] = 0x01 // just 1% control chars
	return body
}

func TestParseURLWithDefaultHTTPS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantScheme string
		wantHost   string
		wantPath   string
		wantErr    bool
	}{
		{
			name:       "full_https_url",
			input:      "https://example.com/api/users",
			wantScheme: schemeHTTPS,
			wantHost:   "example.com",
			wantPath:   "/api/users",
		},
		{
			name:       "full_http_url",
			input:      "http://example.com/api/users",
			wantScheme: schemeHTTP,
			wantHost:   "example.com",
			wantPath:   "/api/users",
		},
		{
			name:       "no_scheme_defaults_https",
			input:      "example.com/api/users",
			wantScheme: schemeHTTPS,
			wantHost:   "example.com",
			wantPath:   "/api/users",
		},
		{
			name:       "no_scheme_with_port",
			input:      "example.com:8443/api",
			wantScheme: schemeHTTPS,
			wantHost:   "example.com:8443",
			wantPath:   "/api",
		},
		{
			name:       "no_scheme_root_path",
			input:      "example.com",
			wantScheme: schemeHTTPS,
			wantHost:   "example.com",
			wantPath:   "",
		},
		{
			name:       "with_query_string",
			input:      "example.com/search?q=test",
			wantScheme: schemeHTTPS,
			wantHost:   "example.com",
			wantPath:   "/search",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := parseURLWithDefaultHTTPS(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantScheme, u.Scheme)
			assert.Equal(t, tc.wantHost, u.Host)
			assert.Equal(t, tc.wantPath, u.Path)
		})
	}
}

func TestTargetFromURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		url       string
		wantHost  string
		wantPort  int
		wantHTTPS bool
	}{
		{
			name:      "https_default_port",
			url:       "https://example.com/api",
			wantHost:  "example.com",
			wantPort:  443,
			wantHTTPS: true,
		},
		{
			name:      "http_default_port",
			url:       "http://example.com/api",
			wantHost:  "example.com",
			wantPort:  80,
			wantHTTPS: false,
		},
		{
			name:      "https_custom_port",
			url:       "https://example.com:8443/api",
			wantHost:  "example.com",
			wantPort:  8443,
			wantHTTPS: true,
		},
		{
			name:      "http_custom_port",
			url:       "http://example.com:8080/api",
			wantHost:  "example.com",
			wantPort:  8080,
			wantHTTPS: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := parseURLWithDefaultHTTPS(tc.url)
			require.NoError(t, err)
			target := targetFromURL(u)
			assert.Equal(t, tc.wantHost, target.Hostname)
			assert.Equal(t, tc.wantPort, target.Port)
			assert.Equal(t, tc.wantHTTPS, target.UsesHTTPS)
		})
	}
}

func TestNormalizePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want string
	}{
		{"no_change", "/api/users", "/api/users"},
		{"numeric", "/api/users/123", "/api/users/*"},
		{"multiple_numeric", "/api/users/123/posts/456", "/api/users/*/posts/*"},
		{"uuid", "/api/users/550e8400-e29b-41d4-a716-446655440000", "/api/users/*"},
		{"uuid_no_dashes", "/api/users/550e8400e29b41d4a716446655440000", "/api/users/*"},
		{"mongodb_objectid", "/api/users/507f1f77bcf86cd799439011", "/api/users/*"},
		{"preserve_query", "/api/users/123?foo=bar", "/api/users/*?foo=bar"},
		{"root", "/", "/"},
		{"empty", "", ""},
		{"trailing_slash", "/api/users/123/", "/api/users/*/"},
		{"mixed", "/v2/orders/42/items/abc123def456789012345678", "/v2/orders/*/items/*"},
		{"short_hex_unchanged", "/api/abc123", "/api/abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizePath(tt.path))
		})
	}
}

func TestExtractRequestPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{
			name: "standard_get",
			raw:  []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want: "/api/users",
		},
		{
			name: "with_query_string",
			raw:  []byte("GET /search?q=test&page=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want: "/search",
		},
		{
			name: "bare_lf",
			raw:  []byte("POST /submit HTTP/1.1\nHost: example.com\n\n"),
			want: "/submit",
		},
		{
			name: "bare_lf_with_query",
			raw:  []byte("GET /path?key=val HTTP/1.1\nHost: example.com\n\n"),
			want: "/path",
		},
		{
			name: "empty_input",
			raw:  nil,
			want: "/",
		},
		{
			name: "method_only",
			raw:  []byte("GET\r\n"),
			want: "/",
		},
		{
			name: "root_path",
			raw:  []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want: "/",
		},
		{
			name: "absolute_uri",
			raw:  []byte("GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want: "http://example.com/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractRequestPath(tt.raw))
		})
	}
}

func TestBuildRawRequestManual(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		method          string
		url             string
		headers         []string
		body            []byte
		wantContains    []string
		wantNotContains []string
	}{
		{
			name:    "simple_get",
			method:  "GET",
			url:     "https://example.com/api/users",
			headers: nil,
			body:    nil,
			wantContains: []string{
				"GET /api/users HTTP/1.1\r\n",
				"Host: example.com\r\n",
				"User-Agent: " + config.UserAgent() + "\r\n",
			},
		},
		{
			name:    "get_with_query",
			method:  "GET",
			url:     "https://example.com/search?q=test",
			headers: nil,
			body:    nil,
			wantContains: []string{
				"GET /search?q=test HTTP/1.1\r\n",
				"Host: example.com\r\n",
			},
		},
		{
			name:    "post_with_body",
			method:  "POST",
			url:     "https://api.example.com/users",
			headers: []string{"Content-Type: application/json"},
			body:    []byte(`{"name":"test"}`),
			wantContains: []string{
				"POST /users HTTP/1.1\r\n",
				"Host: api.example.com\r\n",
				"Content-Type: application/json\r\n",
				"Content-Length: 15\r\n",
				`{"name":"test"}`,
			},
		},
		{
			name:    "with_auth_header",
			method:  "GET",
			url:     "https://api.example.com/protected",
			headers: []string{"Authorization: Bearer token123"},
			body:    nil,
			wantContains: []string{
				"GET /protected HTTP/1.1\r\n",
				"Authorization: Bearer token123\r\n",
			},
		},
		{
			name:    "custom_host_header",
			method:  "GET",
			url:     "https://example.com/path",
			headers: []string{"Host: custom.host.com"},
			body:    nil,
			wantContains: []string{
				"GET /path HTTP/1.1\r\n",
				"Host: custom.host.com\r\n",
			},
		},
		{
			name:    "root_path",
			method:  "GET",
			url:     "https://example.com",
			headers: nil,
			body:    nil,
			wantContains: []string{
				"GET / HTTP/1.1\r\n",
				"Host: example.com\r\n",
			},
		},
		{
			name:    "with_port",
			method:  "GET",
			url:     "https://example.com:8443/api",
			headers: nil,
			body:    nil,
			wantContains: []string{
				"GET /api HTTP/1.1\r\n",
				"Host: example.com:8443\r\n",
			},
		},
		{
			name:    "preserves_header_order",
			method:  "GET",
			url:     "https://example.com/",
			headers: []string{"X-First: 1", "X-Second: 2", "X-Third: 3"},
			body:    nil,
			wantContains: []string{
				"X-First: 1\r\nX-Second: 2\r\nX-Third: 3\r\n",
			},
		},
		{
			name:    "explicit_cl_preserved",
			method:  "POST",
			url:     "https://example.com/",
			headers: []string{"Content-Length: 99"},
			body:    []byte("hello"),
			wantContains: []string{
				"Content-Length: 99\r\n",
			},
		},
		{
			name:    "te_present_no_auto_cl",
			method:  "POST",
			url:     "https://example.com/",
			headers: []string{"Transfer-Encoding: chunked"},
			body:    []byte("5\r\nHELLO\r\n0\r\n\r\n"),
			wantContains: []string{
				"Transfer-Encoding: chunked\r\n",
			},
			wantNotContains: []string{
				"Content-Length:",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := parseURLWithDefaultHTTPS(tc.url)
			require.NoError(t, err)
			result := string(buildRawRequestManual(tc.method, u, tc.headers, tc.body))
			for _, want := range tc.wantContains {
				assert.Contains(t, result, want)
			}
			for _, notWant := range tc.wantNotContains {
				assert.NotContains(t, result, notWant)
			}
		})
	}
}

func TestGlobToRegex(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		glob     string
		expected string
	}{
		{"wildcard_domain", "*.example.com", `.*\.example\.com`},
		{"literal_domain", "api.example.com", `api\.example\.com`},
		{"question_mark", "test?", `test.`},
		{"double_wildcard", "*.*.com", `.*\..*\.com`},
		{"plain_string", "plain", `plain`},
		{"wildcard_path", "path/to/*", `path/to/.*`},
		{"brackets_escaped", "[bracket]", `\[bracket\]`},
		{"parens_escaped", "(paren)", `\(paren\)`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, globToRegex(tt.glob))
		})
	}
}

func TestMatchesGlob(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		s       string
		pattern string
		match   bool
	}{
		{"subdomain_wildcard", "api.example.com", "*.example.com", true},
		{"root_no_match", "example.com", "*.example.com", false},
		{"exact_match", "api.example.com", "api.example.com", true},
		{"middle_wildcard", "api.example.com", "api.*.com", true},
		{"question_mark_match", "test1", "test?", true},
		{"question_mark_no_match", "test12", "test?", false},
		{"empty_matches_all", "anything", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.match, matchesGlob(tt.s, tt.pattern))
		})
	}
}

func TestMatchesCookieDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		domain string
		filter string
		match  bool
	}{
		{"exact_match", "example.com", "example.com", true},
		{"subdomain_match", "api.example.com", "example.com", true},
		{"deep_subdomain_match", "a.b.example.com", "example.com", true},
		{"case_insensitive", "Example.COM", "example.com", true},
		{"case_insensitive_subdomain", "api.EXAMPLE.com", "Example.Com", true},
		{"different_domain", "other.com", "example.com", false},
		{"suffix_not_subdomain", "notexample.com", "example.com", false},
		{"domain_in_subdomain", "example.com.evil.com", "example.com", false},
		{"empty_domain", "", "example.com", false},
		{"empty_filter", "example.com", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.match, matchesCookieDomain(tt.domain, tt.filter))
		})
	}
}

func TestParseCommaSeparated(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"comma_separated", "GET,POST,PUT", []string{"GET", "POST", "PUT"}},
		{"with_spaces", "GET, POST, PUT", []string{"GET", "POST", "PUT"}},
		{"single_value", "GET", []string{"GET"}},
		{"empty", "", nil},
		{"all_whitespace", " , , ", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseCommaSeparated(tt.input))
		})
	}
}

func TestParseStatusFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantNil     bool
		wantEmpty   bool
		wantMatch   []int
		wantNoMatch []int
	}{
		{
			name:        "exact_codes",
			input:       "200,302,404",
			wantMatch:   []int{200, 302, 404},
			wantNoMatch: []int{500},
		},
		{
			name:        "range_uppercase",
			input:       "2XX",
			wantMatch:   []int{200, 201, 299},
			wantNoMatch: []int{199, 300},
		},
		{
			name:        "range_lowercase",
			input:       "4xx",
			wantMatch:   []int{400, 404, 499},
			wantNoMatch: []int{399, 500},
		},
		{
			name:        "mixed_codes_and_ranges",
			input:       "2XX,404,5xx",
			wantMatch:   []int{200, 201, 404, 500, 503},
			wantNoMatch: []int{302, 400},
		},
		{
			name:      "empty_input",
			input:     "",
			wantNil:   true,
			wantEmpty: true,
			wantMatch: []int{200},
		},
		{
			name:      "invalid_input",
			input:     "invalid",
			wantEmpty: true,
		},
		{
			name:      "whitespace_handling",
			input:     "200, 2xx, 404",
			wantMatch: []int{200, 201, 404},
		},
		{
			name:      "all_ranges",
			input:     "1XX,2XX,3XX,4XX,5XX",
			wantMatch: []int{100, 200, 301, 404, 503},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := parseStatusFilter(tt.input)
			if tt.wantNil {
				assert.Nil(t, f)
			}
			if tt.wantEmpty {
				assert.True(t, f.Empty())
			}
			for _, code := range tt.wantMatch {
				assert.True(t, f.Matches(code), "expected %d to match", code)
			}
			for _, code := range tt.wantNoMatch {
				assert.False(t, f.Matches(code), "expected %d not to match", code)
			}
		})
	}
}

func TestUpdateContentLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers string
		length  int
		want    string
	}{
		{
			name:    "update_existing",
			headers: "GET / HTTP/1.1\r\nContent-Length: 10\r\n\r\n",
			length:  42,
			want:    "GET / HTTP/1.1\r\nContent-Length: 42\r\n\r\n",
		},
		{
			name:    "add_missing",
			headers: "POST / HTTP/1.1\r\nHost: x\r\n\r\n",
			length:  100,
			want:    "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n",
		},
		{
			name:    "zero_length_no_add",
			headers: "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
			length:  0,
			want:    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		},
		{
			name:    "case_insensitive",
			headers: "POST / HTTP/1.1\r\ncontent-length: 5\r\n\r\n",
			length:  20,
			want:    "POST / HTTP/1.1\r\nContent-Length: 20\r\n\r\n",
		},
		{
			name:    "duplicate_cl_collapsed",
			headers: "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n",
			length:  7,
			want:    "POST / HTTP/1.1\r\nContent-Length: 7\r\n\r\n",
		},
		{
			name:    "zero_with_existing_cl",
			headers: "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
			length:  0,
			want:    "POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
		},
		{
			name:    "space_before_colon",
			headers: "POST / HTTP/1.1\r\nContent-Length : 5\r\n\r\n",
			length:  20,
			want:    "POST / HTTP/1.1\r\nContent-Length: 20\r\n\r\n",
		},
		{
			name:    "bare_lf_update",
			headers: "POST / HTTP/1.1\nContent-Length: 5\n\n",
			length:  20,
			want:    "POST / HTTP/1.1\nContent-Length: 20\n\n",
		},
		{
			name:    "bare_lf_add",
			headers: "POST / HTTP/1.1\nHost: x\n\n",
			length:  100,
			want:    "POST / HTTP/1.1\nHost: x\nContent-Length: 100\n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(updateContentLength([]byte(tt.headers), tt.length)))
		})
	}
}

func TestValidateWireAnomalies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		headers    string
		wantChecks []string
	}{
		{
			name:       "clean_request",
			headers:    "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
			wantChecks: nil,
		},
		{
			name:       "te_cl_conflict",
			headers:    "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
			wantChecks: []string{"te-cl-conflict"},
		},
		{
			name:       "duplicate_cl",
			headers:    "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\n",
			wantChecks: []string{"duplicate-cl"},
		},
		{
			name:       "duplicate_te",
			headers:    "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n",
			wantChecks: []string{"duplicate-te"},
		},
		{
			name:       "header_whitespace",
			headers:    "GET / HTTP/1.1\r\nContent-Length : 4\r\n\r\n",
			wantChecks: []string{"header-whitespace"},
		},
		{
			name:       "ows_after_colon_ok",
			headers:    "GET / HTTP/1.1\r\nHost:  example.com\r\n\r\n",
			wantChecks: nil,
		},
		{
			name:       "te_cl_space_before_colon",
			headers:    "POST / HTTP/1.1\r\nTransfer-Encoding : chunked\r\nContent-Length : 5\r\n\r\n",
			wantChecks: []string{"te-cl-conflict", "header-whitespace"},
		},
		{
			name:       "duplicate_cl_space_before_colon",
			headers:    "POST / HTTP/1.1\r\nContent-Length : 5\r\nContent-Length : 10\r\n\r\n",
			wantChecks: []string{"duplicate-cl", "header-whitespace"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := validateWireAnomalies([]byte(tt.headers))
			if len(tt.wantChecks) == 0 {
				assert.Empty(t, issues)
				return
			}
			var gotChecks []string
			for _, iss := range issues {
				gotChecks = append(gotChecks, iss.Check)
			}
			for _, want := range tt.wantChecks {
				assert.Contains(t, gotChecks, want)
			}
		})
	}
}

func TestApplyHeaderModifications(t *testing.T) {
	t.Parallel()

	base := "GET / HTTP/1.1\r\nHost: example.com\r\nX-Old: value\r\n\r\n"

	tests := []struct {
		name         string
		remove       []string
		set          []string
		wantContains []string
		wantMissing  []string
	}{
		{
			name:         "single_replaces_existing",
			set:          []string{"Host: new.example.com"},
			wantContains: []string{"Host: new.example.com"},
			wantMissing:  []string{"Host: example.com"},
		},
		{
			name:         "duplicate_headers_preserved",
			set:          []string{"X-Custom: a", "X-Custom: b"},
			wantContains: []string{"X-Custom: a", "X-Custom: b"},
		},
		{
			name:         "remove_then_set",
			remove:       []string{"X-Old"},
			set:          []string{"X-New: added"},
			wantContains: []string{"X-New: added"},
			wantMissing:  []string{"X-Old"},
		},
		{
			name:         "mixed_single_and_duplicate",
			set:          []string{"Host: new.com", "TE: chunked", "TE: identity"},
			wantContains: []string{"Host: new.com", "TE: chunked", "TE: identity"},
			wantMissing:  []string{"Host: example.com"},
		},
		{
			name:         "verbatim_whitespace",
			set:          []string{"Transfer-Encoding:  chunked"},
			wantContains: []string{"Transfer-Encoding:  chunked"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := string(applyHeaderModifications([]byte(base), tt.remove, tt.set))
			for _, want := range tt.wantContains {
				assert.Contains(t, result, want)
			}
			for _, missing := range tt.wantMissing {
				assert.NotContains(t, result, missing)
			}
		})
	}
}

func TestSetHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers string
		hName   string
		hValue  string
		want    string
	}{
		{
			name:    "add_new_header",
			headers: "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
			hName:   "Authorization",
			hValue:  "Bearer token",
			want:    "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer token\r\n\r\n",
		},
		{
			name:    "replace_existing",
			headers: "GET / HTTP/1.1\r\nHost: old.com\r\n\r\n",
			hName:   "Host",
			hValue:  "new.com",
			want:    "GET / HTTP/1.1\r\nHost: new.com\r\n\r\n",
		},
		{
			name:    "case_insensitive_replace",
			headers: "GET / HTTP/1.1\r\nhost: old.com\r\n\r\n",
			hName:   "Host",
			hValue:  "new.com",
			want:    "GET / HTTP/1.1\r\nHost: new.com\r\n\r\n",
		},
		{
			name:    "replace_first_header",
			headers: "GET / HTTP/1.1\r\nHost: old.com\r\nCookie: abc\r\nAccept: */*\r\n\r\n",
			hName:   "Host",
			hValue:  "new.com",
			want:    "GET / HTTP/1.1\r\nHost: new.com\r\nCookie: abc\r\nAccept: */*\r\n\r\n",
		},
		{
			name:    "replace_middle_header",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nCookie: old\r\nAccept: */*\r\n\r\n",
			hName:   "Cookie",
			hValue:  "new",
			want:    "GET / HTTP/1.1\r\nHost: x\r\nCookie: new\r\nAccept: */*\r\n\r\n",
		},
		{
			name:    "replace_last_header",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nCookie: abc\r\nAccept: old\r\n\r\n",
			hName:   "Accept",
			hValue:  "application/json",
			want:    "GET / HTTP/1.1\r\nHost: x\r\nCookie: abc\r\nAccept: application/json\r\n\r\n",
		},
		{
			name:    "replace_empty_value",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nX-Empty:\r\n\r\n",
			hName:   "X-Empty",
			hValue:  "now-has-value",
			want:    "GET / HTTP/1.1\r\nHost: x\r\nX-Empty: now-has-value\r\n\r\n",
		},
		{
			name:    "replace_whitespace_only",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nX-Blank:   \r\n\r\n",
			hName:   "X-Blank",
			hValue:  "filled",
			want:    "GET / HTTP/1.1\r\nHost: x\r\nX-Blank: filled\r\n\r\n",
		},
		{
			name:    "space_before_colon",
			headers: "GET / HTTP/1.1\r\nContent-Length : 5\r\n\r\n",
			hName:   "Content-Length",
			hValue:  "10",
			want:    "GET / HTTP/1.1\r\nContent-Length: 10\r\n\r\n",
		},
		{
			name:    "tab_before_colon",
			headers: "GET / HTTP/1.1\r\nHost\t: old.com\r\n\r\n",
			hName:   "Host",
			hValue:  "new.com",
			want:    "GET / HTTP/1.1\r\nHost: new.com\r\n\r\n",
		},
		{
			name:    "bare_lf_add_new",
			headers: "GET / HTTP/1.1\nHost: x\n\n",
			hName:   "Authorization",
			hValue:  "Bearer token",
			want:    "GET / HTTP/1.1\nHost: x\nAuthorization: Bearer token\n\n",
		},
		{
			name:    "bare_lf_replace",
			headers: "GET / HTTP/1.1\nHost: old.com\n\n",
			hName:   "Host",
			hValue:  "new.com",
			want:    "GET / HTTP/1.1\nHost: new.com\n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(setHeader([]byte(tt.headers), tt.hName, tt.hValue)))
		})
	}
}

func TestRemoveHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers string
		hName   string
		want    string
	}{
		{
			name:    "remove_existing",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nX-Remove: value\r\n\r\n",
			hName:   "X-Remove",
			want:    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		},
		{
			name:    "remove_nonexistent",
			headers: "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
			hName:   "X-NotThere",
			want:    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		},
		{
			name:    "remove_empty_value",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nX-Empty:\r\n\r\n",
			hName:   "X-Empty",
			want:    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		},
		{
			name:    "remove_whitespace_only",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nX-Blank:   \r\n\r\n",
			hName:   "X-Blank",
			want:    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		},
		{
			name:    "case_insensitive",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nx-lower: val\r\n\r\n",
			hName:   "X-Lower",
			want:    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		},
		{
			name:    "space_before_colon",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nContent-Length : 5\r\n\r\n",
			hName:   "Content-Length",
			want:    "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		},
		{
			name:    "bare_lf",
			headers: "GET / HTTP/1.1\nHost: x\nX-Remove: val\n\n",
			hName:   "X-Remove",
			want:    "GET / HTTP/1.1\nHost: x\n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(removeHeader([]byte(tt.headers), tt.hName)))
		})
	}
}

func TestSetHeaderIfMissing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers string
		hName   string
		hValue  string
		want    string
	}{
		{
			name:    "add_when_missing",
			headers: "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
			hName:   "User-Agent",
			hValue:  "sectool/1.0",
			want:    "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: sectool/1.0\r\n\r\n",
		},
		{
			name:    "skip_when_present",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: existing\r\n\r\n",
			hName:   "User-Agent",
			hValue:  "sectool/1.0",
			want:    "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: existing\r\n\r\n",
		},
		{
			name:    "case_insensitive_check",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nuser-agent: existing\r\n\r\n",
			hName:   "User-Agent",
			hValue:  "sectool/1.0",
			want:    "GET / HTTP/1.1\r\nHost: x\r\nuser-agent: existing\r\n\r\n",
		},
		{
			name:    "space_before_colon_present",
			headers: "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent : existing\r\n\r\n",
			hName:   "User-Agent",
			hValue:  "sectool/1.0",
			want:    "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent : existing\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(setHeaderIfMissing([]byte(tt.headers), tt.hName, tt.hValue)))
		})
	}
}

func TestExtractHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers string
		search  string
		want    string
	}{
		{
			name:    "content_encoding_gzip",
			headers: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n\r\n",
			search:  "Content-Encoding",
			want:    "gzip",
		},
		{
			name:    "case_insensitive",
			headers: "HTTP/1.1 200 OK\r\ncontent-encoding: deflate\r\n\r\n",
			search:  "Content-Encoding",
			want:    "deflate",
		},
		{
			name:    "not_found",
			headers: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
			search:  "Content-Encoding",
			want:    "",
		},
		{
			name:    "with_whitespace",
			headers: "HTTP/1.1 200 OK\r\nContent-Encoding:   gzip  \r\n\r\n",
			search:  "Content-Encoding",
			want:    "gzip",
		},
		{
			name:    "empty_headers",
			headers: "",
			search:  "Content-Encoding",
			want:    "",
		},
		{
			name:    "multiple_values",
			headers: "HTTP/1.1 200 OK\r\nContent-Encoding: gzip, br\r\n\r\n",
			search:  "Content-Encoding",
			want:    "gzip, br",
		},
		{
			name:    "bare_lf",
			headers: "HTTP/1.1 200 OK\nContent-Encoding: gzip\n\n",
			search:  "Content-Encoding",
			want:    "gzip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractHeader(tt.headers, tt.search))
		})
	}
}

func TestDecompressForDisplay(t *testing.T) {
	t.Parallel()

	// Create gzip compressed content
	gzipBody := compressGzip(t, []byte("Hello, World!"))

	tests := []struct {
		name             string
		body             []byte
		headers          string
		wantBody         string
		wantDecompressed bool
	}{
		{
			name:             "gzip_decompressed",
			body:             gzipBody,
			headers:          "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
			wantBody:         "Hello, World!",
			wantDecompressed: true,
		},
		{
			name:             "no_encoding_passthrough",
			body:             []byte("Plain text"),
			headers:          "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
			wantBody:         "Plain text",
			wantDecompressed: false,
		},
		{
			name:             "unsupported_encoding_passthrough",
			body:             []byte{0x1f, 0x8b}, // looks like gzip magic but invalid
			headers:          "HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n\r\n",
			wantBody:         string([]byte{0x1f, 0x8b}),
			wantDecompressed: false,
		},
		{
			name:             "multiple_encodings_passthrough",
			body:             gzipBody,
			headers:          "HTTP/1.1 200 OK\r\nContent-Encoding: gzip, br\r\n\r\n",
			wantBody:         string(gzipBody),
			wantDecompressed: false,
		},
		{
			name:             "corrupted_gzip_passthrough",
			body:             []byte{0x1f, 0x8b, 0x08, 0x00, 0x00}, // invalid gzip
			headers:          "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
			wantBody:         string([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00}),
			wantDecompressed: false,
		},
		{
			name:             "empty_body",
			body:             []byte{},
			headers:          "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
			wantBody:         "",
			wantDecompressed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, wasDecompressed := decompressForDisplay(tt.body, tt.headers)
			assert.Equal(t, tt.wantBody, string(result))
			assert.Equal(t, tt.wantDecompressed, wasDecompressed)
		})
	}
}

// compressGzip is a test helper that compresses data with gzip
func compressGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	compressed, err := compressGzipBytes(data)
	require.NoError(t, err)
	return compressed
}

func compressGzipBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(data); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func TestParseTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		raw       string
		override  string
		wantHost  string
		wantPort  int
		wantHTTPS bool
	}{
		{
			name:      "host_header_no_port",
			raw:       "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantHost:  "example.com",
			wantPort:  443,
			wantHTTPS: true,
		},
		{
			name:      "host_header_port_443",
			raw:       "GET / HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
			wantHost:  "example.com",
			wantPort:  443,
			wantHTTPS: true,
		},
		{
			name:      "host_header_port_80",
			raw:       "GET / HTTP/1.1\r\nHost: example.com:80\r\n\r\n",
			wantHost:  "example.com",
			wantPort:  80,
			wantHTTPS: false,
		},
		{
			name:      "host_header_custom_port",
			raw:       "GET / HTTP/1.1\r\nHost: example.com:8443\r\n\r\n",
			wantHost:  "example.com",
			wantPort:  8443,
			wantHTTPS: false,
		},
		{
			name:      "target_override_https",
			raw:       "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			override:  "https://staging.example.com:8443",
			wantHost:  "staging.example.com",
			wantPort:  8443,
			wantHTTPS: true,
		},
		{
			name:      "target_override_http",
			raw:       "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			override:  "http://staging.example.com",
			wantHost:  "staging.example.com",
			wantPort:  80,
			wantHTTPS: false,
		},
		{
			name:      "proxy_form_http",
			raw:       "GET http://example.com:8080/path HTTP/1.1\r\n\r\n",
			wantHost:  "example.com",
			wantPort:  8080,
			wantHTTPS: false,
		},
		{
			name:      "proxy_form_https",
			raw:       "GET https://example.com/path HTTP/1.1\r\n\r\n",
			wantHost:  "example.com",
			wantPort:  443,
			wantHTTPS: true,
		},
		{
			name:      "bare_lf_host_header",
			raw:       "GET / HTTP/1.1\nHost: example.com\n\n",
			wantHost:  "example.com",
			wantPort:  443,
			wantHTTPS: true,
		},
		{
			name:      "bare_lf_proxy_form",
			raw:       "GET http://example.com:8080/path HTTP/1.1\n\n",
			wantHost:  "example.com",
			wantPort:  8080,
			wantHTTPS: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, usesHTTPS := parseTarget([]byte(tt.raw), tt.override)
			assert.Equal(t, tt.wantHost, host)
			assert.Equal(t, tt.wantPort, port)
			assert.Equal(t, tt.wantHTTPS, usesHTTPS)
		})
	}
}

func TestInsertBeforeBlankLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		headers string
		line    string
		want    string
	}{
		{
			name:    "crlf_insert",
			headers: "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
			line:    "X-New: value",
			want:    "GET / HTTP/1.1\r\nHost: x\r\nX-New: value\r\n\r\n",
		},
		{
			name:    "bare_lf_insert",
			headers: "GET / HTTP/1.1\nHost: x\n\n",
			line:    "X-New: value",
			want:    "GET / HTTP/1.1\nHost: x\nX-New: value\n\n",
		},
		{
			name:    "no_blank_line",
			headers: "malformed",
			line:    "X-New: value",
			want:    "malformed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(insertBeforeBlankLine([]byte(tt.headers), tt.line)))
		})
	}
}

func TestValidateContentLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		headers      string
		body         string
		wantContains string
	}{
		{
			name:    "no_cl_header",
			headers: "POST / HTTP/1.1\r\nHost: x\r\n\r\n",
			body:    "hello",
		},
		{
			name:    "matching_length",
			headers: "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
			body:    "hello",
		},
		{
			name:         "mismatched_length",
			headers:      "POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\n",
			body:         "short",
			wantContains: "does not match",
		},
		{
			name:    "space_before_colon_match",
			headers: "POST / HTTP/1.1\r\nContent-Length : 5\r\n\r\n",
			body:    "12345",
		},
		{
			name:         "space_before_colon_mismatch",
			headers:      "POST / HTTP/1.1\r\nContent-Length : 10\r\n\r\n",
			body:         "short",
			wantContains: "does not match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateContentLength([]byte(tt.headers), []byte(tt.body))
			if tt.wantContains != "" {
				assert.Contains(t, result, tt.wantContains)
			} else {
				assert.Empty(t, result)
			}
		})
	}
}

func TestExtractHeaderLines(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "crlf_headers",
			raw:  "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n",
			want: []string{"Host: example.com", "Accept: */*"},
		},
		{
			name: "bare_lf_headers",
			raw:  "GET / HTTP/1.1\nHost: example.com\nAccept: */*\n\n",
			want: []string{"Host: example.com", "Accept: */*"},
		},
		{
			name: "single_line",
			raw:  "GET / HTTP/1.1\r\n",
			want: nil,
		},
		{
			name: "empty",
			raw:  "",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractHeaderLines(tt.raw))
		})
	}
}

func TestParseHeadersToMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want map[string][]string
	}{
		{
			name: "crlf_headers",
			raw:  "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n",
			want: map[string][]string{
				"Host":   {"example.com"},
				"Accept": {"*/*"},
			},
		},
		{
			name: "bare_lf_headers",
			raw:  "GET / HTTP/1.1\nHost: example.com\nAccept: */*\n\n",
			want: map[string][]string{
				"Host":   {"example.com"},
				"Accept": {"*/*"},
			},
		},
		{
			name: "duplicate_headers",
			raw:  "GET / HTTP/1.1\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n",
			want: map[string][]string{
				"Set-Cookie": {"a=1", "b=2"},
			},
		},
		{
			name: "empty",
			raw:  "",
			want: map[string][]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseHeadersToMap(tt.raw))
		})
	}
}

func TestCompressBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		body         []byte
		encoding     string
		wantCompress bool
		wantFailed   bool
	}{
		{
			name:         "gzip_compress",
			body:         []byte("Hello, World!"),
			encoding:     "gzip",
			wantCompress: true,
			wantFailed:   false,
		},
		{
			name:         "deflate_compress",
			body:         []byte("Deflate test content"),
			encoding:     "deflate",
			wantCompress: true,
			wantFailed:   false,
		},
		{
			name:         "empty_encoding_passthrough",
			body:         []byte("Plain text"),
			encoding:     "",
			wantCompress: false,
			wantFailed:   false,
		},
		{
			name:         "unsupported_encoding_passthrough",
			body:         []byte("Plain text"),
			encoding:     "br",
			wantCompress: false,
			wantFailed:   false,
		},
		{
			name:         "multiple_encodings_passthrough",
			body:         []byte("Plain text"),
			encoding:     "gzip, br",
			wantCompress: false,
			wantFailed:   false,
		},
		{
			name:         "empty_body_gzip",
			body:         []byte{},
			encoding:     "gzip",
			wantCompress: true,
			wantFailed:   false,
		},
		{
			name:         "x-gzip_alias",
			body:         []byte("Test content"),
			encoding:     "x-gzip",
			wantCompress: true,
			wantFailed:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, failed := compressBody(tt.body, tt.encoding)
			assert.Equal(t, tt.wantFailed, failed)
			if tt.wantCompress {
				assert.NotEqual(t, tt.body, result, "body should be compressed")
				// Verify round-trip
				headerStr := "Content-Encoding: " + tt.encoding + "\r\n"
				decompressed, wasDecompressed := decompressForDisplay(result, headerStr)
				assert.True(t, wasDecompressed || len(tt.body) == 0)
				assert.Equal(t, string(tt.body), string(decompressed))
			} else {
				assert.Equal(t, string(tt.body), string(result), "body should be unchanged")
			}
		})
	}
}

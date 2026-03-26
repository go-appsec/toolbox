package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertHeadersEqual compares headers ignoring RawLine field
func assertHeadersEqual(t *testing.T, expected, actual Headers) {
	t.Helper()

	require.Len(t, actual, len(expected))
	for i := range expected {
		assert.Equal(t, expected[i].Name, actual[i].Name, "header[%d].Name", i)
		assert.Equal(t, expected[i].Value, actual[i].Value, "header[%d].Value", i)
	}
}

func TestParseRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    *RawHTTP1Request
		wantErr bool
	}{
		{
			name:  "simple_get",
			input: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Query:    "",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
				},
			},
		},
		{
			name:  "path_with_query",
			input: "GET /api/users?id=123&name=test HTTP/1.1\r\nHost: example.com\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/api/users",
				Query:    "id=123&name=test",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
				},
			},
		},
		{
			name:  "post_with_body",
			input: "POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\nHello, World!",
			want: &RawHTTP1Request{
				Method:   "POST",
				Path:     "/api/data",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Content-Length", Value: "13"},
				},
				Body: []byte("Hello, World!"),
			},
		},
		{
			name:  "header_order_preserved",
			input: "GET / HTTP/1.1\r\nZebra: 1\r\nAlpha: 2\r\nMiddle: 3\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Zebra", Value: "1"},
					{Name: "Alpha", Value: "2"},
					{Name: "Middle", Value: "3"},
				},
			},
		},
		{
			name:  "casing_preserved",
			input: "GET / HTTP/1.1\r\ncontent-type: text/plain\r\nCONTENT-LENGTH: 0\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "content-type", Value: "text/plain"},
					{Name: "CONTENT-LENGTH", Value: "0"},
				},
			},
		},
		{
			name:  "duplicate_headers",
			input: "GET / HTTP/1.1\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nSet-Cookie: c=3\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Set-Cookie", Value: "a=1"},
					{Name: "Set-Cookie", Value: "b=2"},
					{Name: "Set-Cookie", Value: "c=3"},
				},
			},
		},
		{
			name:  "bare_lf_accepted",
			input: "GET / HTTP/1.1\nHost: example.com\n\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
				},
			},
		},
		{
			name:  "whitespace_in_header_name",
			input: "GET / HTTP/1.1\r\nHeader : value\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Header ", Value: "value"},
				},
			},
		},
		{
			name:  "no_space_after_colon",
			input: "GET / HTTP/1.1\r\nHeader:value\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Header", Value: "value"},
				},
			},
		},
		{
			name:  "empty_header_value",
			input: "GET / HTTP/1.1\r\nEmpty: \r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Empty", Value: ""},
				},
			},
		},
		{
			name:  "obs_fold_continuation",
			input: "GET / HTTP/1.1\r\nLong-Header: first\r\n second\r\n\tthird\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Long-Header", Value: "first second third"},
				},
			},
		},
		{
			name:  "http_1_0",
			input: "GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.0",
				Protocol: "http/1.0",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
				},
			},
		},
		{
			name:  "proxy_form_url",
			input: "GET http://example.com/path?q=1 HTTP/1.1\r\nHost: proxy.local\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "http://example.com/path",
				Query:    "q=1",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Host", Value: "proxy.local"},
				},
			},
		},
		{
			name:  "cl_te_conflict",
			input: "POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nHello",
			want: &RawHTTP1Request{
				Method:   "POST",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Content-Length", Value: "5"},
					{Name: "Transfer-Encoding", Value: "chunked"},
				},
				Body: []byte{}, // chunked takes precedence but "Hello" isn't valid chunked
			},
		},
		{
			name:  "multiple_content_length",
			input: "GET / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 5\r\n\r\n",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Content-Length", Value: "0"},
					{Name: "Content-Length", Value: "5"},
				},
			},
		},
		{
			name:  "eof_no_trailing_newline",
			input: "GET / HTTP/1.1",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
			},
		},
		{
			name:  "eof_after_headers",
			input: "GET / HTTP/1.1\r\nHost: example.com",
			want: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
				},
			},
		},
		{
			name:    "empty_request",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid_request_line",
			input:   "INVALID\r\n\r\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRequest(strings.NewReader(tt.input))

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want.Method, got.Method)
			assert.Equal(t, tt.want.Path, got.Path)
			assert.Equal(t, tt.want.Query, got.Query)
			assert.Equal(t, tt.want.Version, got.Version)
			assert.Equal(t, tt.want.Protocol, got.Protocol)
			assertHeadersEqual(t, tt.want.Headers, got.Headers)
			if len(tt.want.Body) == 0 {
				assert.Empty(t, got.Body)
			} else {
				assert.Equal(t, tt.want.Body, got.Body)
			}
		})
	}

	t.Run("non_eof_error_empty", func(t *testing.T) {
		_, err := parseRequest(iotest.ErrReader(errors.New("network error")))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "network error")
	})

	t.Run("non_eof_error_partial", func(t *testing.T) {
		// Reader returns partial data then a non-EOF error;
		// parseRequest should return the error, not attempt to parse.
		r := io.MultiReader(strings.NewReader("GET /"), iotest.ErrReader(errors.New("connection reset")))
		_, err := parseRequest(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "connection reset")
	})

	t.Run("chunked_body", func(t *testing.T) {
		input := "POST /upload HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"5\r\n" +
			"Hello\r\n" +
			"6\r\n" +
			"World!\r\n" +
			"0\r\n" +
			"\r\n"

		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		assert.Equal(t, "POST", req.Method)
		assert.Equal(t, "/upload", req.Path)
		assert.Equal(t, []byte("HelloWorld!"), req.Body)
	})

	t.Run("chunked_with_trailers", func(t *testing.T) {
		input := "POST /upload HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Trailer: Checksum\r\n" +
			"\r\n" +
			"5\r\n" +
			"Hello\r\n" +
			"0\r\n" +
			"Checksum: abc123\r\n" +
			"\r\n"

		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		assert.Equal(t, []byte("Hello"), req.Body)
		assert.Contains(t, string(req.Trailers), "Checksum: abc123")
	})

	t.Run("large_header_value", func(t *testing.T) {
		largeValue := strings.Repeat("x", 10000)
		input := "GET / HTTP/1.1\r\nHost: example.com\r\nX-Large: " + largeValue + "\r\n\r\n"

		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		assert.Equal(t, largeValue, req.GetHeader("X-Large"))
	})

	t.Run("invalid_header_name", func(t *testing.T) {
		input := "GET / HTTP/1.1\r\nInvalid<Header>: value\r\n\r\n"

		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		assert.Equal(t, "Invalid<Header>", req.Headers[0].Name)
		assert.Equal(t, "value", req.Headers[0].Value)
	})

	t.Run("control_characters", func(t *testing.T) {
		input := "GET / HTTP/1.1\r\nX-Test: value\twith\ttabs\r\n\r\n"

		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		assert.Equal(t, "value\twith\ttabs", req.GetHeader("X-Test"))
	})

	t.Run("round_trip", func(t *testing.T) {
		cases := []struct {
			name  string
			input string
		}{
			{
				name:  "simple_get",
				input: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			},
			{
				name:  "with_body",
				input: "POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nHello",
			},
			{
				name:  "multiple_headers",
				input: "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nUser-Agent: test\r\n\r\n",
			},
		}

		var buf bytes.Buffer
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				req, err := parseRequest(strings.NewReader(tc.input))
				require.NoError(t, err)

				assert.Equal(t, tc.input, string(req.SerializeRaw(&buf, false)))
			})
		}
	})

	t.Run("header_without_colon", func(t *testing.T) {
		input := "GET / HTTP/1.1\r\nHeaderNoColon\r\nHost: example.com\r\n\r\n"

		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		// Header without colon gets name = full line, value = empty
		assert.Equal(t, "HeaderNoColon", req.Headers[0].Name)
		assert.Empty(t, req.Headers[0].Value)
	})

	t.Run("negative_content_length", func(t *testing.T) {
		input := "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: -5\r\n\r\n"

		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		// Negative content-length should result in no body read
		assert.Empty(t, req.Body)
	})

	t.Run("non_numeric_content_length", func(t *testing.T) {
		input := "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: abc\r\n\r\n"

		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		// Non-numeric content-length should be skipped
		assert.Empty(t, req.Body)
	})

	// edge cases
	t.Run("asterisk_form_url", func(t *testing.T) {
		input := "OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)
		assert.Equal(t, "OPTIONS", req.Method)
		assert.Equal(t, "*", req.Path)
	})

	t.Run("connect_authority_form", func(t *testing.T) {
		input := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)
		assert.Equal(t, "CONNECT", req.Method)
		assert.Equal(t, "example.com:443", req.Path)
	})

	t.Run("multiple_question_marks", func(t *testing.T) {
		input := "GET /search?q=what?really? HTTP/1.1\r\nHost: example.com\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)
		assert.Equal(t, "/search", req.Path)
		assert.Equal(t, "q=what?really?", req.Query)
	})

	t.Run("header_with_multiple_colons", func(t *testing.T) {
		input := "GET / HTTP/1.1\r\nAuthorization: Bearer: token: value\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)
		assert.Equal(t, "Bearer: token: value", req.GetHeader("Authorization"))
	})

	t.Run("header_only_colon", func(t *testing.T) {
		input := "GET / HTTP/1.1\r\n:\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)
		assert.Len(t, req.Headers, 1)
		assert.Empty(t, req.Headers[0].Name)
	})

	t.Run("header_value_leading_tab", func(t *testing.T) {
		input := "GET / HTTP/1.1\r\nHeader:\tvalue\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)
		assert.Equal(t, "value", req.GetHeader("Header"))
	})

	t.Run("https_proxy_form", func(t *testing.T) {
		input := "GET https://example.com/path?q=1 HTTP/1.1\r\nHost: proxy.local\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/path", req.Path)
		assert.Equal(t, "q=1", req.Query)
	})

	t.Run("content_length_zero_explicit", func(t *testing.T) {
		input := "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)
		assert.Empty(t, req.Body)
	})

	t.Run("many_headers", func(t *testing.T) {
		var headers strings.Builder
		for i := 0; i < 100; i++ {
			headers.WriteString("X-Header-" + string(rune('A'+i%26)) + ": value\r\n")
		}
		input := "GET / HTTP/1.1\r\n" + headers.String() + "\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)
		assert.Len(t, req.Headers, 100)
	})
}

func TestParseResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		input         string
		requestMethod string
		want          *RawHTTP1Response
		wantErr       bool
	}{
		{
			name:          "simple_200",
			input:         "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello",
			requestMethod: "GET",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "Content-Length", Value: "5"},
				},
				Body: []byte("Hello"),
			},
		},
		{
			name:          "head_no_body",
			input:         "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n",
			requestMethod: "HEAD",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "Content-Length", Value: "1000"},
				},
			},
		},
		{
			name:          "204_no_body",
			input:         "HTTP/1.1 204 No Content\r\n\r\n",
			requestMethod: "DELETE",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 204,
				StatusText: "No Content",
				Headers:    []Header{},
			},
		},
		{
			name:          "304_no_body",
			input:         "HTTP/1.1 304 Not Modified\r\nETag: \"abc\"\r\n\r\n",
			requestMethod: "GET",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 304,
				StatusText: "Not Modified",
				Headers: []Header{
					{Name: "ETag", Value: "\"abc\""},
				},
			},
		},
		{
			name:          "header_casing_preserved",
			input:         "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nX-CUSTOM: value\r\n\r\n",
			requestMethod: "GET",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "content-type", Value: "text/plain"},
					{Name: "X-CUSTOM", Value: "value"},
				},
			},
		},
		{
			name:          "empty_status_text",
			input:         "HTTP/1.1 200\r\n\r\n",
			requestMethod: "GET",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "",
				Headers:    []Header{},
			},
		},
		{
			name:          "http_1_0",
			input:         "HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nBody",
			requestMethod: "GET",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.0",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "Connection", Value: "close"},
				},
				Body: []byte("Body"),
			},
		},
		{
			name:          "chunked_response",
			input:         "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n",
			requestMethod: "GET",
			want: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "Transfer-Encoding", Value: "chunked"},
				},
				Body: []byte("Hello"),
			},
		},
		{
			name:          "empty_response",
			input:         "",
			requestMethod: "GET",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseResponse(strings.NewReader(tt.input), tt.requestMethod)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want.Version, got.Version)
			assert.Equal(t, tt.want.StatusCode, got.StatusCode)
			assert.Equal(t, tt.want.StatusText, got.StatusText)
			if len(tt.want.Headers) == 0 {
				assert.Empty(t, got.Headers)
			} else {
				assertHeadersEqual(t, tt.want.Headers, got.Headers)
			}
			if len(tt.want.Body) == 0 {
				assert.Empty(t, got.Body)
			} else {
				assert.Equal(t, tt.want.Body, got.Body)
			}
		})
	}

	// edge cases
	t.Run("status_leading_zeros", func(t *testing.T) {
		input := "HTTP/1.1 0200 OK\r\n\r\n"
		resp, err := parseResponse(strings.NewReader(input), "GET")
		require.NoError(t, err)
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("1xx_status_no_body", func(t *testing.T) {
		tests := []struct {
			input string
			code  int
		}{
			{"HTTP/1.1 100 Continue\r\n\r\n", 100},
			{"HTTP/1.1 101 Switching Protocols\r\n\r\n", 101},
			{"HTTP/1.1 102 Processing\r\n\r\n", 102},
			{"HTTP/1.1 103 Early Hints\r\n\r\n", 103},
		}
		for _, tt := range tests {
			resp, err := parseResponse(strings.NewReader(tt.input), "GET")
			require.NoError(t, err)
			assert.Equal(t, tt.code, resp.StatusCode)
			assert.Empty(t, resp.Body)
		}
	})

	t.Run("status_text_with_numbers", func(t *testing.T) {
		input := "HTTP/1.1 404 Not Found 2024\r\n\r\n"
		resp, err := parseResponse(strings.NewReader(input), "GET")
		require.NoError(t, err)
		assert.Equal(t, "Not Found 2024", resp.StatusText)
	})

	t.Run("non_chunked_transfer_encoding", func(t *testing.T) {
		input := "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 5\r\n\r\nHello"
		resp, err := parseResponse(strings.NewReader(input), "GET")
		require.NoError(t, err)
		// gzip TE should be treated as non-chunked, use Content-Length
		assert.Equal(t, []byte("Hello"), resp.Body)
	})

	t.Run("multiple_transfer_encoding_headers", func(t *testing.T) {
		input := "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n"
		resp, err := parseResponse(strings.NewReader(input), "GET")
		require.NoError(t, err)
		// GetHeader returns first header, so "gzip" is seen, not chunked
		// Body is read until EOF as raw bytes
		assert.Equal(t, []byte("5\r\nHello\r\n0\r\n\r\n"), resp.Body)
	})

	t.Run("extra_whitespace_in_status", func(t *testing.T) {
		input := "HTTP/1.1  200  OK\r\nContent-Length: 5\r\n\r\nHello"
		_, err := parseResponse(strings.NewReader(input), "GET")
		// Parser rejects extra whitespace in status line
		require.Error(t, err)
	})
}

func TestRawHTTP1Request_Serialize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  *RawHTTP1Request
		want string
	}{
		{
			name: "simple_get",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
				},
			},
			want: "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name: "with_query",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/api/users",
				Query:   "id=123",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
				},
			},
			want: "GET /api/users?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name: "with_body",
			req: &RawHTTP1Request{
				Method:  "POST",
				Path:    "/api/data",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Content-Type", Value: "text/plain"},
				},
				Body: []byte("Hello"),
			},
			want: "POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nHello",
		},
		{
			name: "preserves_casing",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "content-type", Value: "text/plain"},
					{Name: "X-CUSTOM-HEADER", Value: "value"},
				},
			},
			want: "GET / HTTP/1.1\r\ncontent-type: text/plain\r\nX-CUSTOM-HEADER: value\r\n\r\n",
		},
		{
			name: "preserves_order",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Zebra", Value: "last"},
					{Name: "Alpha", Value: "first"},
					{Name: "Middle", Value: "middle"},
				},
			},
			want: "GET / HTTP/1.1\r\nZebra: last\r\nAlpha: first\r\nMiddle: middle\r\n\r\n",
		},
	}

	var buf bytes.Buffer
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.req.SerializeRaw(&buf, false)))
		})
	}

	t.Run("removes_chunked", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "POST",
			Path:    "/",
			Version: "HTTP/1.1",
			Headers: []Header{
				{Name: "Host", Value: "example.com"},
				{Name: "Transfer-Encoding", Value: "chunked"},
			},
			Body: []byte("Hello"),
		}

		serialized := string(req.SerializeRaw(bytes.NewBuffer(nil), false))

		assert.NotContains(t, serialized, "Transfer-Encoding")
		assert.Contains(t, serialized, "Content-Length: 5")
	})

	t.Run("idempotent", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "POST",
			Path:    "/",
			Version: "HTTP/1.1",
			Headers: []Header{
				{Name: "Host", Value: "example.com"},
				{Name: "Transfer-Encoding", Value: "chunked"},
			},
			Body: []byte("test"),
		}

		first := req.SerializeRaw(bytes.NewBuffer(nil), false)
		second := req.SerializeRaw(bytes.NewBuffer(nil), false)
		third := req.SerializeRaw(bytes.NewBuffer(nil), false)

		assert.Equal(t, first, second)
		assert.Equal(t, second, third)
		assert.Len(t, req.Headers, 2)
		assert.Equal(t, "Transfer-Encoding", req.Headers[1].Name)
	})
}

func TestRawHTTP1Response_Serialize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		resp *RawHTTP1Response
		want string
	}{
		{
			name: "simple_200",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "Content-Type", Value: "text/plain"},
				},
				Body: []byte("Hello"),
			},
			want: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nHello",
		},
		{
			name: "no_status_text",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 204,
				Headers:    []Header{},
			},
			want: "HTTP/1.1 204\r\n\r\n",
		},
		{
			name: "preserves_header_casing",
			resp: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "content-type", Value: "text/plain"},
					{Name: "X-CUSTOM", Value: "value"},
				},
			},
			want: "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nX-CUSTOM: value\r\n\r\n",
		},
	}

	var buf bytes.Buffer
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(tt.resp.SerializeRaw(&buf, false)))
		})
	}

	t.Run("idempotent", func(t *testing.T) {
		resp := &RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Headers: []Header{
				{Name: "Transfer-Encoding", Value: "chunked"},
			},
			Body: []byte("test"),
		}

		first := resp.SerializeRaw(bytes.NewBuffer(nil), false)
		second := resp.SerializeRaw(bytes.NewBuffer(nil), false)

		assert.Equal(t, first, second)
		assert.Len(t, resp.Headers, 1)
		assert.Equal(t, "Transfer-Encoding", resp.Headers[0].Name)
	})
}

func TestRawHTTP1Request_GetHeader(t *testing.T) {
	t.Parallel()

	req := &RawHTTP1Request{
		Headers: []Header{
			{Name: "Content-Type", Value: "text/plain"},
			{Name: "X-Custom", Value: "value1"},
			{Name: "x-custom", Value: "value2"},
		},
	}

	assert.Equal(t, "text/plain", req.GetHeader("content-type"))
	assert.Equal(t, "text/plain", req.GetHeader("Content-Type"))
	assert.Equal(t, "value1", req.GetHeader("X-Custom"))
	assert.Equal(t, "value1", req.GetHeader("x-custom"))
	assert.Empty(t, req.GetHeader("Missing"))
}

func TestRawHTTP1Request_SetHeader(t *testing.T) {
	t.Parallel()

	t.Run("update_existing", func(t *testing.T) {
		req := &RawHTTP1Request{
			Headers: []Header{
				{Name: "Content-Type", Value: "text/plain"},
			},
		}

		req.SetHeader("Content-Type", "application/json")
		assert.Equal(t, "application/json", req.GetHeader("Content-Type"))
	})

	t.Run("add_new", func(t *testing.T) {
		req := &RawHTTP1Request{
			Headers: []Header{
				{Name: "Content-Type", Value: "text/plain"},
			},
		}

		req.SetHeader("X-New", "value")
		assert.Equal(t, "value", req.GetHeader("X-New"))
	})
}

func TestRawHTTP1Request_RemoveHeader(t *testing.T) {
	t.Parallel()

	req := &RawHTTP1Request{
		Headers: []Header{
			{Name: "Content-Type", Value: "text/plain"},
			{Name: "X-Remove", Value: "value1"},
			{Name: "x-remove", Value: "value2"},
			{Name: "Keep", Value: "keep"},
		},
	}

	req.RemoveHeader("X-Remove")

	assert.Empty(t, req.GetHeader("X-Remove"))
	assert.Equal(t, "text/plain", req.GetHeader("Content-Type"))
	assert.Equal(t, "keep", req.GetHeader("Keep"))
	assert.Len(t, req.Headers, 2)
}

func TestParseRequestLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantMethod  string
		wantPath    string
		wantQuery   string
		wantVersion string
		wantErr     bool
	}{
		{
			name:        "standard",
			input:       "GET /path HTTP/1.1",
			wantMethod:  "GET",
			wantPath:    "/path",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "with_query",
			input:       "POST /api?foo=bar HTTP/1.1",
			wantMethod:  "POST",
			wantPath:    "/api",
			wantQuery:   "foo=bar",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "proxy_form",
			input:       "GET http://example.com/path?q=1 HTTP/1.1",
			wantMethod:  "GET",
			wantPath:    "http://example.com/path",
			wantQuery:   "q=1",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "no_version",
			input:       "GET /",
			wantMethod:  "GET",
			wantPath:    "/",
			wantVersion: "HTTP/1.1",
		},
		{
			name:    "invalid",
			input:   "INVALID",
			wantErr: true,
		},
		// edge cases
		{
			name:        "asterisk_form",
			input:       "OPTIONS * HTTP/1.1",
			wantMethod:  "OPTIONS",
			wantPath:    "*",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "authority_form",
			input:       "CONNECT example.com:443 HTTP/1.1",
			wantMethod:  "CONNECT",
			wantPath:    "example.com:443",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "lowercase_method",
			input:       "get / HTTP/1.1",
			wantMethod:  "get",
			wantPath:    "/",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "lowercase_http_version",
			input:       "GET / http/1.1",
			wantMethod:  "GET",
			wantPath:    "/",
			wantVersion: "http/1.1",
		},
		{
			name:    "only_method",
			input:   "GET",
			wantErr: true,
		},
		{
			name:        "empty_query",
			input:       "GET /path? HTTP/1.1",
			wantMethod:  "GET",
			wantPath:    "/path",
			wantVersion: "HTTP/1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, path, query, version, err := ParseRequestLine([]byte(tt.input))

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantMethod, method)
			assert.Equal(t, tt.wantPath, path)
			assert.Equal(t, tt.wantQuery, query)
			assert.Equal(t, tt.wantVersion, version)
		})
	}
}

func TestParseStatusLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantVersion string
		wantCode    int
		wantText    string
		wantErr     bool
	}{
		{
			name:        "standard",
			input:       "HTTP/1.1 200 OK",
			wantVersion: "HTTP/1.1",
			wantCode:    200,
			wantText:    "OK",
		},
		{
			name:        "no_reason",
			input:       "HTTP/1.1 204",
			wantVersion: "HTTP/1.1",
			wantCode:    204,
			wantText:    "",
		},
		{
			name:        "multi_word_reason",
			input:       "HTTP/1.1 404 Not Found",
			wantVersion: "HTTP/1.1",
			wantCode:    404,
			wantText:    "Not Found",
		},
		{
			name:    "invalid_code",
			input:   "HTTP/1.1 ABC",
			wantErr: true,
		},
		{
			name:    "too_short",
			input:   "HTTP/1.1",
			wantErr: true,
		},
		{
			name:        "status_100_continue",
			input:       "HTTP/1.1 100 Continue",
			wantVersion: "HTTP/1.1",
			wantCode:    100,
			wantText:    "Continue",
		},
		{
			name:        "status_101_switching",
			input:       "HTTP/1.1 101 Switching Protocols",
			wantVersion: "HTTP/1.1",
			wantCode:    101,
			wantText:    "Switching Protocols",
		},
		{
			name:        "status_204_no_content",
			input:       "HTTP/1.1 204 No Content",
			wantVersion: "HTTP/1.1",
			wantCode:    204,
			wantText:    "No Content",
		},
		{
			name:        "status_301_redirect",
			input:       "HTTP/1.1 301 Moved Permanently",
			wantVersion: "HTTP/1.1",
			wantCode:    301,
			wantText:    "Moved Permanently",
		},
		{
			name:        "status_400_bad_request",
			input:       "HTTP/1.1 400 Bad Request",
			wantVersion: "HTTP/1.1",
			wantCode:    400,
			wantText:    "Bad Request",
		},
		{
			name:        "status_500_server_error",
			input:       "HTTP/1.1 500 Internal Server Error",
			wantVersion: "HTTP/1.1",
			wantCode:    500,
			wantText:    "Internal Server Error",
		},
		{
			name:        "status_599_boundary",
			input:       "HTTP/1.1 599 Custom Error",
			wantVersion: "HTTP/1.1",
			wantCode:    599,
			wantText:    "Custom Error",
		},
		{
			name:        "http_1_0_status",
			input:       "HTTP/1.0 200 OK",
			wantVersion: "HTTP/1.0",
			wantCode:    200,
			wantText:    "OK",
		},
		// edge cases
		{
			name:        "leading_zero_status",
			input:       "HTTP/1.1 0404 Not Found",
			wantVersion: "HTTP/1.1",
			wantCode:    404,
			wantText:    "Not Found",
		},
		{
			name:        "nonstandard_status_code",
			input:       "HTTP/1.1 999 Custom Status",
			wantVersion: "HTTP/1.1",
			wantCode:    999,
			wantText:    "Custom Status",
		},
		{
			name:        "negative_status_code",
			input:       "HTTP/1.1 -200 OK",
			wantVersion: "HTTP/1.1",
			wantCode:    -200, // permissive parsing for security testing
			wantText:    "OK",
		},
		{
			name:        "status_code_too_large",
			input:       "HTTP/1.1 99999 Error",
			wantVersion: "HTTP/1.1",
			wantCode:    99999, // permissive parsing for security testing
			wantText:    "Error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, code, text, err := parseStatusLine([]byte(tt.input))

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantVersion, version)
			assert.Equal(t, tt.wantCode, code)
			assert.Equal(t, tt.wantText, text)
		})
	}
}

func TestRawHTTP1Response_SerializeHeaders(t *testing.T) {
	t.Parallel()

	t.Run("excludes_body", func(t *testing.T) {
		resp := &RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Headers: []Header{
				{Name: "Content-Type", Value: "text/plain"},
			},
			Body: []byte("This is the response body"),
		}

		buf := bytes.NewBuffer(nil)
		headers := resp.SerializeHeaders(buf)

		assert.Contains(t, string(headers), "HTTP/1.1 200 OK")
		assert.Contains(t, string(headers), "Content-Type: text/plain")
		assert.Contains(t, string(headers), "Content-Length: 25")
		assert.NotContains(t, string(headers), "This is the response body")
		assert.True(t, bytes.HasSuffix(headers, []byte("\r\n\r\n")))
	})

	t.Run("updates_content_length", func(t *testing.T) {
		resp := &RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Headers: []Header{
				{Name: "Content-Length", Value: "999"},
			},
			Body: []byte("short"),
		}

		buf := bytes.NewBuffer(nil)
		headers := resp.SerializeHeaders(buf)

		assert.Contains(t, string(headers), "Content-Length: 5")
		assert.NotContains(t, string(headers), "Content-Length: 999")
	})

	t.Run("strips_chunked_encoding", func(t *testing.T) {
		resp := &RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Headers: []Header{
				{Name: "Transfer-Encoding", Value: "chunked"},
			},
			Body: []byte("decoded body"),
		}

		buf := bytes.NewBuffer(nil)
		headers := resp.SerializeHeaders(buf)

		assert.NotContains(t, string(headers), "Transfer-Encoding")
		assert.Contains(t, string(headers), "Content-Length: 12")
	})

	t.Run("empty_body", func(t *testing.T) {
		resp := &RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 204,
			StatusText: "No Content",
			Headers: []Header{
				{Name: "X-Custom", Value: "value"},
			},
		}

		buf := bytes.NewBuffer(nil)
		headers := resp.SerializeHeaders(buf)

		assert.Contains(t, string(headers), "HTTP/1.1 204 No Content")
		assert.Contains(t, string(headers), "X-Custom: value")
		assert.NotContains(t, string(headers), "Content-Length")
	})
}

func TestReadChunkedBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		wantBody     string
		wantTrailers string
	}{
		{
			name:     "simple",
			input:    "5\r\nHello\r\n0\r\n\r\n",
			wantBody: "Hello",
		},
		{
			name:     "multiple_chunks",
			input:    "5\r\nHello\r\n6\r\n World\r\n0\r\n\r\n",
			wantBody: "Hello World",
		},
		{
			name:         "with_trailers",
			input:        "5\r\nHello\r\n0\r\nChecksum: abc\r\n\r\n",
			wantBody:     "Hello",
			wantTrailers: "Checksum: abc\r\n",
		},
		{
			name:     "chunk_extensions",
			input:    "5;ext=val\r\nHello\r\n0\r\n\r\n",
			wantBody: "Hello",
		},
		{
			name:     "hex_size_uppercase",
			input:    "A\r\n0123456789\r\n0\r\n\r\n",
			wantBody: "0123456789",
		},
		{
			name:     "hex_size_lowercase",
			input:    "a\r\n0123456789\r\n0\r\n\r\n",
			wantBody: "0123456789",
		},
		{
			name:     "hex_size_with_leading_zero",
			input:    "05\r\nHello\r\n0\r\n\r\n",
			wantBody: "Hello",
		},
		{
			name:     "empty_chunks",
			input:    "0\r\n\r\n",
			wantBody: "",
		},
		{
			name:     "single_byte_chunk",
			input:    "1\r\nX\r\n0\r\n\r\n",
			wantBody: "X",
		},
		{
			name:         "multiple_trailers",
			input:        "5\r\nHello\r\n0\r\nX-Checksum: abc\r\nX-Signature: xyz\r\n\r\n",
			wantBody:     "Hello",
			wantTrailers: "X-Checksum: abc\r\nX-Signature: xyz\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := bufio.NewReader(bytes.NewReader([]byte(tt.input)))
			body, trailers, err := readChunkedBody(br)
			require.NoError(t, err)

			assert.Equal(t, tt.wantBody, string(body))
			assert.Equal(t, tt.wantTrailers, string(trailers))
		})
	}

	// edge cases
	t.Run("invalid_hex_chunk_size", func(t *testing.T) {
		input := "GG\r\nHello\r\n0\r\n\r\n"
		br := bufio.NewReader(bytes.NewReader([]byte(input)))
		body, _, err := readChunkedBody(br)
		// Permissive parsing: returns empty body and no error on invalid hex
		require.NoError(t, err)
		assert.Empty(t, body)
	})

	t.Run("large_hex_chunk_size", func(t *testing.T) {
		// Very large chunk size - should handle gracefully
		input := "FFFFF\r\n" // Declares ~1MB chunk but has no data
		br := bufio.NewReader(bytes.NewReader([]byte(input)))
		_, _, err := readChunkedBody(br)
		// Should error due to missing data
		assert.Error(t, err)
	})

	t.Run("chunk_extension_with_quotes", func(t *testing.T) {
		input := "5;name=\"val;ue\"\r\nHello\r\n0\r\n\r\n"
		br := bufio.NewReader(bytes.NewReader([]byte(input)))
		body, _, err := readChunkedBody(br)
		require.NoError(t, err)
		assert.Equal(t, "Hello", string(body))
	})

	t.Run("bare_lf_in_chunked", func(t *testing.T) {
		input := "5\nHello\n0\n\n"
		br := bufio.NewReader(bytes.NewReader([]byte(input)))
		body, _, err := readChunkedBody(br)
		require.NoError(t, err)
		assert.Equal(t, "Hello", string(body))
	})
}

func TestSerializeRequestWithTrailers(t *testing.T) {
	t.Parallel()

	req := &RawHTTP1Request{
		Method:  "POST",
		Path:    "/upload",
		Version: "HTTP/1.1",
		Headers: []Header{
			{Name: "Host", Value: "example.com"},
		},
		Body:     []byte("Hello"),
		Trailers: []byte("Checksum: abc\r\n"),
	}

	var buf bytes.Buffer
	serialized := req.SerializeRaw(&buf, false)

	assert.Contains(t, string(serialized), "POST /upload HTTP/1.1")
	assert.Contains(t, string(serialized), "Content-Length: 5")
	assert.Contains(t, string(serialized), "Hello")
	// Note: trailers may or may not be included depending on implementation
}

func TestReadLineWithEnding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantLine   string
		wantBareLF bool
	}{
		{
			name:       "crlf",
			input:      "hello\r\n",
			wantLine:   "hello",
			wantBareLF: false,
		},
		{
			name:       "bare_lf",
			input:      "hello\n",
			wantLine:   "hello",
			wantBareLF: true,
		},
		{
			name:       "empty_crlf",
			input:      "\r\n",
			wantLine:   "",
			wantBareLF: false,
		},
		{
			name:       "empty_lf",
			input:      "\n",
			wantLine:   "",
			wantBareLF: true,
		},
		{
			name:       "content_with_cr",
			input:      "hello\rworld\r\n",
			wantLine:   "hello\rworld",
			wantBareLF: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := bufio.NewReader(strings.NewReader(tt.input))
			line, bareLF, err := readLineWithEnding(br)
			require.NoError(t, err)
			assert.Equal(t, tt.wantLine, string(line))
			assert.Equal(t, tt.wantBareLF, bareLF)
		})
	}
}

func TestHeaderRawLinePreservation(t *testing.T) {
	t.Parallel()

	t.Run("simple_header", func(t *testing.T) {
		input := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		assert.Equal(t, "Host: example.com", string(req.Headers[0].RawLine))
	})

	t.Run("obs_fold_preserved", func(t *testing.T) {
		input := "GET / HTTP/1.1\r\nLong-Header: first\r\n second\r\n\tthird\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		// RawLine should include all continuation lines
		assert.Equal(t, "Long-Header: first\r\n second\r\n\tthird", string(req.Headers[0].RawLine))
		// Value should be folded
		assert.Equal(t, "first second third", req.Headers[0].Value)
	})

	t.Run("whitespace_in_name_preserved", func(t *testing.T) {
		input := "GET / HTTP/1.1\r\nHeader : value\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		assert.Equal(t, "Header : value", string(req.Headers[0].RawLine))
		assert.Equal(t, "Header ", req.Headers[0].Name)
	})

	t.Run("multiple_headers", func(t *testing.T) {
		input := "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		assert.Equal(t, "Host: example.com", string(req.Headers[0].RawLine))
		assert.Equal(t, "Accept: */*", string(req.Headers[1].RawLine))
	})
}

func TestWireFormatTracking(t *testing.T) {
	t.Parallel()

	t.Run("crlf_no_chunked", func(t *testing.T) {
		input := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)
		assert.Nil(t, req.Wire)
	})

	t.Run("bare_lf_request", func(t *testing.T) {
		input := "GET / HTTP/1.1\nHost: example.com\n\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)
		require.NotNil(t, req.Wire)
		assert.True(t, req.Wire.UsedBareLF)
		assert.False(t, req.Wire.WasChunked)
	})

	t.Run("chunked_request", func(t *testing.T) {
		input := "POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)
		require.NotNil(t, req.Wire)
		assert.True(t, req.Wire.WasChunked)
		assert.False(t, req.Wire.UsedBareLF)
	})

	t.Run("bare_lf_response", func(t *testing.T) {
		input := "HTTP/1.1 200 OK\nContent-Length: 5\n\nHello"
		resp, err := parseResponse(strings.NewReader(input), "GET")
		require.NoError(t, err)
		require.NotNil(t, resp.Wire)
		assert.True(t, resp.Wire.UsedBareLF)
	})

	t.Run("chunked_response", func(t *testing.T) {
		input := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n0\r\n\r\n"
		resp, err := parseResponse(strings.NewReader(input), "GET")
		require.NoError(t, err)
		require.NotNil(t, resp.Wire)
		assert.True(t, resp.Wire.WasChunked)
	})
}

func TestSerializeRawBareLF(t *testing.T) {
	t.Parallel()

	t.Run("request_bare_lf", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "GET",
			Path:    "/",
			Version: "HTTP/1.1",
			Headers: []Header{
				{Name: "Host", Value: "example.com"},
			},
			Wire: &WireFormat{UsedBareLF: true},
		}

		var buf bytes.Buffer
		serialized := req.SerializeRaw(&buf, false)

		assert.Equal(t, "GET / HTTP/1.1\nHost: example.com\n\n", string(serialized))
	})

	t.Run("response_bare_lf", func(t *testing.T) {
		resp := &RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Headers: []Header{
				{Name: "X-Test", Value: "value"},
			},
			Body: []byte("Hi"),
			Wire: &WireFormat{UsedBareLF: true},
		}

		var buf bytes.Buffer
		serialized := resp.SerializeRaw(&buf, false)

		assert.Contains(t, string(serialized), "HTTP/1.1 200 OK\n")
		assert.Contains(t, string(serialized), "X-Test: value\n")
		assert.NotContains(t, string(serialized), "\r\n")
	})
}

func TestSerializeRawChunked(t *testing.T) {
	t.Parallel()

	t.Run("request_chunked", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "POST",
			Path:    "/",
			Version: "HTTP/1.1",
			Headers: []Header{
				{Name: "Host", Value: "example.com"},
				{Name: "Transfer-Encoding", Value: "chunked"},
			},
			Body: []byte("Hello"),
			Wire: &WireFormat{WasChunked: true},
		}

		var buf bytes.Buffer
		serialized := req.SerializeRaw(&buf, true)

		assert.Contains(t, string(serialized), "Transfer-Encoding: chunked")
		assert.Contains(t, string(serialized), "5\r\nHello\r\n0\r\n\r\n")
		assert.NotContains(t, string(serialized), "Content-Length")
	})

	t.Run("request_chunked_with_trailers", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "POST",
			Path:    "/",
			Version: "HTTP/1.1",
			Headers: []Header{
				{Name: "Host", Value: "example.com"},
				{Name: "Transfer-Encoding", Value: "chunked"},
			},
			Body:     []byte("Hello"),
			Trailers: []byte("Checksum: abc\r\n"),
			Wire:     &WireFormat{WasChunked: true},
		}

		var buf bytes.Buffer
		serialized := req.SerializeRaw(&buf, true)

		assert.Contains(t, string(serialized), "5\r\nHello\r\n0\r\nChecksum: abc\r\n\r\n")
	})

	t.Run("response_chunked", func(t *testing.T) {
		resp := &RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Headers: []Header{
				{Name: "Transfer-Encoding", Value: "chunked"},
			},
			Body: []byte("Hello"),
			Wire: &WireFormat{WasChunked: true},
		}

		var buf bytes.Buffer
		serialized := resp.SerializeRaw(&buf, true)

		assert.Contains(t, string(serialized), "Transfer-Encoding: chunked")
		assert.Contains(t, string(serialized), "5\r\nHello\r\n0\r\n\r\n")
	})
}

func TestSerializeRawFallback(t *testing.T) {
	t.Parallel()

	t.Run("nil_wire", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "GET",
			Path:    "/",
			Version: "HTTP/1.1",
			Headers: []Header{
				{Name: "Host", Value: "example.com"},
			},
		}

		var buf bytes.Buffer
		serialized := req.SerializeRaw(&buf, false)

		// Should use CRLF when Wire is nil
		assert.Equal(t, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", string(serialized))
	})

	t.Run("no_raw_line", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "GET",
			Path:    "/",
			Version: "HTTP/1.1",
			Headers: []Header{
				{Name: "Host", Value: "example.com"},
				{Name: "X-New", Value: "added"}, // Programmatically added, no RawLine
			},
		}

		var buf bytes.Buffer
		serialized := req.SerializeRaw(&buf, false)

		// Should use Name: Value format when RawLine is nil
		assert.Contains(t, string(serialized), "X-New: added\r\n")
	})

	t.Run("preserve_raw_line", func(t *testing.T) {
		req := &RawHTTP1Request{
			Method:  "GET",
			Path:    "/",
			Version: "HTTP/1.1",
			Headers: []Header{
				{Name: "Header ", Value: "value", RawLine: []byte("Header : value")},
			},
		}

		var buf bytes.Buffer
		serialized := req.SerializeRaw(&buf, false)

		// Should use RawLine when available
		assert.Contains(t, string(serialized), "Header : value\r\n")
	})
}

func TestSerializeRawRoundTrip(t *testing.T) {
	t.Parallel()

	t.Run("bare_lf_round_trip", func(t *testing.T) {
		input := "GET / HTTP/1.1\nHost: example.com\nAccept: */*\n\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		var buf bytes.Buffer
		serialized := req.SerializeRaw(&buf, false)

		assert.Equal(t, input, string(serialized))
	})

	t.Run("obs_fold_round_trip", func(t *testing.T) {
		input := "GET / HTTP/1.1\r\nLong: first\r\n second\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		var buf bytes.Buffer
		serialized := req.SerializeRaw(&buf, false)

		assert.Equal(t, input, string(serialized))
	})
}

func TestCompareSerializeRedirect(t *testing.T) {
	t.Parallel()

	// Simulate a typical redirect response that the upstream might send
	input := "HTTP/1.1 307 Temporary Redirect\r\nContent-Length: 0\r\nLocation: /final\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\n\r\n"

	resp, err := parseResponse(strings.NewReader(input), "POST")
	require.NoError(t, err)

	var buf bytes.Buffer
	serialized := resp.SerializeRaw(&buf, false)
	t.Logf("Serialize output (%d bytes):\n%s", len(serialized), string(serialized))

	buf.Reset()
	serializedRaw := resp.SerializeRaw(&buf, false)
	t.Logf("SerializeRaw output (%d bytes):\n%s", len(serializedRaw), string(serializedRaw))

	// Check that both produce valid HTTP responses
	assert.Contains(t, string(serialized), "HTTP/1.1 307")
	assert.Contains(t, string(serializedRaw), "HTTP/1.1 307")
}

func TestHeadersSetClearsRawLine(t *testing.T) {
	t.Parallel()

	t.Run("set_clears_rawline", func(t *testing.T) {
		input := "GET / HTTP/1.1\r\nContent-Length: 100\r\nHost: example.com\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		// Verify RawLine is present after parsing
		require.NotNil(t, req.Headers[0].RawLine)
		assert.Equal(t, "Content-Length: 100", string(req.Headers[0].RawLine))

		// Update the header value
		req.SetHeader("Content-Length", "50")

		// Verify RawLine is cleared
		for _, h := range req.Headers {
			if strings.EqualFold(h.Name, "Content-Length") {
				assert.Nil(t, h.RawLine, "RawLine should be cleared after Set()")
				assert.Equal(t, "50", h.Value)
			}
		}

		// SerializeRaw should use new value, not old RawLine
		var buf bytes.Buffer
		serialized := req.SerializeRaw(&buf, false)
		assert.Contains(t, string(serialized), "Content-Length: 50")
		assert.NotContains(t, string(serialized), "Content-Length: 100")
	})

	t.Run("set_new_header_no_rawline", func(t *testing.T) {
		input := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
		req, err := parseRequest(strings.NewReader(input))
		require.NoError(t, err)

		// Add new header
		req.SetHeader("X-New", "value")

		// New header should not have RawLine
		for _, h := range req.Headers {
			if h.Name == "X-New" {
				assert.Nil(t, h.RawLine)
				assert.Equal(t, "value", h.Value)
			}
		}

		var buf bytes.Buffer
		serialized := req.SerializeRaw(&buf, false)
		assert.Contains(t, string(serialized), "X-New: value")
	})
}

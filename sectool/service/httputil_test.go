package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			name:     "status_204_no_content",
			input:    []byte("HTTP/1.1 204 No Content\r\n\r\n"),
			expected: 204,
		},
		{
			name:     "status_301_redirect",
			input:    []byte("HTTP/1.1 301 Moved Permanently\r\nLocation: /new\r\n\r\n"),
			expected: 301,
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
			name:     "get_http_2",
			input:    []byte("GET /path HTTP/2\r\nHost: test.com\r\n\r\n"),
			expected: []byte("GET /path HTTP/1.1\r\nHost: test.com\r\n\r\n"),
		},
		{
			name:     "http_1_1_unchanged",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "http_1_0_unchanged",
			input:    []byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"),
			expected: []byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "http_2_with_body",
			input:    []byte("POST /api HTTP/2\r\nHost: test.com\r\nContent-Length: 4\r\n\r\ntest"),
			expected: []byte("POST /api HTTP/1.1\r\nHost: test.com\r\nContent-Length: 4\r\n\r\ntest"),
		},
		{
			name:     "no_crlf",
			input:    []byte("GET / HTTP/2"),
			expected: []byte("GET / HTTP/2"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := transformRequestForValidation(tc.input)
			require.Equal(t, string(tc.expected), string(result))
		})
	}
}

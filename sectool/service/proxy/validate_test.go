package proxy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hostHeader is a convenience for test cases that need a valid Host header.
var hostHeader = Header{Name: "Host", Value: "example.com"}

func TestValidateRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		req     *RawHTTP1Request
		wantErr string
	}{
		{
			name: "valid_get",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
		},
		{
			name: "valid_post",
			req: &RawHTTP1Request{
				Method:  "POST",
				Path:    "/api/users",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "Content-Type", Value: "application/json"},
					{Name: "Content-Length", Value: "15"},
				},
				Body: []byte(`{"name":"test"}`),
			},
		},
		{
			name:    "nil_request",
			req:     nil,
			wantErr: "nil request",
		},
		{
			name: "empty_method",
			req: &RawHTTP1Request{
				Method:  "",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
			wantErr: "empty method",
		},
		{
			name: "method_with_space",
			req: &RawHTTP1Request{
				Method:  "GET POST",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
			wantErr: "invalid method characters",
		},
		{
			name: "method_with_control",
			req: &RawHTTP1Request{
				Method:  "GET\x00",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
			wantErr: "invalid method characters",
		},
		{
			name: "empty_path",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
			wantErr: "empty path",
		},
		{
			name: "invalid_version",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/2.0",
				Headers: Headers{hostHeader},
			},
			wantErr: "invalid HTTP version",
		},
		{
			name: "http_1_0_valid",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.0",
			},
		},
		{
			name: "nul_in_header_name",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "X-Bad\x00Header", Value: "value"},
				},
			},
			wantErr: "NUL byte in header name",
		},
		{
			name: "nul_in_header_value",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "X-Header", Value: "bad\x00value"},
				},
			},
			wantErr: "NUL byte in header value",
		},
		{
			name: "path_with_query",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/api/users?id=123",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
		},
		{
			name: "custom_method",
			req: &RawHTTP1Request{
				Method:  "CUSTOMMETHOD",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
		},
		{
			name: "method_with_tab",
			req: &RawHTTP1Request{
				Method:  "GET\t",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
			wantErr: "invalid method characters",
		},
		{
			name: "path_with_nul",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/path\x00inject",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
		},
		{
			name: "multiple_headers",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					{Name: "Host", Value: "example.com"},
					{Name: "Accept", Value: "*/*"},
					{Name: "User-Agent", Value: "test"},
				},
			},
		},
		{
			name: "empty_headers_http_1_0",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.0",
				Headers: Headers{},
			},
		},
		{
			name: "lowercase_method_valid",
			req: &RawHTTP1Request{
				Method:  "get",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
		},
		{
			name: "method_special_chars_only",
			req: &RawHTTP1Request{
				Method:  "!#$%",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
		},
		{
			name: "path_query_and_fragment",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/api/users?id=1#section",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
		},
		{
			name: "path_only_query",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "?query=1",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
		},
		{
			name: "path_encoded_nul",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/path%00inject",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
		},
		{
			name: "header_value_with_tab",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "X-Header", Value: "value\twith\ttabs"},
				},
			},
		},
		{
			name: "header_name_only_nul",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "\x00", Value: "value"},
				},
			},
			wantErr: "NUL byte in header name",
		},
		{
			name: "http_2_invalid_for_request",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/2",
				Headers: Headers{hostHeader},
			},
			wantErr: "invalid HTTP version",
		},
		{
			name: "http_version_with_spaces",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/ 1.1",
				Headers: Headers{hostHeader},
			},
			wantErr: "invalid HTTP version",
		},
		// New checks: header name validation
		{
			name: "header_name_with_space",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "X Header", Value: "value"},
				},
			},
			wantErr: "invalid header name",
		},
		{
			name: "header_name_trailing_space",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "Content-Type ", Value: "text/html"},
				},
			},
			wantErr: "invalid header name",
		},
		{
			name: "header_name_with_colon",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "X:Header", Value: "value"},
				},
			},
			wantErr: "invalid header name",
		},
		{
			name: "empty_header_name",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "", Value: "value"},
				},
			},
			wantErr: "empty header name",
		},
		{
			name: "header_without_colon",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "BadHeader", Value: "", RawLine: []byte("BadHeader")},
				},
			},
			wantErr: "header without colon separator",
		},
		// New checks: CR/LF in path and header values
		{
			name: "crlf_in_path",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/path\r\nX-Inject: val",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
			wantErr: "CR/LF in request path",
		},
		{
			name: "lf_in_path",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/path\ninjection",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
			wantErr: "CR/LF in request path",
		},
		{
			name: "crlf_in_header_value",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "X-Header", Value: "value\r\nX-Inject: evil"},
				},
			},
			wantErr: "CR/LF in header value",
		},
		{
			name: "lf_in_header_value",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "X-Header", Value: "val\nue"},
				},
			},
			wantErr: "CR/LF in header value",
		},
		// New checks: bare LF wire format
		{
			name: "bare_lf_wire",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
				Wire:    &WireFormat{UsedBareLF: true},
			},
			wantErr: "bare LF line endings",
		},
		// New checks: obs-fold
		{
			name: "obs_fold_header",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "X-Long", Value: "first second", RawLine: []byte("X-Long: first\r\n second")},
				},
			},
			wantErr: "obs-fold",
		},
		// New checks: Host header
		{
			name: "missing_host",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
			},
			wantErr: "missing Host header",
		},
		{
			name: "missing_host_http_1_0",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.0",
			},
		},
		{
			name: "duplicate_host",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					{Name: "Host", Value: "example.com"},
					{Name: "Host", Value: "evil.com"},
				},
			},
			wantErr: "duplicate Host header",
		},
		// New checks: smuggling indicators
		{
			name: "te_cl_conflict",
			req: &RawHTTP1Request{
				Method:  "POST",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "Transfer-Encoding", Value: "chunked"},
					{Name: "Content-Length", Value: "5"},
				},
				Body: []byte("hello"),
			},
			wantErr: "both Transfer-Encoding and Content-Length",
		},
		{
			name: "duplicate_cl",
			req: &RawHTTP1Request{
				Method:  "POST",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "Content-Length", Value: "5"},
					{Name: "Content-Length", Value: "10"},
				},
				Body: []byte("hello"),
			},
			wantErr: "duplicate Content-Length",
		},
		{
			name: "duplicate_te",
			req: &RawHTTP1Request{
				Method:  "POST",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "Transfer-Encoding", Value: "chunked"},
					{Name: "Transfer-Encoding", Value: "identity"},
				},
			},
			wantErr: "duplicate Transfer-Encoding",
		},
		// New checks: Content-Length accuracy
		{
			name: "cl_body_mismatch",
			req: &RawHTTP1Request{
				Method:  "POST",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "Content-Length", Value: "10"},
				},
				Body: []byte("short"),
			},
			wantErr: "Content-Length (10) does not match body length (5)",
		},
		{
			name: "cl_body_match",
			req: &RawHTTP1Request{
				Method:  "POST",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "Content-Length", Value: "4"},
				},
				Body: []byte("test"),
			},
		},
		{
			name: "non_numeric_cl",
			req: &RawHTTP1Request{
				Method:  "POST",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "Content-Length", Value: "abc"},
				},
			},
			wantErr: "non-numeric Content-Length",
		},
		{
			name: "cl_zero_no_body",
			req: &RawHTTP1Request{
				Method:  "POST",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "Content-Length", Value: "0"},
				},
			},
		},
		// Multiple issues reported together
		{
			name: "multiple_issues",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					{Name: "Content-Length", Value: "5"},
					{Name: "Content-Length", Value: "10"},
				},
				Body: []byte("hello"),
			},
			wantErr: "missing Host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequest(tt.req)

			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateRequestMultipleIssues(t *testing.T) {
	t.Parallel()

	// Request with multiple issues: missing Host + duplicate CL + CL mismatch
	req := &RawHTTP1Request{
		Method:  "POST",
		Path:    "/",
		Version: "HTTP/1.1",
		Headers: Headers{
			{Name: "Content-Length", Value: "5"},
			{Name: "Content-Length", Value: "10"},
		},
		Body: []byte("hello"),
	}
	err := validateRequest(req)
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "missing Host header")
	assert.Contains(t, msg, "duplicate Content-Length")
}

func TestCheckLineEndings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantMsg string
	}{
		{
			name:    "crlf_only",
			input:   "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantMsg: "",
		},
		{
			name:    "bare_lf_only",
			input:   "GET / HTTP/1.1\nHost: example.com\n\n",
			wantMsg: "using LF instead of CRLF",
		},
		{
			name:    "mixed_endings",
			input:   "GET / HTTP/1.1\r\nHost: example.com\n\r\n",
			wantMsg: "mixed line endings",
		},
		{
			name:    "bare_cr",
			input:   "GET / HTTP/1.1\rHost: example.com\r\n\r\n",
			wantMsg: "bare CR without LF",
		},
		{
			name:    "empty_input",
			input:   "",
			wantMsg: "",
		},
		{
			name:    "no_newlines",
			input:   "GET / HTTP/1.1",
			wantMsg: "",
		},
		{
			name:    "crlf_at_end_only",
			input:   "GET / HTTP/1.1\r\n",
			wantMsg: "",
		},
		{
			name:    "multiple_crlf",
			input:   "\r\n\r\n\r\n",
			wantMsg: "",
		},
		{
			name:    "only_cr",
			input:   "\r",
			wantMsg: "bare CR without LF",
		},
		{
			name:    "cr_not_followed_by_lf",
			input:   "GET / HTTP/1.1\r Host: example.com\r\n",
			wantMsg: "bare CR without LF",
		},
		{
			name:    "alternating_crlf_lf",
			input:   "Line1\r\nLine2\nLine3\r\n",
			wantMsg: "mixed line endings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CheckLineEndings([]byte(tt.input))

			if tt.wantMsg == "" {
				assert.Empty(t, got)
			} else {
				assert.Contains(t, got, tt.wantMsg)
			}
		})
	}
}

func TestIsValidToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "valid_method",
			input: "GET",
			want:  true,
		},
		{
			name:  "valid_custom_header",
			input: "X-CUSTOM",
			want:  true,
		},
		{
			name:  "with_numbers",
			input: "HTTP2",
			want:  true,
		},
		{
			name:  "special_chars",
			input: "!#$%&'*+-.^_`|~",
			want:  true,
		},
		{
			name:  "empty_string",
			input: "",
			want:  false,
		},
		{
			name:  "with_space",
			input: "GET POST",
			want:  false,
		},
		{
			name:  "with_colon",
			input: "Content-Type:",
			want:  false,
		},
		{
			name:  "with_slash",
			input: "HTTP/1.1",
			want:  false,
		},
		{
			name:  "with_nul",
			input: "GET\x00",
			want:  false,
		},
		{
			name:  "with_tab",
			input: "GET\t",
			want:  false,
		},
		{
			name:  "tilde_allowed",
			input: "X-Custom~Header",
			want:  true,
		},
		{
			name:  "caret_allowed",
			input: "X^Custom",
			want:  true,
		},
		{
			name:  "backtick_allowed",
			input: "X`Custom",
			want:  true,
		},
		{
			name:  "at_sign_not_allowed",
			input: "X@Custom",
			want:  false,
		},
		{
			name:  "brackets_not_allowed",
			input: "X[Custom]",
			want:  false,
		},
		{
			name:  "quotes_not_allowed",
			input: "X\"Custom\"",
			want:  false,
		},
		{
			name:  "parentheses_not_allowed",
			input: "X(Custom)",
			want:  false,
		},
		{
			name:  "single_char",
			input: "X",
			want:  true,
		},
		{
			name:  "all_digits",
			input: "12345",
			want:  true,
		},
		{
			name:  "del_char_not_allowed",
			input: "X\x7FCustom",
			want:  false,
		},
		{
			name:  "high_ascii_not_allowed",
			input: "X\x80Custom",
			want:  false,
		},
		{
			name:  "newline_not_allowed",
			input: "X\nCustom",
			want:  false,
		},
		{
			name:  "carriage_return_not_allowed",
			input: "X\rCustom",
			want:  false,
		},
		{
			name:  "form_feed_not_allowed",
			input: "X\fCustom",
			want:  false,
		},
		{
			name:  "hyphen_allowed_middle",
			input: "Content-Type",
			want:  true,
		},
		{
			name:  "underscore_allowed",
			input: "Content_Type",
			want:  true,
		},
		{
			name:  "period_allowed",
			input: "X.Custom",
			want:  true,
		},
		{
			name:  "semicolon_not_allowed",
			input: "X;Custom",
			want:  false,
		},
		{
			name:  "equals_not_allowed",
			input: "X=Custom",
			want:  false,
		},
		{
			name:  "comma_not_allowed",
			input: "X,Custom",
			want:  false,
		},
		{
			name:  "brace_not_allowed",
			input: "X{Custom}",
			want:  false,
		},
		{
			name:  "backslash_not_allowed",
			input: "X\\Custom",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isValidToken(tt.input))
		})
	}
}

func TestValidateRequestCRLFInjection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		req     *RawHTTP1Request
		wantErr string
	}{
		{
			name: "method_with_crlf",
			req: &RawHTTP1Request{
				Method:  "GET\r\nX-Injected: true",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
			wantErr: "invalid method characters",
		},
		{
			name: "path_with_crlf",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/path\r\nX-Inject: val",
				Version: "HTTP/1.1",
				Headers: Headers{hostHeader},
			},
			wantErr: "CR/LF in request path",
		},
		{
			name: "version_with_crlf",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1\r\nX-Inject: val",
				Headers: Headers{hostHeader},
			},
			wantErr: "invalid HTTP version",
		},
		{
			name: "header_value_with_crlf",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "X-Header", Value: "value\r\nX-Inject: evil"},
				},
			},
			wantErr: "CR/LF in header value",
		},
		{
			name: "multiple_nul_in_value",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: Headers{
					hostHeader,
					{Name: "X-Header", Value: "a\x00b\x00c"},
				},
			},
			wantErr: "NUL byte in header value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequest(tt.req)

			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParseValidationIntegration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     string
		wantParse bool
		wantValid bool
	}{
		{
			name:      "invalid_method_chars",
			input:     "GET<inject> / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantParse: true,
			wantValid: false,
		},
		{
			name:      "nul_in_header",
			input:     "GET / HTTP/1.1\r\nHost: example.com\r\nX-Header: val\x00ue\r\n\r\n",
			wantParse: true,
			wantValid: false,
		},
		{
			name:      "bare_lf_line_endings",
			input:     "GET / HTTP/1.1\nHost: example.com\n\n",
			wantParse: true,
			wantValid: false,
		},
		{
			name:      "obs_fold_parsed",
			input:     "GET / HTTP/1.1\r\nHost: example.com\r\nX-Long: first\r\n second\r\n\r\n",
			wantParse: true,
			wantValid: false,
		},
		{
			name:      "header_no_colon",
			input:     "GET / HTTP/1.1\r\nHost: example.com\r\nBadHeader\r\n\r\n",
			wantParse: true,
			wantValid: false, // "BadHeader" is not a valid token (no colon means entire line is the name, but that's actually valid token chars)
		},
		{
			name:      "missing_version",
			input:     "GET /\r\nHost: example.com\r\n\r\n",
			wantParse: true,
			wantValid: true, // parser defaults to HTTP/1.1
		},
		{
			name:      "duplicate_cl_and_te",
			input:     "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello",
			wantParse: true,
			wantValid: false, // both TE and CL present
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := parseRequest(strings.NewReader(tt.input))

			if tt.wantParse {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				return
			}

			err = validateRequest(req)
			if tt.wantValid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestCountHeaders(t *testing.T) {
	t.Parallel()

	headers := Headers{
		{Name: "Host", Value: "example.com"},
		{Name: "Content-Length", Value: "5"},
		{Name: "content-length", Value: "10"},
		{Name: "X-Custom", Value: "val"},
	}

	assert.Equal(t, 1, countHeaders(headers, "Host"))
	assert.Equal(t, 2, countHeaders(headers, "Content-Length"))
	assert.Equal(t, 1, countHeaders(headers, "X-Custom"))
	assert.Equal(t, 0, countHeaders(headers, "Missing"))
}

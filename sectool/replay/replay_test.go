package replay

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildURLFromHTTPRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		req      *http.Request
		expected string
		wantErr  bool
	}{
		{
			name: "from_host_header",
			req: &http.Request{
				Method: "GET",
				Host:   "example.com",
				URL:    mustParseURL("/path"),
			},
			expected: "https://example.com/path",
		},
		{
			name: "localhost_uses_http",
			req: &http.Request{
				Method: "GET",
				Host:   "localhost:8080",
				URL:    mustParseURL("/api"),
			},
			expected: "http://localhost:8080/api",
		},
		{
			name: "127_uses_http",
			req: &http.Request{
				Method: "GET",
				Host:   "127.0.0.1:3000",
				URL:    mustParseURL("/test"),
			},
			expected: "http://127.0.0.1:3000/test",
		},
		{
			name: "no_host",
			req: &http.Request{
				Method: "GET",
				Host:   "",
				Header: http.Header{},
				URL:    mustParseURL("/path"),
			},
			wantErr: true,
		},
		{
			name: "host_from_header",
			req: &http.Request{
				Method: "GET",
				Host:   "",
				Header: http.Header{"Host": []string{"from-header.com"}},
				URL:    mustParseURL("/path"),
			},
			expected: "https://from-header.com/path",
		},
		{
			name: "port_80_uses_http",
			req: &http.Request{
				Method: "GET",
				Host:   "example.com:80",
				URL:    mustParseURL("/path"),
			},
			expected: "http://example.com:80/path",
		},
		{
			name: "non_http_port",
			req: &http.Request{
				Method: "GET",
				Host:   "example.com:8443",
				URL:    mustParseURL("/path"),
			},
			expected: "https://example.com:8443/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildURLFromHTTPRequest(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRejectModificationFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		target        string
		headers       []string
		removeHeaders []string
		path          string
		query         string
		setQuery      []string
		removeQuery   []string
		setJSON       []string
		removeJSON    []string
		wantErr       bool
		wantContains  string
	}{
		{
			name: "no_flags",
		},
		{
			name:         "string_flag",
			target:       "https://other.com",
			wantErr:      true,
			wantContains: "--target",
		},
		{
			name:         "slice_flag",
			headers:      []string{"X-Test: val"},
			wantErr:      true,
			wantContains: "--set-header",
		},
		{
			name:         "multiple_flags",
			target:       "https://other.com",
			headers:      []string{"X: Y"},
			path:         "/new",
			wantErr:      true,
			wantContains: "--target, --set-header, --path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rejectModificationFlags(tt.target, tt.headers, tt.removeHeaders,
				tt.path, tt.query, tt.setQuery, tt.removeQuery,
				tt.setJSON, tt.removeJSON)
			if !tt.wantErr {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantContains)
			assert.Contains(t, err.Error(), "edit the source files directly")
		})
	}
}

func TestParseHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "basic_headers",
			raw:  "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n",
			want: []string{"Host: example.com", "Accept: */*"},
		},
		{
			name: "obs_fold_space",
			raw:  "GET / HTTP/1.1\r\nX-Long: first\r\n second\r\n\r\n",
			want: []string{"X-Long: first second"},
		},
		{
			name: "obs_fold_tab",
			raw:  "GET / HTTP/1.1\r\nX-Long: first\r\n\tsecond\r\n\r\n",
			want: []string{"X-Long: first second"},
		},
		{
			name: "multiple_continuations",
			raw:  "GET / HTTP/1.1\r\nX-Long: a\r\n b\r\n c\r\n\r\n",
			want: []string{"X-Long: a b c"},
		},
		{
			name: "body_placeholder_removed",
			raw:  "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n<< REQUEST BODY (binary-safe; edit 'body' file) >>\n",
			want: []string{"Host: example.com"},
		},
		{
			name: "lf_line_endings",
			raw:  "GET / HTTP/1.1\nHost: example.com\nAccept: */*\n\n",
			want: []string{"Host: example.com", "Accept: */*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHeaders([]byte(tt.raw))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{
			name: "standard_request",
			raw:  []byte("POST /path HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			want: "POST",
		},
		{
			name: "bare_lf",
			raw:  []byte("PUT /path HTTP/1.1\nHost: example.com\n\n"),
			want: "PUT",
		},
		{
			name: "empty_input",
			raw:  nil,
			want: "GET",
		},
		{
			name: "no_space_in_line",
			raw:  []byte("INVALID\r\n"),
			want: "INVALID",
		},
		{
			name: "method_only",
			raw:  []byte("DELETE"),
			want: "DELETE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ExtractMethod(tt.raw))
		})
	}
}

func TestGroupHeaderEntries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entries []string
		want    []HeaderGroup
	}{
		{
			name:    "single_entry",
			entries: []string{"Host: example.com"},
			want:    []HeaderGroup{{Key: "host", Entries: []string{"Host: example.com"}}},
		},
		{
			name:    "duplicate_name",
			entries: []string{"TE: chunked", "TE: identity"},
			want:    []HeaderGroup{{Key: "te", Entries: []string{"TE: chunked", "TE: identity"}}},
		},
		{
			name:    "mixed",
			entries: []string{"Host: new.com", "TE: chunked", "TE: identity", "X-Custom: val"},
			want: []HeaderGroup{
				{Key: "host", Entries: []string{"Host: new.com"}},
				{Key: "te", Entries: []string{"TE: chunked", "TE: identity"}},
				{Key: "x-custom", Entries: []string{"X-Custom: val"}},
			},
		},
		{
			name:    "case_insensitive",
			entries: []string{"host: a", "HOST: b"},
			want:    []HeaderGroup{{Key: "host", Entries: []string{"host: a", "HOST: b"}}},
		},
		{
			name:    "invalid_skipped",
			entries: []string{"no-colon", "Valid: yes"},
			want:    []HeaderGroup{{Key: "valid", Entries: []string{"Valid: yes"}}},
		},
		{
			name:    "empty",
			entries: nil,
			want:    []HeaderGroup{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GroupHeaderEntries(tt.entries)
			if len(tt.want) == 0 {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestContainsHeader(t *testing.T) {
	t.Parallel()

	entries := []string{"Content-Type: text/html", "Authorization: Bearer tok"}

	assert.True(t, ContainsHeader(entries, "Content-Type"))
	assert.True(t, ContainsHeader(entries, "content-type"))
	assert.True(t, ContainsHeader(entries, "AUTHORIZATION"))
	assert.False(t, ContainsHeader(entries, "Content-Length"))
	assert.False(t, ContainsHeader(nil, "anything"))
}

func TestApplyRawQueryModifications(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		query  string
		remove []string
		set    []string
		want   string
	}{
		{
			name:   "remove_single",
			query:  "a=1&b=2&c=3",
			remove: []string{"b"},
			want:   "a=1&c=3",
		},
		{
			name:  "set_existing",
			query: "a=1&b=2",
			set:   []string{"a=changed"},
			want:  "a=changed&b=2",
		},
		{
			name:  "set_new",
			query: "a=1",
			set:   []string{"b=2"},
			want:  "a=1&b=2",
		},
		{
			name:   "remove_then_set",
			query:  "a=1&b=2&c=3",
			remove: []string{"b"},
			set:    []string{"d=4"},
			want:   "a=1&c=3&d=4",
		},
		{
			name:  "encoding_preserved",
			query: "foo=%2F&bar=%20hello",
			set:   []string{"baz=new"},
			want:  "foo=%2F&bar=%20hello&baz=new",
		},
		{
			name:  "order_preserved",
			query: "z=1&a=2&m=3",
			set:   []string{"a=changed"},
			want:  "z=1&a=changed&m=3",
		},
		{
			name:  "empty_query_set",
			query: "",
			set:   []string{"key=value"},
			want:  "key=value",
		},
		{
			name:   "empty_query_remove",
			query:  "",
			remove: []string{"anything"},
			want:   "",
		},
		{
			name:   "remove_all",
			query:  "a=1",
			remove: []string{"a"},
			want:   "",
		},
		{
			name:   "remove_nonexistent",
			query:  "a=1",
			remove: []string{"b"},
			want:   "a=1",
		},
		{
			name:  "duplicate_params_preserved",
			query: "a=1&a=2&b=3",
			set:   []string{"c=4"},
			want:  "a=1&a=2&b=3&c=4",
		},
		{
			name:  "set_replaces_first_only",
			query: "a=1&a=2",
			set:   []string{"a=changed"},
			want:  "a=changed&a=2",
		},
		{
			name:   "remove_encoded_key",
			query:  "foo%20bar=1&b=2",
			remove: []string{"foo bar"},
			want:   "b=2",
		},
		{
			name:  "set_replaces_encoded_key",
			query: "foo%20bar=1&b=2",
			set:   []string{"foo bar=changed"},
			want:  "foo bar=changed&b=2",
		},
		{
			name:   "remove_plus_encoded_key",
			query:  "foo+bar=1&b=2",
			remove: []string{"foo bar"},
			want:   "b=2",
		},
		{
			name:  "set_encoded_replaces_raw",
			query: "foo bar=1&b=2",
			set:   []string{"foo%20bar=changed"},
			want:  "foo%20bar=changed&b=2",
		},
		{
			name:   "remove_encoded_matches_raw",
			query:  "foo bar=1&b=2",
			remove: []string{"foo%20bar"},
			want:   "b=2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ApplyRawQueryModifications(tt.query, tt.remove, tt.set))
		})
	}
}

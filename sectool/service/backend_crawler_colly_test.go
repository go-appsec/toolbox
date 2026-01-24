package service

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIsTextContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{"empty", "", true},
		{"text_html", "text/html", true},
		{"text_plain", "text/plain", true},
		{"text_html_charset", "text/html; charset=utf-8", true},
		{"application_json", "application/json", true},
		{"application_xml", "application/xml", true},
		{"application_javascript", "application/javascript", true},
		{"application_x_javascript", "application/x-javascript", true},
		{"image_png", "image/png", false},
		{"image_jpeg", "image/jpeg", false},
		{"application_pdf", "application/pdf", false},
		{"application_octet_stream", "application/octet-stream", false},
		{"video_mp4", "video/mp4", false},
		{"audio_mpeg", "audio/mpeg", false},
		{"uppercase", "TEXT/HTML", true},
		{"mixed_case", "Application/JSON", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isTextContentType(tt.contentType))
		})
	}
}

func TestMatchesFlowFilters(t *testing.T) {
	t.Parallel()

	flow := &CrawlFlow{
		URL:        "https://example.com/api/users/123",
		Host:       "example.com",
		Path:       "/api/users/123",
		Method:     "GET",
		StatusCode: 200,
	}

	t.Run("empty_filters_matches", func(t *testing.T) {
		assert.True(t, matchesFlowFilters(flow, CrawlListOptions{}))
	})

	t.Run("path_pattern_matches", func(t *testing.T) {
		assert.True(t, matchesFlowFilters(flow, CrawlListOptions{PathPattern: "/api/*"}))
		assert.True(t, matchesFlowFilters(flow, CrawlListOptions{PathPattern: "/api/users/*"}))
		assert.False(t, matchesFlowFilters(flow, CrawlListOptions{PathPattern: "/admin/*"}))
	})

	t.Run("status_code_matches", func(t *testing.T) {
		assert.True(t, matchesFlowFilters(flow, CrawlListOptions{StatusCodes: parseStatusFilter("200")}))
		assert.True(t, matchesFlowFilters(flow, CrawlListOptions{StatusCodes: parseStatusFilter("200,201,404")}))
		assert.False(t, matchesFlowFilters(flow, CrawlListOptions{StatusCodes: parseStatusFilter("404,500")}))
	})

	t.Run("status_code_range_matches", func(t *testing.T) {
		assert.True(t, matchesFlowFilters(flow, CrawlListOptions{StatusCodes: parseStatusFilter("2XX")}))
		assert.True(t, matchesFlowFilters(flow, CrawlListOptions{StatusCodes: parseStatusFilter("2xx")}))
		assert.False(t, matchesFlowFilters(flow, CrawlListOptions{StatusCodes: parseStatusFilter("4XX")}))
		assert.True(t, matchesFlowFilters(flow, CrawlListOptions{StatusCodes: parseStatusFilter("2XX,4XX")}))
	})

	t.Run("method_matches", func(t *testing.T) {
		assert.True(t, matchesFlowFilters(flow, CrawlListOptions{Methods: []string{"GET"}}))
		assert.True(t, matchesFlowFilters(flow, CrawlListOptions{Methods: []string{"get"}}))
		assert.True(t, matchesFlowFilters(flow, CrawlListOptions{Methods: []string{"GET", "POST"}}))
		assert.False(t, matchesFlowFilters(flow, CrawlListOptions{Methods: []string{"POST"}}))
	})

	t.Run("combined_filters", func(t *testing.T) {
		assert.True(t, matchesFlowFilters(flow, CrawlListOptions{
			PathPattern: "/api/*",
			StatusCodes: parseStatusFilter("200"),
			Methods:     []string{"GET"},
		}))
		assert.False(t, matchesFlowFilters(flow, CrawlListOptions{
			PathPattern: "/api/*",
			StatusCodes: parseStatusFilter("404"),
			Methods:     []string{"GET"},
		}))
	})
}

func TestGlobsToRegexes(t *testing.T) {
	t.Parallel()

	t.Run("simple_patterns", func(t *testing.T) {
		patterns := []string{"*logout*", "*admin*"}
		regexes := globsToRegexes(patterns)

		assert.Len(t, regexes, 2)
		assert.True(t, regexes[0].MatchString("/user/logout"))
		assert.True(t, regexes[0].MatchString("logout"))
		assert.False(t, regexes[0].MatchString("/login"))
		assert.True(t, regexes[1].MatchString("/admin/dashboard"))
	})

	t.Run("question_mark", func(t *testing.T) {
		patterns := []string{"/api/v?/users"}
		regexes := globsToRegexes(patterns)

		assert.Len(t, regexes, 1)
		assert.True(t, regexes[0].MatchString("/api/v1/users"))
		assert.True(t, regexes[0].MatchString("/api/v2/users"))
		assert.False(t, regexes[0].MatchString("/api/v10/users"))
	})

	t.Run("empty_patterns", func(t *testing.T) {
		regexes := globsToRegexes(nil)
		assert.Empty(t, regexes)

		regexes = globsToRegexes([]string{})
		assert.Empty(t, regexes)
	})
}

func TestBuildDomainFilters(t *testing.T) {
	t.Parallel()

	t.Run("matches_exact_domain", func(t *testing.T) {
		filters := buildDomainFilters([]string{"example.com"})
		assert.Len(t, filters, 1)

		assert.True(t, filters[0].MatchString("https://example.com/"))
		assert.True(t, filters[0].MatchString("http://example.com/path"))
		assert.True(t, filters[0].MatchString("https://example.com:8080/"))
	})

	t.Run("matches_single_subdomain", func(t *testing.T) {
		filters := buildDomainFilters([]string{"example.com"})

		assert.True(t, filters[0].MatchString("https://api.example.com/"))
		assert.True(t, filters[0].MatchString("https://www.example.com/path"))
	})

	t.Run("matches_multi_level_subdomains", func(t *testing.T) {
		// Critical: must match any number of subdomain levels (a.b.c.example.com)
		filters := buildDomainFilters([]string{"example.com"})

		assert.True(t, filters[0].MatchString("https://sub.api.example.com/"))
		assert.True(t, filters[0].MatchString("https://a.b.c.example.com/"))
		assert.True(t, filters[0].MatchString("https://deep.nested.sub.domain.example.com/path"))
	})

	t.Run("rejects_different_domain", func(t *testing.T) {
		filters := buildDomainFilters([]string{"example.com"})

		assert.False(t, filters[0].MatchString("https://notexample.com/"))
		assert.False(t, filters[0].MatchString("https://example.org/"))
		assert.False(t, filters[0].MatchString("https://fakeexample.com/"))
	})

	t.Run("rejects_suffix_match", func(t *testing.T) {
		// Ensure we don't match domains that merely contain the target as suffix
		filters := buildDomainFilters([]string{"example.com"})

		assert.False(t, filters[0].MatchString("https://badexample.com/"))
		assert.False(t, filters[0].MatchString("https://myexample.com/"))
	})

	t.Run("multiple_domains", func(t *testing.T) {
		filters := buildDomainFilters([]string{"example.com", "test.org"})
		assert.Len(t, filters, 2)

		assert.True(t, filters[0].MatchString("https://example.com/"))
		assert.True(t, filters[1].MatchString("https://test.org/"))
	})
}

func TestCrawlFlowFields(t *testing.T) {
	t.Parallel()

	flow := CrawlFlow{
		ID:             "abc123",
		SessionID:      "sess1",
		URL:            "https://example.com/test?q=1",
		Host:           "example.com",
		Path:           "/test?q=1",
		Method:         "GET",
		FoundOn:        "https://example.com/",
		Depth:          2,
		StatusCode:     200,
		ContentType:    "text/html",
		ResponseLength: 13,
		Request:        []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Response:       []byte("HTTP/1.1 200 OK\r\n\r\n<html></html>"),
		Truncated:      false,
		Duration:       100 * time.Millisecond,
		DiscoveredAt:   time.Now(),
	}

	assert.Equal(t, "abc123", flow.ID)
	assert.Equal(t, "sess1", flow.SessionID)
	assert.Equal(t, "https://example.com/test?q=1", flow.URL)
	assert.Equal(t, "example.com", flow.Host)
	assert.Equal(t, "/test?q=1", flow.Path)
	assert.Equal(t, "GET", flow.Method)
	assert.Equal(t, 200, flow.StatusCode)
	assert.Equal(t, 2, flow.Depth)
	assert.Equal(t, "text/html", flow.ContentType)
	assert.Equal(t, 13, flow.ResponseLength)
	assert.False(t, flow.Truncated)
}

func TestReadBodyLimited(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		input         string
		limit         int
		wantBody      string
		wantTotalSize int
		wantTruncated bool
	}{
		{
			name:          "smaller_than_limit",
			input:         "hello",
			limit:         100,
			wantBody:      "hello",
			wantTotalSize: 5,
			wantTruncated: false,
		},
		{
			name:          "exactly_at_limit",
			input:         "hello",
			limit:         5,
			wantBody:      "hello",
			wantTotalSize: 5,
			wantTruncated: false,
		},
		{
			name:          "larger_than_limit",
			input:         "hello world this is a long message",
			limit:         5,
			wantBody:      "hello",
			wantTotalSize: 34,
			wantTruncated: true,
		},
		{
			name:          "empty_body",
			input:         "",
			limit:         100,
			wantBody:      "",
			wantTotalSize: 0,
			wantTruncated: false,
		},
		{
			name:          "limit_of_one",
			input:         "abc",
			limit:         1,
			wantBody:      "a",
			wantTotalSize: 3,
			wantTruncated: true,
		},
		{
			name:          "one_byte_over_limit",
			input:         "abcdef",
			limit:         5,
			wantBody:      "abcde",
			wantTotalSize: 6,
			wantTruncated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bytes.NewReader([]byte(tt.input))
			body, totalSize, truncated := readBodyLimited(reader, tt.limit)

			assert.Equal(t, tt.wantBody, string(body))
			assert.Equal(t, tt.wantTotalSize, totalSize)
			assert.Equal(t, tt.wantTruncated, truncated)
		})
	}
}

func TestParseSinceTimestamp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantOK  bool
		wantUTC string // expected time in UTC format for comparison
	}{
		{"rfc3339_utc", "2024-01-15T10:30:00Z", true, "2024-01-15T10:30:00Z"},
		{"rfc3339_offset", "2024-01-15T10:30:00+05:00", true, "2024-01-15T05:30:00Z"},
		{"rfc3339_negative_offset", "2024-01-15T10:30:00-08:00", true, "2024-01-15T18:30:00Z"},
		{"datetime_no_tz", "2024-01-15T10:30:00", true, ""}, // local TZ, can't compare directly
		{"date_only", "2024-01-15", true, ""},               // local TZ, can't compare directly
		{"flow_id", "abc123", false, ""},
		{"last_keyword", "last", false, ""},
		{"invalid_format", "2024/01/15", false, ""},
		{"empty", "", false, ""},
		{"partial_date", "2024-01", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := parseSinceTimestamp(tt.input)
			assert.Equal(t, tt.wantOK, ok, "parseSinceTimestamp(%q) ok mismatch", tt.input)
			if ok && tt.wantUTC != "" {
				assert.Equal(t, tt.wantUTC, result.UTC().Format(time.RFC3339))
			}
			if ok {
				assert.False(t, result.IsZero(), "parsed time should not be zero")
			}
		})
	}
}

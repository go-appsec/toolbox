package service

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/config"
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

// newTestCollySession creates a CollyBackend with a pre-populated session for unit testing.
// Returns the backend and session ID.
func newTestCollySession(t *testing.T, flows []*CrawlFlow) (*CollyBackend, string) {
	t.Helper()

	cfg := config.DefaultConfig()
	b := NewCollyBackend(cfg, nil, nil)
	t.Cleanup(func() { _ = b.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	sessionID := "test-session"
	sess := &crawlSession{
		info:      CrawlSessionInfo{ID: sessionID, State: crawlStateRunning, CreatedAt: time.Now()},
		startedAt: time.Now(),
		flowsByID: make(map[string]*CrawlFlow),
		urlsSeen:  make(map[string]bool),
		ctx:       ctx,
		cancel:    cancel,
	}
	for _, f := range flows {
		f.SessionID = sessionID
		sess.flowsByID[f.ID] = f
		sess.flowsOrdered = append(sess.flowsOrdered, f)
	}

	b.sessions[sessionID] = sess
	return b, sessionID
}

func TestCollyBackend_ListFlows_since_last_with_search(t *testing.T) {
	t.Parallel()

	// Create 4 flows: only flow-1 and flow-3 have "SECRET" in the request header
	flows := []*CrawlFlow{
		{ID: "flow-0", Host: "a.com", Path: "/0", Method: "GET", StatusCode: 200,
			Request: []byte("GET /0 HTTP/1.1\r\nHost: a.com\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\nok")},
		{ID: "flow-1", Host: "a.com", Path: "/1", Method: "GET", StatusCode: 200,
			Request: []byte("GET /1 HTTP/1.1\r\nHost: a.com\r\nX-Secret: yes\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\nok")},
		{ID: "flow-2", Host: "a.com", Path: "/2", Method: "GET", StatusCode: 200,
			Request: []byte("GET /2 HTTP/1.1\r\nHost: a.com\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\nok")},
		{ID: "flow-3", Host: "a.com", Path: "/3", Method: "GET", StatusCode: 200,
			Request: []byte("GET /3 HTTP/1.1\r\nHost: a.com\r\nX-Secret: yes\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\nok")},
	}
	b, sessionID := newTestCollySession(t, flows)

	ctx := t.Context()
	secretRe := regexp.MustCompile(`X-Secret`)

	// 1. Poll with search: should return flow-1 and flow-3, cursor at index 4
	got, err := b.ListFlows(ctx, sessionID, CrawlListOptions{SearchHeaderRe: secretRe})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "flow-1", got[0].ID)
	assert.Equal(t, "flow-3", got[1].ID)

	// Cursor should be at index 4 (after flow-3 at index 3)
	sess := b.sessions[sessionID]
	sess.mu.RLock()
	cursor := sess.lastReturnedIdx
	sess.mu.RUnlock()
	assert.Equal(t, 4, cursor)

	// 2. Poll with since=last (no search): flow-0 and flow-2 are before the cursor,
	// so nothing is returned. This is correct: the search advanced past them.
	got, err = b.ListFlows(ctx, sessionID, CrawlListOptions{Since: sinceLast})
	require.NoError(t, err)
	assert.Empty(t, got)

	// 3. Add a new flow after the cursor
	sess.mu.Lock()
	newFlow := &CrawlFlow{ID: "flow-4", SessionID: sessionID, Host: "a.com", Path: "/4",
		Method: "GET", StatusCode: 200,
		Request: []byte("GET /4 HTTP/1.1\r\nHost: a.com\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\nnew")}
	sess.flowsByID["flow-4"] = newFlow
	sess.flowsOrdered = append(sess.flowsOrdered, newFlow)
	sess.mu.Unlock()

	// 4. Poll with since=last: new flow is returned
	got, err = b.ListFlows(ctx, sessionID, CrawlListOptions{Since: sinceLast})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "flow-4", got[0].ID)
}

func TestCollyBackend_ListFlows_search_cursor_not_past_results(t *testing.T) {
	t.Parallel()

	// Regression test: search cursor must only advance to the last matching
	// flow, not to the end of the full flow list.
	// flow-0: no match, flow-1: match, flow-2: no match, flow-3: no match
	flows := []*CrawlFlow{
		{ID: "flow-0", Host: "a.com", Path: "/0", Method: "GET", StatusCode: 200,
			Request: []byte("GET /0 HTTP/1.1\r\nHost: a.com\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\nok")},
		{ID: "flow-1", Host: "a.com", Path: "/1", Method: "GET", StatusCode: 200,
			Request: []byte("GET /1 HTTP/1.1\r\nHost: a.com\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\nSECRET")},
		{ID: "flow-2", Host: "a.com", Path: "/2", Method: "GET", StatusCode: 200,
			Request: []byte("GET /2 HTTP/1.1\r\nHost: a.com\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\nok")},
		{ID: "flow-3", Host: "a.com", Path: "/3", Method: "GET", StatusCode: 200,
			Request: []byte("GET /3 HTTP/1.1\r\nHost: a.com\r\n\r\n"), Response: []byte("HTTP/1.1 200 OK\r\n\r\nok")},
	}
	b, sessionID := newTestCollySession(t, flows)

	ctx := t.Context()
	secretRe := regexp.MustCompile(`SECRET`)

	// Search matches only flow-1 (index 1). Cursor should advance to 2, not 4.
	got, err := b.ListFlows(ctx, sessionID, CrawlListOptions{SearchBodyRe: secretRe})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "flow-1", got[0].ID)

	sess := b.sessions[sessionID]
	sess.mu.RLock()
	cursor := sess.lastReturnedIdx
	sess.mu.RUnlock()
	assert.Equal(t, 2, cursor)

	// since=last without search: should return flow-2 and flow-3
	got, err = b.ListFlows(ctx, sessionID, CrawlListOptions{Since: sinceLast})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "flow-2", got[0].ID)
	assert.Equal(t, "flow-3", got[1].ID)
}

func TestCollyBackend_ListFlows_search_with_limit(t *testing.T) {
	t.Parallel()

	// 6 flows: matches at indices 0, 2, 4 (even indices have X-Tag header)
	flows := make([]*CrawlFlow, 6)
	for i := range flows {
		hdr := "GET /%d HTTP/1.1\r\nHost: a.com\r\n"
		if i%2 == 0 {
			hdr += "X-Tag: yes\r\n"
		}
		flows[i] = &CrawlFlow{
			ID: fmt.Sprintf("flow-%d", i), Host: "a.com", Path: fmt.Sprintf("/%d", i),
			Method: "GET", StatusCode: 200,
			Request:  []byte(fmt.Sprintf(hdr+"\r\n", i)),
			Response: []byte("HTTP/1.1 200 OK\r\n\r\nok"),
		}
	}
	b, sessionID := newTestCollySession(t, flows)

	ctx := t.Context()
	tagRe := regexp.MustCompile(`X-Tag`)

	// limit=2 with search: should return flow-0 and flow-2, stop early
	got, err := b.ListFlows(ctx, sessionID, CrawlListOptions{
		SearchHeaderRe: tagRe, Limit: 2,
	})
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "flow-0", got[0].ID)
	assert.Equal(t, "flow-2", got[1].ID)

	// Cursor should be at 3 (after flow-2 at index 2), not at 5
	sess := b.sessions[sessionID]
	sess.mu.RLock()
	cursor := sess.lastReturnedIdx
	sess.mu.RUnlock()
	assert.Equal(t, 3, cursor)

	// since=last with same search: should return flow-4 (the remaining match)
	got, err = b.ListFlows(ctx, sessionID, CrawlListOptions{
		Since: sinceLast, SearchHeaderRe: tagRe,
	})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "flow-4", got[0].ID)

	// since=last without search: returns flow-5 (only remaining unseen flow)
	got, err = b.ListFlows(ctx, sessionID, CrawlListOptions{Since: sinceLast})
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "flow-5", got[0].ID)
}

func TestCollyBackend_CreateSession_follows_links(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body>
			<a href="/page1">Page 1</a>
			<a href="/page2">Page 2</a>
		</body></html>`)
	})
	mux.HandleFunc("/page1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body>
			<a href="/page3">Page 3</a>
		</body></html>`)
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body>
			<p>Page 2 content</p>
		</body></html>`)
	})
	mux.HandleFunc("/page3", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<html><body>
			<p>Page 3 content</p>
		</body></html>`)
	})

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	cfg := config.DefaultConfig()
	// Speed up crawling for testing
	cfg.Crawler.DelayMS = 0
	cfg.Crawler.Parallelism = 4

	b := NewCollyBackend(cfg, nil, nil)
	t.Cleanup(func() { _ = b.Close() })

	ctx := t.Context()

	info, err := b.CreateSession(ctx, CrawlOptions{
		Seeds: []CrawlSeed{{URL: ts.URL + "/"}},
	})
	require.NoError(t, err)
	require.NotEmpty(t, info.ID)

	sessionID := info.ID

	// Poll until completed or timeout
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		status, err := b.GetStatus(ctx, sessionID)
		require.NoError(t, err)
		if status.State == crawlStateCompleted {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	status, err := b.GetStatus(ctx, sessionID)
	require.NoError(t, err)
	assert.Equal(t, crawlStateCompleted, status.State)

	// Should have visited at least 4 pages: /, /page1, /page2, /page3
	flows, err := b.ListFlows(ctx, sessionID, CrawlListOptions{})
	require.NoError(t, err)
	assert.Len(t, flows, 4)

	// Collect visited paths for verification
	visitedPaths := make(map[string]bool, len(flows))
	for _, f := range flows {
		assert.False(t, visitedPaths[f.Path]) // no duplicate paths
		visitedPaths[f.Path] = true
	}
	assert.Contains(t, visitedPaths, "/")
	assert.Contains(t, visitedPaths, "/page1")
	assert.Contains(t, visitedPaths, "/page2")
	assert.Contains(t, visitedPaths, "/page3")

	// Errors should be empty or minimal
	crawlErrors, err := b.ListErrors(ctx, sessionID, 0)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(crawlErrors), 1)
}

package proxy

import (
	"bytes"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/store"
)

func TestStore(t *testing.T) {
	t.Parallel()

	t.Run("assigns_sequential_offsets", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		for i := 0; i < 5; i++ {
			entry := &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Method:  "GET",
					Path:    "/",
					Version: "HTTP/1.1",
				},
			}
			offset := h.Store(entry)
			assert.Equal(t, uint32(i), offset)
		}
		assert.Equal(t, 5, h.Count())
	})

	t.Run("concurrent_writes", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		var wg sync.WaitGroup
		const numGoroutines = 10
		const entriesPerGoroutine = 100
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < entriesPerGoroutine; j++ {
					entry := &HistoryEntry{
						Protocol: "http/1.1",
						Request: &RawHTTP1Request{
							Method:  "GET",
							Path:    "/",
							Version: "HTTP/1.1",
						},
					}
					h.Store(entry)
				}
			}()
		}

		wg.Wait()
		assert.Equal(t, numGoroutines*entriesPerGoroutine, h.Count())

		for i := uint32(0); i < uint32(numGoroutines*entriesPerGoroutine); i++ {
			_, ok := h.Get(i)
			assert.True(t, ok)
		}
	})
}

func TestGet(t *testing.T) {
	t.Parallel()

	t.Run("retrieves_stored_entry", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)
		entry := &HistoryEntry{
			Protocol:  "http/1.1",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
			Request: &RawHTTP1Request{
				Method:   "GET",
				Path:     "/test",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
				},
			},
			Response: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200,
				StatusText: "OK",
				Headers: []Header{
					{Name: "Content-Type", Value: "text/plain"},
				},
				Body: []byte("Hello"),
			},
		}

		offset := h.Store(entry)
		retrieved, ok := h.Get(offset)

		require.True(t, ok)
		assert.Equal(t, uint32(0), retrieved.Offset)
		assert.Equal(t, "http/1.1", retrieved.Protocol)
		assert.Equal(t, "GET", retrieved.Request.Method)
		assert.Equal(t, "/test", retrieved.Request.Path)
		assert.Equal(t, 200, retrieved.Response.StatusCode)
		assert.Equal(t, []byte("Hello"), retrieved.Response.Body)
	})

	t.Run("not_found", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		_, ok := h.Get(999)
		assert.False(t, ok)
	})

	t.Run("serialization_roundtrip", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)
		entry := &HistoryEntry{
			Protocol:  "http/1.1",
			Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
			Duration:  250 * time.Millisecond,
			Request: &RawHTTP1Request{
				Method:   "POST",
				Path:     "/api/data",
				Query:    "foo=bar",
				Version:  "HTTP/1.1",
				Protocol: "http/1.1",
				Headers: []Header{
					{Name: "Content-Type", Value: "application/json"},
					{Name: "x-custom-header", Value: "value"},
				},
				Body: []byte(`{"key":"value"}`),
			},
			Response: &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 201,
				StatusText: "Created",
				Headers: []Header{
					{Name: "Content-Type", Value: "application/json"},
				},
				Body: []byte(`{"id":123}`),
			},
		}

		offset := h.Store(entry)
		retrieved, ok := h.Get(offset)
		require.True(t, ok)

		assert.Equal(t, entry.Protocol, retrieved.Protocol)
		assert.Equal(t, entry.Timestamp, retrieved.Timestamp)
		assert.Equal(t, entry.Duration, retrieved.Duration)

		assert.Equal(t, entry.Request.Method, retrieved.Request.Method)
		assert.Equal(t, entry.Request.Path, retrieved.Request.Path)
		assert.Equal(t, entry.Request.Query, retrieved.Request.Query)
		assert.Equal(t, entry.Request.Version, retrieved.Request.Version)
		assert.Equal(t, entry.Request.Headers, retrieved.Request.Headers)
		assert.Equal(t, entry.Request.Body, retrieved.Request.Body)

		assert.Equal(t, entry.Response.Version, retrieved.Response.Version)
		assert.Equal(t, entry.Response.StatusCode, retrieved.Response.StatusCode)
		assert.Equal(t, entry.Response.StatusText, retrieved.Response.StatusText)
		assert.Equal(t, entry.Response.Headers, retrieved.Response.Headers)
		assert.Equal(t, entry.Response.Body, retrieved.Response.Body)
	})
}

func TestList(t *testing.T) {
	t.Parallel()

	t.Run("pagination", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		for i := 0; i < 10; i++ {
			entry := &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Method:  "GET",
					Path:    "/" + string(rune('a'+i)),
					Version: "HTTP/1.1",
				},
			}
			h.Store(entry)
		}

		tests := []struct {
			name      string
			count     int
			offset    uint32
			wantLen   int
			wantFirst string
			wantLast  string
		}{
			{
				name:      "first_five",
				count:     5,
				offset:    0,
				wantLen:   5,
				wantFirst: "/a",
				wantLast:  "/e",
			},
			{
				name:      "from_offset_five",
				count:     5,
				offset:    5,
				wantLen:   5,
				wantFirst: "/f",
				wantLast:  "/j",
			},
			{
				name:      "partial_remaining",
				count:     5,
				offset:    8,
				wantLen:   2,
				wantFirst: "/i",
				wantLast:  "/j",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				entries := h.List(tt.count, tt.offset)
				assert.Len(t, entries, tt.wantLen)
				if tt.wantLen > 0 {
					assert.Equal(t, tt.wantFirst, entries[0].Request.Path)
					assert.Equal(t, tt.wantLast, entries[len(entries)-1].Request.Path)
				}
			})
		}
	})

	t.Run("empty_history", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		entries := h.List(10, 0)
		assert.Empty(t, entries)
	})

	t.Run("offset_beyond_max", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)
		entry := &HistoryEntry{
			Protocol: "http/1.1",
			Request:  &RawHTTP1Request{Method: "GET", Path: "/"},
		}
		h.Store(entry)

		entries := h.List(10, 100)
		assert.Empty(t, entries)
	})

	t.Run("zero_count", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)
		entry := &HistoryEntry{
			Protocol: "http/1.1",
			Request:  &RawHTTP1Request{Method: "GET", Path: "/"},
		}
		h.Store(entry)

		entries := h.List(0, 0)
		assert.Empty(t, entries)
	})
}

func TestUpdate(t *testing.T) {
	t.Parallel()

	t.Run("updates_existing_entry", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)
		entry := &HistoryEntry{
			Protocol: "http/1.1",
			Request: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/original",
				Version: "HTTP/1.1",
			},
		}
		offset := h.Store(entry)

		entry.Response = &RawHTTP1Response{
			Version:    "HTTP/1.1",
			StatusCode: 200,
			StatusText: "OK",
			Body:       []byte("response body"),
		}
		h.Update(entry)

		retrieved, ok := h.Get(offset)
		require.True(t, ok)
		assert.Equal(t, "/original", retrieved.Request.Path)
		require.NotNil(t, retrieved.Response)
		assert.Equal(t, 200, retrieved.Response.StatusCode)
		assert.Equal(t, []byte("response body"), retrieved.Response.Body)
	})

	t.Run("ignores_nonexistent", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		entry := &HistoryEntry{
			Offset:   999,
			Protocol: "http/1.1",
		}
		h.Update(entry) // should not panic
	})
}

func TestFormatRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entry   *HistoryEntry
		wantNil bool
		check   func(t *testing.T, result []byte)
	}{
		{
			name: "http1_request",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Method:  "GET",
					Path:    "/test",
					Version: "HTTP/1.1",
					Headers: []Header{{Name: "Host", Value: "example.com"}},
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()

				assert.Contains(t, string(result), "GET /test HTTP/1.1")
				assert.Contains(t, string(result), "Host: example.com")
			},
		},
		{
			name: "h2_request",
			entry: &HistoryEntry{
				Protocol: "h2",
				H2Request: &H2RequestData{
					Method:    "POST",
					Path:      "/api",
					Authority: "example.com",
					Headers:   []Header{{Name: "content-type", Value: "application/json"}},
					Body:      []byte(`{"test":1}`),
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()

				assert.Contains(t, string(result), "POST /api HTTP/1.1")
				assert.Contains(t, string(result), "host: example.com")
				assert.Contains(t, string(result), "content-type: application/json")
				assert.Contains(t, string(result), `{"test":1}`)
			},
		},
		{
			name: "nil_http1_request",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  nil,
			},
			wantNil: true,
		},
		{
			name: "nil_h2_request",
			entry: &HistoryEntry{
				Protocol:  "h2",
				H2Request: nil,
			},
			wantNil: true,
		},
		// edge cases
		{
			name: "h2_empty_headers",
			entry: &HistoryEntry{
				Protocol: "h2",
				H2Request: &H2RequestData{
					Method:    "GET",
					Path:      "/test",
					Authority: "example.com",
					Headers:   []Header{},
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()

				assert.Contains(t, string(result), "GET /test HTTP/1.1")
				assert.Contains(t, string(result), "host: example.com")
			},
		},
		{
			name: "h2_nil_headers",
			entry: &HistoryEntry{
				Protocol: "h2",
				H2Request: &H2RequestData{
					Method:    "GET",
					Path:      "/test",
					Authority: "example.com",
					Headers:   nil,
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()

				assert.Contains(t, string(result), "GET /test HTTP/1.1")
			},
		},
		{
			name: "http1_empty_body",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Method:  "GET",
					Path:    "/",
					Version: "HTTP/1.1",
					Headers: []Header{{Name: "Host", Value: "example.com"}},
					Body:    []byte{},
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()

				assert.Contains(t, string(result), "GET / HTTP/1.1")
			},
		},
	}

	var buf bytes.Buffer // reuse to validate reset
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.FormatRequest(&buf)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				tt.check(t, result)
			}
		})
	}
}

func TestFormatResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		entry   *HistoryEntry
		wantNil bool
		check   func(t *testing.T, result []byte)
	}{
		{
			name: "http1_response",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: &RawHTTP1Response{
					Version:    "HTTP/1.1",
					StatusCode: 200,
					StatusText: "OK",
					Headers:    []Header{{Name: "Content-Type", Value: "text/plain"}},
					Body:       []byte("Hello"),
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()

				assert.Contains(t, string(result), "HTTP/1.1 200 OK")
				assert.Contains(t, string(result), "Content-Type: text/plain")
				assert.Contains(t, string(result), "Hello")
			},
		},
		{
			name: "h2_response",
			entry: &HistoryEntry{
				Protocol: "h2",
				H2Response: &H2ResponseData{
					StatusCode: 201,
					Headers:    []Header{{Name: "content-type", Value: "application/json"}},
					Body:       []byte(`{"id":1}`),
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()

				assert.Contains(t, string(result), "HTTP/2 201 Created")
				assert.Contains(t, string(result), "content-type: application/json")
				assert.Contains(t, string(result), `{"id":1}`)
			},
		},
		{
			name: "nil_http1_response",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: nil,
			},
			wantNil: true,
		},
		{
			name: "nil_h2_response",
			entry: &HistoryEntry{
				Protocol:   "h2",
				H2Response: nil,
			},
			wantNil: true,
		},
		// edge cases
		{
			name: "h2_empty_headers",
			entry: &HistoryEntry{
				Protocol: "h2",
				H2Response: &H2ResponseData{
					StatusCode: 200,
					Headers:    []Header{},
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()

				assert.Contains(t, string(result), "HTTP/2 200")
			},
		},
		{
			name: "h2_nonstandard_status",
			entry: &HistoryEntry{
				Protocol: "h2",
				H2Response: &H2ResponseData{
					StatusCode: 999,
					Headers:    []Header{},
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()

				// StatusText should default to empty or unknown for non-standard codes
				assert.Contains(t, string(result), "HTTP/2 999")
			},
		},
		{
			name: "http1_empty_body",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: &RawHTTP1Response{
					Version:    "HTTP/1.1",
					StatusCode: 204,
					StatusText: "No Content",
					Headers:    []Header{},
					Body:       []byte{},
				},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()

				assert.Contains(t, string(result), "HTTP/1.1 204 No Content")
			},
		},
	}

	var buf bytes.Buffer // reuse to validate reset
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.FormatResponse(&buf)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				tt.check(t, result)
			}
		})
	}
}

func TestGetMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry *HistoryEntry
		want  string
	}{
		{
			name: "http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  &RawHTTP1Request{Method: "POST"},
			},
			want: "POST",
		},
		{
			name: "h2",
			entry: &HistoryEntry{
				Protocol:  "h2",
				H2Request: &H2RequestData{Method: "PUT"},
			},
			want: "PUT",
		},
		{
			name: "nil_http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  nil,
			},
			want: "",
		},
		{
			name: "nil_h2",
			entry: &HistoryEntry{
				Protocol:  "h2",
				H2Request: nil,
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.entry.GetMethod())
		})
	}
}

func TestGetPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry *HistoryEntry
		want  string
	}{
		{
			name: "http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  &RawHTTP1Request{Path: "/api/users"},
			},
			want: "/api/users",
		},
		{
			name: "h2",
			entry: &HistoryEntry{
				Protocol:  "h2",
				H2Request: &H2RequestData{Path: "/api/data"},
			},
			want: "/api/data",
		},
		{
			name: "h2_strips_query",
			entry: &HistoryEntry{
				Protocol:  "h2",
				H2Request: &H2RequestData{Path: "/search?q=test&page=1"},
			},
			want: "/search",
		},
		{
			name: "nil_http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  nil,
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.entry.GetPath())
		})
	}
}

func TestGetHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry *HistoryEntry
		want  string
	}{
		{
			name: "http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Headers: []Header{{Name: "Host", Value: "example.com"}},
				},
			},
			want: "example.com",
		},
		{
			name: "h2",
			entry: &HistoryEntry{
				Protocol:  "h2",
				H2Request: &H2RequestData{Authority: "api.example.com"},
			},
			want: "api.example.com",
		},
		{
			name: "nil_http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  nil,
			},
			want: "",
		},
		// edge cases
		{
			name: "h2_empty_authority",
			entry: &HistoryEntry{
				Protocol:  "h2",
				H2Request: &H2RequestData{Authority: ""},
			},
			want: "",
		},
		{
			name: "http1_host_case_insensitive",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Headers: []Header{{Name: "host", Value: "lowercase.com"}},
				},
			},
			want: "lowercase.com",
		},
		{
			name: "http1_no_host_header",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Headers: []Header{{Name: "X-Custom", Value: "value"}},
				},
			},
			want: "",
		},
		{
			name: "http1_empty_headers",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Headers: []Header{},
				},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.entry.GetHost())
		})
	}
}

func TestGetStatusCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		entry *HistoryEntry
		want  int
	}{
		{
			name: "http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: &RawHTTP1Response{StatusCode: 200},
			},
			want: 200,
		},
		{
			name: "h2",
			entry: &HistoryEntry{
				Protocol:   "h2",
				H2Response: &H2ResponseData{StatusCode: 404},
			},
			want: 404,
		},
		{
			name: "nil_http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: nil,
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.entry.GetStatusCode())
		})
	}
}

func TestGetRequestHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		entry      *HistoryEntry
		headerName string
		want       string
	}{
		{
			name: "http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Headers: []Header{{Name: "Content-Type", Value: "application/json"}},
				},
			},
			headerName: "Content-Type",
			want:       "application/json",
		},
		{
			name: "h2",
			entry: &HistoryEntry{
				Protocol: "h2",
				H2Request: &H2RequestData{
					Headers: []Header{{Name: "authorization", Value: "Bearer token"}},
				},
			},
			headerName: "authorization",
			want:       "Bearer token",
		},
		{
			name: "nil_request",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request:  nil,
			},
			headerName: "Content-Type",
			want:       "",
		},
		{
			name: "case_insensitive_http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Headers: []Header{{Name: "Content-Type", Value: "text/plain"}},
				},
			},
			headerName: "content-type",
			want:       "text/plain",
		},
		{
			name: "case_insensitive_uppercase",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Headers: []Header{{Name: "content-type", Value: "text/html"}},
				},
			},
			headerName: "CONTENT-TYPE",
			want:       "text/html",
		},
		{
			name: "first_matching_header",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Headers: []Header{
						{Name: "X-Custom", Value: "first"},
						{Name: "x-custom", Value: "second"},
					},
				},
			},
			headerName: "X-Custom",
			want:       "first",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.entry.GetRequestHeader(tt.headerName))
		})
	}
}

func TestHistoryStoreClose(t *testing.T) {
	t.Parallel()

	t.Run("close_idempotent", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())

		h.Store(&HistoryEntry{
			Protocol: "http/1.1",
			Request:  &RawHTTP1Request{Method: "GET", Path: "/"},
		})

		// Double close should not panic
		h.Close()
		h.Close()
	})
}

func TestGetResponseHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		entry      *HistoryEntry
		headerName string
		want       string
	}{
		{
			name: "http1",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: &RawHTTP1Response{
					Headers: []Header{{Name: "Content-Type", Value: "text/html"}},
				},
			},
			headerName: "Content-Type",
			want:       "text/html",
		},
		{
			name: "h2",
			entry: &HistoryEntry{
				Protocol: "h2",
				H2Response: &H2ResponseData{
					Headers: []Header{{Name: "x-request-id", Value: "abc123"}},
				},
			},
			headerName: "x-request-id",
			want:       "abc123",
		},
		{
			name: "nil_response",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: nil,
			},
			headerName: "Content-Type",
			want:       "",
		},
		{
			name: "empty_header_name_search",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: &RawHTTP1Response{
					Headers: []Header{{Name: "X-Header", Value: "value"}},
				},
			},
			headerName: "",
			want:       "",
		},
		{
			name: "header_with_empty_value",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: &RawHTTP1Response{
					Headers: []Header{{Name: "X-Empty", Value: ""}},
				},
			},
			headerName: "X-Empty",
			want:       "",
		},
		{
			name: "first_matching_header",
			entry: &HistoryEntry{
				Protocol: "http/1.1",
				Response: &RawHTTP1Response{
					Headers: []Header{
						{Name: "Set-Cookie", Value: "first=1"},
						{Name: "Set-Cookie", Value: "second=2"},
					},
				},
			},
			headerName: "Set-Cookie",
			want:       "first=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.entry.GetResponseHeader(tt.headerName))
		})
	}
}

func TestCount(t *testing.T) {
	t.Parallel()

	t.Run("empty_history", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		assert.Equal(t, 0, h.Count())
	})

	t.Run("after_stores", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		for i := 0; i < 5; i++ {
			entry := &HistoryEntry{
				Protocol: "http/1.1",
				Request:  &RawHTTP1Request{Method: "GET", Path: "/"},
			}
			h.Store(entry)
			assert.Equal(t, i+1, h.Count())
		}
	})
}

func TestNewHistoryStoreRecovery(t *testing.T) {
	t.Parallel()

	t.Run("recovers_offset_from_storage", func(t *testing.T) {
		s := store.NewMemStorage()

		h1 := newHistoryStore(s)
		for i := 0; i < 5; i++ {
			h1.Store(&HistoryEntry{
				Protocol: "http/1.1",
				Request:  &RawHTTP1Request{Method: "GET", Path: "/" + strconv.Itoa(i)},
			})
		}

		// Create new store backed by same storage
		h2 := newHistoryStore(s)
		assert.Equal(t, 5, h2.Count())

		// Existing entries accessible
		for i := 0; i < 5; i++ {
			entry, ok := h2.Get(uint32(i))
			require.True(t, ok)
			assert.Equal(t, "/"+strconv.Itoa(i), entry.GetPath())
		}

		// New entries get non-colliding offsets
		h2.Store(&HistoryEntry{
			Protocol: "http/1.1",
			Request:  &RawHTTP1Request{Method: "GET", Path: "/new"},
		})
		assert.Equal(t, 6, h2.Count())

		entry, ok := h2.Get(5)
		require.True(t, ok)
		assert.Equal(t, "/new", entry.GetPath())
	})

	t.Run("empty_storage", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		assert.Equal(t, 0, h.Count())
	})
}

func TestListConcurrentWithStore(t *testing.T) {
	t.Parallel()

	h := newHistoryStore(store.NewMemStorage())
	t.Cleanup(h.Close)

	// Pre-populate
	for i := 0; i < 100; i++ {
		entry := &HistoryEntry{
			Protocol: "http/1.1",
			Request:  &RawHTTP1Request{Method: "GET", Path: "/"},
		}
		h.Store(entry)
	}

	var wg sync.WaitGroup

	// Concurrent readers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				entries := h.List(10, uint32(j%10))
				_ = entries // just read
			}
		}()
	}

	// Concurrent writers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				entry := &HistoryEntry{
					Protocol: "http/1.1",
					Request:  &RawHTTP1Request{Method: "POST", Path: "/concurrent"},
				}
				h.Store(entry)
			}
		}()
	}

	wg.Wait()

	// Verify all entries are accessible: 100 initial + 250 concurrent writes (5 writers * 50 each)
	count := h.Count()
	assert.Equal(t, 350, count)

	// Verify data integrity by checking some entries
	entries := h.List(10, 0)
	require.Len(t, entries, 10)
	for _, entry := range entries {
		assert.NotEmpty(t, entry.GetMethod())
		assert.NotEmpty(t, entry.GetPath())
	}
}

func TestGetMeta(t *testing.T) {
	t.Parallel()

	t.Run("http1_fields", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		entry := &HistoryEntry{
			Protocol:  "http/1.1",
			Timestamp: time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC),
			Duration:  150 * time.Millisecond,
			Request: &RawHTTP1Request{
				Method:  "POST",
				Path:    "/api/data",
				Query:   "page=1",
				Version: "HTTP/1.1",
				Headers: []Header{{Name: "Host", Value: "example.com"}},
				Body:    []byte(`{"key":"value"}`),
			},
			Response: &RawHTTP1Response{
				StatusCode: 201,
				Headers:    []Header{{Name: "Content-Type", Value: "application/json"}},
				Body:       []byte(`{"id":1}`),
			},
		}
		offset := h.Store(entry)

		meta, ok := h.GetMeta(offset)
		require.True(t, ok)
		assert.Equal(t, uint32(0), meta.Offset)
		assert.Equal(t, "http/1.1", meta.Protocol)
		assert.Equal(t, "POST", meta.Method)
		assert.Equal(t, "example.com", meta.Host)
		assert.Equal(t, "/api/data?page=1", meta.Path)
		assert.Equal(t, 201, meta.Status)
		assert.Equal(t, "application/json", meta.ContentType)
		assert.Equal(t, len(`{"id":1}`), meta.RespLen)
		assert.Equal(t, entry.Timestamp, meta.Timestamp)
		assert.Equal(t, 150*time.Millisecond, meta.Duration)
	})

	t.Run("h2_fields", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		entry := &HistoryEntry{
			Protocol:   "h2",
			H2StreamID: 3,
			Timestamp:  time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC),
			H2Request: &H2RequestData{
				Method:    "GET",
				Authority: "api.example.com",
				Path:      "/users?q=test",
				Headers:   []Header{{Name: "accept", Value: "application/json"}},
			},
			H2Response: &H2ResponseData{
				StatusCode: 200,
				Headers:    []Header{{Name: "content-type", Value: "text/html"}},
				Body:       []byte("response body"),
			},
		}
		offset := h.Store(entry)

		meta, ok := h.GetMeta(offset)
		require.True(t, ok)
		assert.Equal(t, "h2", meta.Protocol)
		assert.Equal(t, "GET", meta.Method)
		assert.Equal(t, "api.example.com", meta.Host)
		assert.Equal(t, "/users?q=test", meta.Path)
		assert.Equal(t, 200, meta.Status)
		assert.Equal(t, "text/html", meta.ContentType)
		assert.Equal(t, len("response body"), meta.RespLen)
		assert.Equal(t, uint32(3), meta.H2StreamID)
	})

	t.Run("not_found", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		_, ok := h.GetMeta(999)
		assert.False(t, ok)
	})
}

func TestListMeta(t *testing.T) {
	t.Parallel()

	t.Run("returns_meta_only", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		for i := 0; i < 5; i++ {
			h.Store(&HistoryEntry{
				Protocol: "http/1.1",
				Request: &RawHTTP1Request{
					Method:  "GET",
					Path:    "/" + strconv.Itoa(i),
					Version: "HTTP/1.1",
					Headers: []Header{{Name: "Host", Value: "example.com"}},
				},
				Response: &RawHTTP1Response{
					StatusCode: 200,
					Body:       []byte("body-" + strconv.Itoa(i)),
				},
			})
		}

		metas := h.ListMeta(3, 1)
		require.Len(t, metas, 3)
		assert.Equal(t, "/1", metas[0].Path)
		assert.Equal(t, "/3", metas[2].Path)
		assert.Equal(t, uint32(1), metas[0].Offset)
		assert.Equal(t, uint32(3), metas[2].Offset)
	})

	t.Run("empty_history", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		metas := h.ListMeta(10, 0)
		assert.Empty(t, metas)
	})
}

func TestStoreMeta_path_includes_query(t *testing.T) {
	t.Parallel()

	t.Run("http1_with_query", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		offset := h.Store(&HistoryEntry{
			Protocol: "http/1.1",
			Request: &RawHTTP1Request{
				Method: "GET",
				Path:   "/search",
				Query:  "q=test&page=2",
			},
		})

		meta, ok := h.GetMeta(offset)
		require.True(t, ok)
		assert.Equal(t, "/search?q=test&page=2", meta.Path)
	})

	t.Run("http1_without_query", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		offset := h.Store(&HistoryEntry{
			Protocol: "http/1.1",
			Request:  &RawHTTP1Request{Method: "GET", Path: "/index"},
		})

		meta, ok := h.GetMeta(offset)
		require.True(t, ok)
		assert.Equal(t, "/index", meta.Path)
	})

	t.Run("h2_path_includes_query", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		offset := h.Store(&HistoryEntry{
			Protocol: "h2",
			H2Request: &H2RequestData{
				Method: "GET",
				Path:   "/api?token=abc",
			},
		})

		meta, ok := h.GetMeta(offset)
		require.True(t, ok)
		assert.Equal(t, "/api?token=abc", meta.Path)
	})
}

func TestUpdateConcurrent(t *testing.T) {
	t.Parallel()

	h := newHistoryStore(store.NewMemStorage())
	t.Cleanup(h.Close)

	// Store an entry
	entry := &HistoryEntry{
		Protocol: "http/1.1",
		Request:  &RawHTTP1Request{Method: "GET", Path: "/"},
	}
	offset := h.Store(entry)

	// Concurrent updates
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			entry, ok := h.Get(offset)
			if !ok {
				return
			}
			entry.Response = &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 200 + idx,
			}
			h.Update(entry)
		}(i)
	}

	wg.Wait()

	// Verify entry is still readable with valid data
	retrieved, ok := h.Get(offset)
	require.True(t, ok)
	require.NotNil(t, retrieved.Response)
	assert.Equal(t, "HTTP/1.1", retrieved.Response.Version)
	assert.GreaterOrEqual(t, retrieved.Response.StatusCode, 200)
	assert.Less(t, retrieved.Response.StatusCode, 210)
}

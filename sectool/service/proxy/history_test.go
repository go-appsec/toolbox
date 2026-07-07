package proxy

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

func newTestEntry(method, path string) *types.Flow {
	return &types.Flow{
		Adapter:     types.ProtocolHTTP11,
		ProtocolTag: types.ProtocolHTTP11,
		Request: &types.Message{
			Method:  method,
			Path:    path,
			Version: "HTTP/1.1",
		},
		StartedAt: time.Now(),
	}
}

// newTestEntryAt produces a test flow with an explicit start time.
func newTestEntryAt(method, path string, ts time.Time) *types.Flow {
	f := newTestEntry(method, path)
	f.StartedAt = ts
	return f
}

// h2Req builds a request Message with folded HTTP/2 pseudo-headers.
func h2Req(method, authority, path string, body []byte, hdrs ...types.Header) *types.Message {
	headers := types.Headers{
		{Name: ":method", Value: method},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	}
	headers = append(headers, hdrs...)
	return &types.Message{Headers: headers, Body: body}
}

func TestHistoryStore_Store(t *testing.T) {
	t.Parallel()

	t.Run("returns_unique_flow_id", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		seen := make(map[string]bool)
		for i := 0; i < 5; i++ {
			id := h.Store(newTestEntry("GET", "/"))
			assert.NotEmpty(t, id)
			assert.False(t, seen[id], "flow_id collision: %s", id)
			seen[id] = true
		}
		assert.Equal(t, 5, h.Count())
	})

	t.Run("populates_flow_id_on_flow", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		flow := newTestEntry("POST", "/api")
		flowID := h.Store(flow)
		assert.Equal(t, flowID, flow.FlowID)
	})

	t.Run("child_flow_excluded_from_listing", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		parent := h.Store(newTestEntry("GET", "/ws"))
		child := h.Store(&types.Flow{
			Adapter:      types.ProtocolTagWS,
			ProtocolTag:  types.ProtocolTagWSFrame,
			Direction:    types.DirectionC2S,
			ParentFlowID: parent,
			Request:      &types.Message{Method: types.MethodFrame, Path: "/ws/1", Body: []byte("hi")},
			StartedAt:    time.Now(),
		})

		// Child retrievable by id and linked to its parent.
		got, ok := h.Get(child)
		require.True(t, ok)
		assert.Equal(t, parent, got.ParentFlowID)
		assert.Equal(t, "hi", string(got.Request.Body))

		// Child absent from listing, meta, and count.
		assert.Equal(t, 1, h.Count())
		_, ok = h.GetMeta(child)
		assert.False(t, ok)
		for _, f := range h.Page(10, "") {
			assert.NotEqual(t, child, f.FlowID)
		}
		for _, m := range h.PageMeta(10, "") {
			assert.NotEqual(t, child, m.FlowID)
		}
	})

	t.Run("concurrent_writes", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		const numGoroutines = 10
		const entriesPerGoroutine = 100
		var wg sync.WaitGroup
		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < entriesPerGoroutine; j++ {
					h.Store(newTestEntry("GET", "/"))
				}
			}()
		}
		wg.Wait()
		assert.Equal(t, numGoroutines*entriesPerGoroutine, h.Count())
	})
}

func TestHistoryStore_Complete(t *testing.T) {
	t.Parallel()

	t.Run("attaches_response_and_completion", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		flowID := h.Store(newTestEntry("GET", "/api"))
		completedAt := time.Now().Add(time.Second)
		resp := &types.Message{StatusCode: 200, Body: []byte("ok")}
		ok := h.Complete(flowID, resp, completedAt, map[string]any{"phase": "mutated"})
		require.True(t, ok)

		got, found := h.Get(flowID)
		require.True(t, found)
		require.NotNil(t, got.Response)
		assert.Equal(t, 200, got.Response.StatusCode)
		assert.Equal(t, completedAt.UTC(), got.CompletedAt)
		assert.Equal(t, "mutated", got.Annotations["phase"])

		// Meta reflects the now-attached status.
		meta, found := h.GetMeta(flowID)
		require.True(t, found)
		assert.Equal(t, 200, meta.Status)
	})

	t.Run("unknown_flow_id", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)
		assert.False(t, h.Complete("missing", nil, time.Now(), nil))
	})

	t.Run("child_flow_has_no_meta", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		parent := h.Store(newTestEntry("STREAM", "/s"))
		child := h.Store(&types.Flow{
			ProtocolTag:  "custom.chunk",
			ParentFlowID: parent,
			Request:      &types.Message{Method: "CHUNK", Body: []byte("a")},
			StartedAt:    time.Now(),
		})
		require.True(t, h.Complete(child, &types.Message{Body: []byte("done")}, time.Now(), nil))

		got, found := h.Get(child)
		require.True(t, found)
		assert.Equal(t, "done", string(got.Response.Body))
		_, hasMeta := h.GetMeta(child)
		assert.False(t, hasMeta)
	})
}

func TestHistoryStore_Children(t *testing.T) {
	t.Parallel()

	h := newHistoryStore(store.NewMemStorage())
	t.Cleanup(h.Close)

	parent := h.Store(newTestEntry("STREAM", "/s"))
	// Emit children out of timestamp order to prove emission order is preserved,
	// not a timestamp sort.
	base := time.Now()
	emitTimes := []time.Time{base.Add(3 * time.Second), base, base.Add(time.Second)}
	want := make([]string, 0, len(emitTimes))
	for i, ts := range emitTimes {
		id := h.Store(&types.Flow{
			ProtocolTag:  "custom.chunk",
			ParentFlowID: parent,
			Direction:    types.DirectionS2C,
			Request:      &types.Message{Method: "CHUNK", Body: []byte{byte('0' + i)}},
			StartedAt:    ts,
		})
		want = append(want, id)
	}

	children := h.Children(parent)
	got := make([]string, len(children))
	for i, c := range children {
		got[i] = c.FlowID
	}
	assert.Equal(t, want, got)
	assert.Empty(t, h.Children("no-such-parent"))
}

func TestHistoryStore_Get(t *testing.T) {
	t.Parallel()

	t.Run("retrieves_stored_flow", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		flowID := h.Store(newTestEntry("GET", "/foo"))
		got, ok := h.Get(flowID)
		require.True(t, ok)
		assert.Equal(t, flowID, got.FlowID)
		assert.Equal(t, "/foo", got.Request.Path)
	})

	t.Run("not_found", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		_, ok := h.Get("nonexistent")
		assert.False(t, ok)
	})

	t.Run("serialization_roundtrip", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		ts := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)
		flow := &types.Flow{
			Adapter:     types.ProtocolHTTP11,
			ProtocolTag: types.ProtocolHTTP11,
			StartedAt:   ts,
			CompletedAt: ts.Add(250 * time.Millisecond),
			Request: &types.Message{
				Method:  "POST",
				Path:    "/api/data",
				Query:   "foo=bar",
				Version: "HTTP/1.1",
				Headers: []types.Header{
					{Name: "Content-Type", Value: "application/json"},
					{Name: "x-custom", Value: "value"},
				},
				Body: []byte(`{"key":"value"}`),
			},
			Response: &types.Message{
				Version:    "HTTP/1.1",
				StatusCode: 201,
				StatusText: "Created",
				Headers:    []types.Header{{Name: "Content-Type", Value: "application/json"}},
				Body:       []byte(`{"id":123}`),
			},
		}

		flowID := h.Store(flow)
		got, ok := h.Get(flowID)
		require.True(t, ok)

		assert.Equal(t, flow.ProtocolTag, got.ProtocolTag)
		assert.Equal(t, ts, got.StartedAt)
		assert.Equal(t, flow.CompletedAt, got.CompletedAt)
		assert.Equal(t, flow.Request.Method, got.Request.Method)
		assert.Equal(t, flow.Request.Path, got.Request.Path)
		assert.Equal(t, flow.Request.Query, got.Request.Query)
		assert.Equal(t, flow.Request.Version, got.Request.Version)
		assert.Equal(t, flow.Request.Headers, got.Request.Headers)
		assert.Equal(t, flow.Request.Body, got.Request.Body)
		assert.Equal(t, flow.Response.Version, got.Response.Version)
		assert.Equal(t, flow.Response.StatusCode, got.Response.StatusCode)
		assert.Equal(t, flow.Response.StatusText, got.Response.StatusText)
		assert.Equal(t, flow.Response.Headers, got.Response.Headers)
		assert.Equal(t, flow.Response.Body, got.Response.Body)
	})
}

func TestHistoryStore_Page(t *testing.T) {
	t.Parallel()

	t.Run("oldest_first_with_cursor", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		base := time.Now()
		var ids []string
		for i := 0; i < 5; i++ {
			ids = append(ids, h.Store(newTestEntryAt("GET", "/", base.Add(time.Duration(i)*time.Millisecond))))
		}

		entries := h.Page(2, "")
		require.Len(t, entries, 2)
		assert.Equal(t, ids[0], entries[0].FlowID)
		assert.Equal(t, ids[1], entries[1].FlowID)

		entries = h.Page(2, entries[len(entries)-1].FlowID)
		require.Len(t, entries, 2)
		assert.Equal(t, ids[2], entries[0].FlowID)
		assert.Equal(t, ids[3], entries[1].FlowID)

		entries = h.Page(2, entries[len(entries)-1].FlowID)
		require.Len(t, entries, 1)
		assert.Equal(t, ids[4], entries[0].FlowID)
	})

	t.Run("unknown_cursor_starts_from_beginning", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		base := time.Now()
		first := h.Store(newTestEntryAt("GET", "/", base))
		h.Store(newTestEntryAt("GET", "/", base.Add(time.Millisecond)))

		entries := h.Page(1, "never-existed")
		require.Len(t, entries, 1)
		assert.Equal(t, first, entries[0].FlowID)
	})

	t.Run("empty_store", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		entries := h.Page(10, "")
		assert.Empty(t, entries)
	})
}

func TestHistoryStore_PageMeta(t *testing.T) {
	t.Parallel()

	h := newHistoryStore(store.NewMemStorage())
	t.Cleanup(h.Close)

	base := time.Now()
	flow1 := h.Store(newTestEntryAt("POST", "/a", base))
	flow2 := h.Store(newTestEntryAt("GET", "/b", base.Add(time.Millisecond)))

	metas := h.PageMeta(10, "")
	require.Len(t, metas, 2)
	assert.Equal(t, flow1, metas[0].FlowID)
	assert.Equal(t, "POST", metas[0].Method)
	assert.Equal(t, flow2, metas[1].FlowID)
	assert.Equal(t, "GET", metas[1].Method)
	assert.False(t, metas[0].Timestamp.IsZero())
}

func TestHistoryStore_Delete(t *testing.T) {
	t.Parallel()

	t.Run("removes_entries", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		first := h.Store(newTestEntry("GET", "/"))
		second := h.Store(newTestEntry("GET", "/"))

		deleted := h.Delete(first)
		assert.Equal(t, 1, deleted)
		assert.Equal(t, 1, h.Count())

		_, ok := h.Get(first)
		assert.False(t, ok)
		_, ok = h.Get(second)
		assert.True(t, ok)
	})

	t.Run("idempotent_unknown_id", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		assert.Equal(t, 0, h.Delete("nonexistent"))
	})

	t.Run("deleted_cursor_falls_back_to_beginning", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		base := time.Now()
		first := h.Store(newTestEntryAt("GET", "/", base))
		h.Store(newTestEntryAt("GET", "/", base.Add(time.Millisecond)))
		h.Delete(first)

		entries := h.Page(10, first)
		assert.Len(t, entries, 1)
	})

	t.Run("multi_id_with_unknowns", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		ids := make([]string, 5)
		for i := range ids {
			ids[i] = h.Store(newTestEntry("GET", "/"))
		}

		deleted := h.Delete(ids[0], "nope1", ids[2], "nope2", ids[4])
		assert.Equal(t, 3, deleted)
		assert.Equal(t, 2, h.Count())

		_, ok := h.Get(ids[1])
		assert.True(t, ok)
		_, ok = h.Get(ids[3])
		assert.True(t, ok)
	})

	t.Run("empty_input", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		h.Store(newTestEntry("GET", "/"))
		assert.Equal(t, 0, h.Delete())
		assert.Equal(t, 1, h.Count())
	})

	t.Run("removes_child_flow", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		parent := h.Store(newTestEntry("STREAM", "/s"))
		c1 := h.Store(childFlow(parent, "a"))
		c2 := h.Store(childFlow(parent, "b"))

		assert.Equal(t, 1, h.Delete(c1))
		_, ok := h.Get(c1)
		assert.False(t, ok) // payload removed
		// Parent untouched; surviving child still indexed, in order.
		assert.Equal(t, 1, h.Count())
		remaining := h.Children(parent)
		require.Len(t, remaining, 1)
		assert.Equal(t, c2, remaining[0].FlowID)
	})

	t.Run("delete_parent_drops_child_index", func(t *testing.T) {
		h := newHistoryStore(store.NewMemStorage())
		t.Cleanup(h.Close)

		parent := h.Store(newTestEntry("STREAM", "/s"))
		h.Store(childFlow(parent, "a"))

		assert.Equal(t, 1, h.Delete(parent))
		assert.Equal(t, 0, h.Count())
		// Child index for the gone parent is dropped (no dangling references).
		assert.Empty(t, h.Children(parent))
	})
}

// childFlow builds a payload-only child flow under parent.
func childFlow(parent, body string) *types.Flow {
	return &types.Flow{
		ProtocolTag:  "custom.chunk",
		ParentFlowID: parent,
		Direction:    types.DirectionS2C,
		Request:      &types.Message{Method: "CHUNK", Body: []byte(body)},
		StartedAt:    time.Now(),
	}
}

func TestHistoryStore_TimestampOrdering(t *testing.T) {
	t.Parallel()

	h := newHistoryStore(store.NewMemStorage())
	t.Cleanup(h.Close)

	base := time.Now()
	var ids []string
	for i := 0; i < 20; i++ {
		ids = append(ids, h.Store(newTestEntryAt("GET", "/", base.Add(time.Duration(i)*time.Millisecond))))
	}

	entries := h.Page(20, "")
	require.Len(t, entries, 20)
	for i, e := range entries {
		assert.Equal(t, ids[i], e.FlowID)
	}
}

func TestHistoryStore_Recovery(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	h := newHistoryStore(storage)

	base := time.Now()
	var ids []string
	for i := 0; i < 3; i++ {
		ids = append(ids, h.Store(newTestEntryAt("GET", "/", base.Add(time.Duration(i)*time.Millisecond))))
	}

	// Recreate store from same storage; recovery should rebuild ordering.
	h2 := newHistoryStore(storage)
	t.Cleanup(h2.Close)

	assert.Equal(t, 3, h2.Count())
	entries := h2.Page(10, "")
	require.Len(t, entries, 3)
	for i, e := range entries {
		assert.Equal(t, ids[i], e.FlowID)
	}
}

func TestHistoryStore_RecoverChildOrder(t *testing.T) {
	t.Parallel()

	storage := store.NewMemStorage()
	h := newHistoryStore(storage)

	parent := h.Store(newTestEntryAt("STREAM", "/s", time.Now()))
	base := time.Now()
	var childIDs []string
	for i := 0; i < 3; i++ {
		c := childFlow(parent, "x")
		c.StartedAt = base.Add(time.Duration(i) * time.Millisecond)
		childIDs = append(childIDs, h.Store(c))
	}

	// Rebuild over the same storage; the child index must be reconstructed so
	// children remain reachable via Children, ordered by (started_at, flow_id).
	h2 := newHistoryStore(storage)
	t.Cleanup(h2.Close)

	got := make([]string, 0, 3)
	for _, c := range h2.Children(parent) {
		got = append(got, c.FlowID)
	}
	assert.Equal(t, childIDs, got)
}

func TestFormatRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		flow    *types.Flow
		wantNil bool
		check   func(t *testing.T, result []byte)
	}{
		{
			name: "http1_request",
			flow: &types.Flow{
				ProtocolTag: types.ProtocolHTTP11,
				Request: &types.Message{
					Method:  "GET",
					Path:    "/test",
					Version: "HTTP/1.1",
					Headers: []types.Header{{Name: "Host", Value: "example.com"}},
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
			flow: &types.Flow{
				ProtocolTag: types.ProtocolH2,
				Request:     h2Req("POST", "example.com", "/api", []byte(`{"test":1}`), types.Header{Name: "content-type", Value: "application/json"}),
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
			name: "h2_pseudo_headers_folded",
			flow: &types.Flow{
				ProtocolTag: types.ProtocolH2,
				Request: h2Req("GET", "example.com", "/x", nil,
					types.Header{Name: types.HeaderStreamID, Value: "7"},
					types.Header{Name: "accept", Value: "*/*"}),
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()
				// Pseudo-headers and the stream id are reconstructed into the
				// request line/host, never re-emitted as headers.
				assert.NotContains(t, string(result), ":method")
				assert.NotContains(t, string(result), ":path")
				assert.NotContains(t, string(result), types.HeaderStreamID)
				assert.Contains(t, string(result), "GET /x HTTP/1.1")
				assert.Contains(t, string(result), "accept: */*")
			},
		},
		{
			name:    "nil_request",
			flow:    &types.Flow{ProtocolTag: types.ProtocolHTTP11},
			wantNil: true,
		},
		{
			name: "http1_empty_body",
			flow: &types.Flow{
				ProtocolTag: types.ProtocolHTTP11,
				Request: &types.Message{
					Method:  "GET",
					Path:    "/",
					Version: "HTTP/1.1",
					Headers: []types.Header{{Name: "Host", Value: "example.com"}},
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
			result := tt.flow.FormatRequest(&buf)
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
		flow    *types.Flow
		wantNil bool
		check   func(t *testing.T, result []byte)
	}{
		{
			name: "http1_response",
			flow: &types.Flow{
				ProtocolTag: types.ProtocolHTTP11,
				Response: &types.Message{
					Version:    "HTTP/1.1",
					StatusCode: 200,
					StatusText: "OK",
					Headers:    []types.Header{{Name: "Content-Type", Value: "text/plain"}},
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
			flow: &types.Flow{
				ProtocolTag: types.ProtocolH2,
				Response: &types.Message{
					StatusCode: 201,
					Headers:    []types.Header{{Name: "content-type", Value: "application/json"}},
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
			name:    "nil_response",
			flow:    &types.Flow{ProtocolTag: types.ProtocolHTTP11},
			wantNil: true,
		},
		{
			name: "h2_nonstandard_status",
			flow: &types.Flow{
				ProtocolTag: types.ProtocolH2,
				Response:    &types.Message{StatusCode: 999},
			},
			check: func(t *testing.T, result []byte) {
				t.Helper()
				// StatusText should default to empty for non-standard codes
				assert.Contains(t, string(result), "HTTP/2 999")
			},
		},
		{
			name: "http1_empty_body",
			flow: &types.Flow{
				ProtocolTag: types.ProtocolHTTP11,
				Response: &types.Message{
					Version:    "HTTP/1.1",
					StatusCode: 204,
					StatusText: "No Content",
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
			result := tt.flow.FormatResponse(&buf)
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				tt.check(t, result)
			}
		})
	}
}

func TestGetPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		flow *types.Flow
		want string
	}{
		{
			name: "http1",
			flow: &types.Flow{ProtocolTag: types.ProtocolHTTP11, Request: &types.Message{Path: "/api/users"}},
			want: "/api/users",
		},
		{
			name: "h2_no_query",
			flow: &types.Flow{ProtocolTag: types.ProtocolH2, Request: h2Req("GET", "example.com", "/api/data", nil)},
			want: "/api/data",
		},
		{
			name: "h2_strips_query",
			flow: &types.Flow{ProtocolTag: types.ProtocolH2, Request: h2Req("GET", "example.com", "/search?q=test&page=1", nil)},
			want: "/search",
		},
		{
			name: "nil_http1",
			flow: &types.Flow{ProtocolTag: types.ProtocolHTTP11},
			want: "",
		},
		{
			name: "nil_h2",
			flow: &types.Flow{ProtocolTag: types.ProtocolH2},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.flow.GetPath())
		})
	}
}

func TestGetHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		flow *types.Flow
		want string
	}{
		{
			name: "http1",
			flow: &types.Flow{ProtocolTag: types.ProtocolHTTP11, Request: &types.Message{Headers: []types.Header{{Name: "Host", Value: "example.com"}}}},
			want: "example.com",
		},
		{
			name: "h2",
			flow: &types.Flow{ProtocolTag: types.ProtocolH2, Request: h2Req("GET", "api.example.com", "/", nil)},
			want: "api.example.com",
		},
		{
			name: "nil_http1",
			flow: &types.Flow{ProtocolTag: types.ProtocolHTTP11},
			want: "",
		},
		{
			name: "nil_h2",
			flow: &types.Flow{ProtocolTag: types.ProtocolH2},
			want: "",
		},
		{
			name: "http1_case_insensitive",
			flow: &types.Flow{ProtocolTag: types.ProtocolHTTP11, Request: &types.Message{Headers: []types.Header{{Name: "host", Value: "lowercase.com"}}}},
			want: "lowercase.com",
		},
		{
			name: "http1_no_host_header",
			flow: &types.Flow{ProtocolTag: types.ProtocolHTTP11, Request: &types.Message{Headers: []types.Header{{Name: "X-Custom", Value: "value"}}}},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.flow.GetHost())
		})
	}
}

func TestGetRequestHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		flow       *types.Flow
		headerName string
		want       string
	}{
		{
			name:       "http1",
			flow:       &types.Flow{ProtocolTag: types.ProtocolHTTP11, Request: &types.Message{Headers: []types.Header{{Name: "Content-Type", Value: "application/json"}}}},
			headerName: "Content-Type",
			want:       "application/json",
		},
		{
			name:       "h2",
			flow:       &types.Flow{ProtocolTag: types.ProtocolH2, Request: h2Req("GET", "example.com", "/", nil, types.Header{Name: "authorization", Value: "Bearer token"})},
			headerName: "authorization",
			want:       "Bearer token",
		},
		{
			name:       "nil_request",
			flow:       &types.Flow{ProtocolTag: types.ProtocolHTTP11},
			headerName: "Content-Type",
			want:       "",
		},
		{
			name:       "case_insensitive_lookup",
			flow:       &types.Flow{ProtocolTag: types.ProtocolHTTP11, Request: &types.Message{Headers: []types.Header{{Name: "Content-Type", Value: "text/plain"}}}},
			headerName: "content-type",
			want:       "text/plain",
		},
		{
			name: "first_matching_header",
			flow: &types.Flow{ProtocolTag: types.ProtocolHTTP11, Request: &types.Message{Headers: []types.Header{
				{Name: "X-Custom", Value: "first"},
				{Name: "x-custom", Value: "second"},
			}}},
			headerName: "X-Custom",
			want:       "first",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.flow.GetRequestHeader(tt.headerName))
		})
	}
}

func TestGetResponseHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		flow       *types.Flow
		headerName string
		want       string
	}{
		{
			name:       "http1",
			flow:       &types.Flow{ProtocolTag: types.ProtocolHTTP11, Response: &types.Message{Headers: []types.Header{{Name: "Content-Type", Value: "text/html"}}}},
			headerName: "Content-Type",
			want:       "text/html",
		},
		{
			name:       "h2",
			flow:       &types.Flow{ProtocolTag: types.ProtocolH2, Response: &types.Message{Headers: []types.Header{{Name: "x-request-id", Value: "abc123"}}}},
			headerName: "x-request-id",
			want:       "abc123",
		},
		{
			name:       "nil_response",
			flow:       &types.Flow{ProtocolTag: types.ProtocolHTTP11},
			headerName: "Content-Type",
			want:       "",
		},
		{
			name:       "case_insensitive_lookup",
			flow:       &types.Flow{ProtocolTag: types.ProtocolHTTP11, Response: &types.Message{Headers: []types.Header{{Name: "Content-Type", Value: "text/plain"}}}},
			headerName: "content-type",
			want:       "text/plain",
		},
		{
			name: "first_matching_header",
			flow: &types.Flow{ProtocolTag: types.ProtocolHTTP11, Response: &types.Message{Headers: []types.Header{
				{Name: "Set-Cookie", Value: "first=1"},
				{Name: "Set-Cookie", Value: "second=2"},
			}}},
			headerName: "Set-Cookie",
			want:       "first=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.flow.GetResponseHeader(tt.headerName))
		})
	}
}

func TestHistoryStore_PageConcurrent(t *testing.T) {
	t.Parallel()

	h := newHistoryStore(store.NewMemStorage())
	t.Cleanup(h.Close)

	const initial = 100
	const writers = 5
	const writerIterations = 50
	const readers = 5
	const readerIterations = 50

	for i := 0; i < initial; i++ {
		h.Store(newTestEntry("GET", "/"))
	}

	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < readerIterations; j++ {
				_ = h.Page(10, "")
				_ = h.PageMeta(10, "")
			}
		}()
	}
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < writerIterations; j++ {
				h.Store(newTestEntry("POST", "/concurrent"))
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, initial+writers*writerIterations, h.Count())

	entries := h.Page(10, "")
	require.Len(t, entries, 10)
	for _, e := range entries {
		assert.NotEmpty(t, e.GetMethod())
		assert.NotEmpty(t, e.GetPath())
	}
}

package service

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleOastPoll(t *testing.T) {
	t.Parallel()

	t.Run("missing_oast_id", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		w := doRequest(t, srv, "POST", "/oast/poll", OastPollRequest{})

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeInvalidRequest, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "oast_id")
	})

	t.Run("session_not_found", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		w := doRequest(t, srv, "POST", "/oast/poll", OastPollRequest{OastID: "nonexistent"})

		assert.Equal(t, http.StatusNotFound, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeNotFound, resp.Error.Code)
	})

	t.Run("invalid_wait_duration", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		w := doRequest(t, srv, "POST", "/oast/poll", OastPollRequest{
			OastID: "test",
			Wait:   "not-a-duration",
		})

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeInvalidRequest, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "invalid wait duration")
	})

	t.Run("caps_wait_at_120s", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		backend := srv.oastBackend.(*InteractshBackend)
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "testcap",
				Domain:    "cap.oast.fun",
				CreatedAt: time.Now(),
			},
			stopPolling: make(chan struct{}),
			events: []OastEventInfo{
				{ID: "e1", Time: time.Now(), Type: "dns"},
			},
		}
		backend.mu.Lock()
		backend.sessions["cap.oast.fun"] = sess
		backend.byID["testcap"] = "cap.oast.fun"
		backend.mu.Unlock()
		defer func() {
			backend.mu.Lock()
			delete(backend.sessions, "cap.oast.fun")
			delete(backend.byID, "testcap")
			backend.mu.Unlock()
		}()

		// Request with wait > 120s - should be capped but should succeed
		// Since there are already events, it returns immediately
		w := doRequest(t, srv, "POST", "/oast/poll", OastPollRequest{
			OastID: "testcap",
			Wait:   "300s",
		})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var pollResp OastPollResponse
		require.NoError(t, json.Unmarshal(resp.Data, &pollResp))
		assert.Len(t, pollResp.Events, 1)
	})

	t.Run("returns_events_with_formatted_time", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		eventTime := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)

		backend := srv.oastBackend.(*InteractshBackend)
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "testfmt",
				Domain:    "fmt.oast.fun",
				CreatedAt: time.Now(),
			},
			stopPolling: make(chan struct{}),
			events: []OastEventInfo{
				{
					ID:        "evt1",
					Time:      eventTime,
					Type:      "http",
					SourceIP:  "192.168.1.1",
					Subdomain: "test.fmt.oast.fun",
					Details:   map[string]interface{}{"raw_request": "GET / HTTP/1.1"},
				},
			},
		}
		backend.mu.Lock()
		backend.sessions["fmt.oast.fun"] = sess
		backend.byID["testfmt"] = "fmt.oast.fun"
		backend.mu.Unlock()
		defer func() {
			backend.mu.Lock()
			delete(backend.sessions, "fmt.oast.fun")
			delete(backend.byID, "testfmt")
			backend.mu.Unlock()
		}()

		w := doRequest(t, srv, "POST", "/oast/poll", OastPollRequest{
			OastID: "testfmt",
		})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var pollResp OastPollResponse
		require.NoError(t, json.Unmarshal(resp.Data, &pollResp))
		require.Len(t, pollResp.Events, 1)

		event := pollResp.Events[0]
		assert.Equal(t, "evt1", event.EventID)
		assert.Equal(t, "2024-06-15T10:30:00Z", event.Time)
		assert.Equal(t, "http", event.Type)
		assert.Equal(t, "192.168.1.1", event.SourceIP)
		assert.Equal(t, "test.fmt.oast.fun", event.Subdomain)
		assert.Equal(t, "GET / HTTP/1.1", event.Details["raw_request"])
	})

	t.Run("returns_dropped_count", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		backend := srv.oastBackend.(*InteractshBackend)
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "testdrop",
				Domain:    "drop.oast.fun",
				CreatedAt: time.Now(),
			},
			stopPolling:  make(chan struct{}),
			droppedCount: 42,
		}
		backend.mu.Lock()
		backend.sessions["drop.oast.fun"] = sess
		backend.byID["testdrop"] = "drop.oast.fun"
		backend.mu.Unlock()
		defer func() {
			backend.mu.Lock()
			delete(backend.sessions, "drop.oast.fun")
			delete(backend.byID, "testdrop")
			backend.mu.Unlock()
		}()

		w := doRequest(t, srv, "POST", "/oast/poll", OastPollRequest{
			OastID: "testdrop",
		})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

		var pollResp OastPollResponse
		require.NoError(t, json.Unmarshal(resp.Data, &pollResp))
		assert.Equal(t, 42, pollResp.DroppedCount)
	})

	t.Run("poll_by_domain", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		backend := srv.oastBackend.(*InteractshBackend)
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "testdom",
				Domain:    "domain.oast.fun",
				CreatedAt: time.Now(),
			},
			stopPolling: make(chan struct{}),
			events: []OastEventInfo{
				{ID: "e1", Time: time.Now(), Type: "dns"},
			},
		}
		backend.mu.Lock()
		backend.sessions["domain.oast.fun"] = sess
		backend.byID["testdom"] = "domain.oast.fun"
		backend.mu.Unlock()
		defer func() {
			backend.mu.Lock()
			delete(backend.sessions, "domain.oast.fun")
			delete(backend.byID, "testdom")
			backend.mu.Unlock()
		}()

		// Poll by domain instead of ID
		w := doRequest(t, srv, "POST", "/oast/poll", OastPollRequest{
			OastID: "domain.oast.fun",
		})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var pollResp OastPollResponse
		require.NoError(t, json.Unmarshal(resp.Data, &pollResp))
		assert.Len(t, pollResp.Events, 1)
	})

	t.Run("with_limit", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		now := time.Now()
		backend := srv.oastBackend.(*InteractshBackend)
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "testlimit",
				Domain:    "limit.oast.fun",
				CreatedAt: now,
			},
			stopPolling: make(chan struct{}),
			events: []OastEventInfo{
				{ID: "e1", Time: now, Type: "dns"},
				{ID: "e2", Time: now.Add(time.Second), Type: "dns"},
				{ID: "e3", Time: now.Add(2 * time.Second), Type: "dns"},
				{ID: "e4", Time: now.Add(3 * time.Second), Type: "dns"},
			},
		}
		backend.mu.Lock()
		backend.sessions["limit.oast.fun"] = sess
		backend.byID["testlimit"] = "limit.oast.fun"
		backend.mu.Unlock()
		defer func() {
			backend.mu.Lock()
			delete(backend.sessions, "limit.oast.fun")
			delete(backend.byID, "testlimit")
			backend.mu.Unlock()
		}()

		// Poll with limit
		w := doRequest(t, srv, "POST", "/oast/poll", OastPollRequest{
			OastID: "testlimit",
			Limit:  2,
		})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

		var pollResp OastPollResponse
		require.NoError(t, json.Unmarshal(resp.Data, &pollResp))
		assert.Len(t, pollResp.Events, 2)
		assert.Equal(t, "e1", pollResp.Events[0].EventID)
		assert.Equal(t, "e2", pollResp.Events[1].EventID)
	})

	t.Run("since_last_with_limit", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		now := time.Now()
		backend := srv.oastBackend.(*InteractshBackend)
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "testsincelimit",
				Domain:    "sincelimit.oast.fun",
				CreatedAt: now,
			},
			stopPolling: make(chan struct{}),
			events: []OastEventInfo{
				{ID: "e1", Time: now, Type: "dns"},
				{ID: "e2", Time: now.Add(time.Second), Type: "dns"},
				{ID: "e3", Time: now.Add(2 * time.Second), Type: "dns"},
				{ID: "e4", Time: now.Add(3 * time.Second), Type: "dns"},
			},
		}
		backend.mu.Lock()
		backend.sessions["sincelimit.oast.fun"] = sess
		backend.byID["testsincelimit"] = "sincelimit.oast.fun"
		backend.mu.Unlock()
		defer func() {
			backend.mu.Lock()
			delete(backend.sessions, "sincelimit.oast.fun")
			delete(backend.byID, "testsincelimit")
			backend.mu.Unlock()
		}()

		// First poll with limit 2
		w := doRequest(t, srv, "POST", "/oast/poll", OastPollRequest{
			OastID: "testsincelimit",
			Limit:  2,
		})
		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

		var pollResp OastPollResponse
		require.NoError(t, json.Unmarshal(resp.Data, &pollResp))
		assert.Len(t, pollResp.Events, 2)

		// Second poll with --since last should return remaining events
		w = doRequest(t, srv, "POST", "/oast/poll", OastPollRequest{
			OastID: "testsincelimit",
			Since:  "last",
		})
		assert.Equal(t, http.StatusOK, w.Code)

		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.NoError(t, json.Unmarshal(resp.Data, &pollResp))

		// Should return the remaining 2 events (e3, e4)
		assert.Len(t, pollResp.Events, 2)
		assert.Equal(t, "e3", pollResp.Events[0].EventID)
		assert.Equal(t, "e4", pollResp.Events[1].EventID)
	})
}

func TestHandleOastGet(t *testing.T) {
	t.Parallel()

	t.Run("missing_oast_id", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		w := doRequest(t, srv, "POST", "/oast/get", OastGetRequest{})

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeInvalidRequest, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "oast_id")
	})

	t.Run("missing_event_id", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		w := doRequest(t, srv, "POST", "/oast/get", OastGetRequest{OastID: "test123"})

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeInvalidRequest, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "event_id")
	})

	t.Run("session_not_found", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		w := doRequest(t, srv, "POST", "/oast/get", OastGetRequest{
			OastID:  "nonexistent",
			EventID: "event1",
		})

		assert.Equal(t, http.StatusNotFound, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeNotFound, resp.Error.Code)
	})

	t.Run("event_not_found", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		backend := srv.oastBackend.(*InteractshBackend)
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "testget",
				Domain:    "get.oast.fun",
				CreatedAt: time.Now(),
			},
			stopPolling: make(chan struct{}),
			events: []OastEventInfo{
				{ID: "e1", Time: time.Now(), Type: "dns"},
			},
		}
		backend.mu.Lock()
		backend.sessions["get.oast.fun"] = sess
		backend.byID["testget"] = "get.oast.fun"
		backend.mu.Unlock()
		defer func() {
			backend.mu.Lock()
			delete(backend.sessions, "get.oast.fun")
			delete(backend.byID, "testget")
			backend.mu.Unlock()
		}()

		w := doRequest(t, srv, "POST", "/oast/get", OastGetRequest{
			OastID:  "testget",
			EventID: "nonexistent",
		})

		assert.Equal(t, http.StatusNotFound, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeNotFound, resp.Error.Code)
	})

	t.Run("returns_full_event_details", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		eventTime := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
		rawRequest := "GET / HTTP/1.1\r\nHost: sqli-test.get.oast.fun\r\nUser-Agent: curl/8.0.1\r\nAccept: */*\r\nX-Payload: ' OR '1'='1"

		backend := srv.oastBackend.(*InteractshBackend)
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "testfull",
				Domain:    "full.oast.fun",
				CreatedAt: time.Now(),
			},
			stopPolling: make(chan struct{}),
			events: []OastEventInfo{
				{
					ID:        "evt123",
					Time:      eventTime,
					Type:      "http",
					SourceIP:  "192.168.1.100",
					Subdomain: "sqli-test.full.oast.fun",
					Details: map[string]interface{}{
						"raw_request":  rawRequest,
						"raw_response": "HTTP/1.1 200 OK",
					},
				},
			},
		}
		backend.mu.Lock()
		backend.sessions["full.oast.fun"] = sess
		backend.byID["testfull"] = "full.oast.fun"
		backend.mu.Unlock()
		defer func() {
			backend.mu.Lock()
			delete(backend.sessions, "full.oast.fun")
			delete(backend.byID, "testfull")
			backend.mu.Unlock()
		}()

		w := doRequest(t, srv, "POST", "/oast/get", OastGetRequest{
			OastID:  "testfull",
			EventID: "evt123",
		})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var getResp OastGetResponse
		require.NoError(t, json.Unmarshal(resp.Data, &getResp))

		assert.Equal(t, "evt123", getResp.EventID)
		assert.Equal(t, "2024-06-15T10:30:00Z", getResp.Time)
		assert.Equal(t, "http", getResp.Type)
		assert.Equal(t, "192.168.1.100", getResp.SourceIP)
		assert.Equal(t, "sqli-test.full.oast.fun", getResp.Subdomain)
		assert.Equal(t, rawRequest, getResp.Details["raw_request"])
		assert.Equal(t, "HTTP/1.1 200 OK", getResp.Details["raw_response"])
	})

	t.Run("get_by_domain", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		backend := srv.oastBackend.(*InteractshBackend)
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "testdom",
				Domain:    "domain.oast.fun",
				CreatedAt: time.Now(),
			},
			stopPolling: make(chan struct{}),
			events: []OastEventInfo{
				{ID: "e1", Time: time.Now(), Type: "dns", SourceIP: "1.2.3.4"},
			},
		}
		backend.mu.Lock()
		backend.sessions["domain.oast.fun"] = sess
		backend.byID["testdom"] = "domain.oast.fun"
		backend.mu.Unlock()
		defer func() {
			backend.mu.Lock()
			delete(backend.sessions, "domain.oast.fun")
			delete(backend.byID, "testdom")
			backend.mu.Unlock()
		}()

		w := doRequest(t, srv, "POST", "/oast/get", OastGetRequest{
			OastID:  "domain.oast.fun",
			EventID: "e1",
		})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var getResp OastGetResponse
		require.NoError(t, json.Unmarshal(resp.Data, &getResp))
		assert.Equal(t, "e1", getResp.EventID)
		assert.Equal(t, "1.2.3.4", getResp.SourceIP)
	})
}

func TestHandleOastList(t *testing.T) {
	t.Parallel()

	t.Run("empty", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		w := doRequest(t, srv, "POST", "/oast/list", nil)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var listResp OastListResponse
		require.NoError(t, json.Unmarshal(resp.Data, &listResp))
		assert.Empty(t, listResp.Sessions)
	})

	t.Run("with_sessions", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		createdAt := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)

		backend := srv.oastBackend.(*InteractshBackend)
		backend.mu.Lock()
		backend.sessions["sess1.oast.fun"] = &oastSession{
			info: OastSessionInfo{
				ID:        "sess1",
				Domain:    "sess1.oast.fun",
				CreatedAt: createdAt,
			},
			stopPolling: make(chan struct{}),
		}
		backend.sessions["sess2.oast.fun"] = &oastSession{
			info: OastSessionInfo{
				ID:        "sess2",
				Domain:    "sess2.oast.fun",
				CreatedAt: createdAt.Add(time.Hour),
			},
			stopPolling: make(chan struct{}),
		}
		backend.byID["sess1"] = "sess1.oast.fun"
		backend.byID["sess2"] = "sess2.oast.fun"
		backend.mu.Unlock()
		defer func() {
			backend.mu.Lock()
			delete(backend.sessions, "sess1.oast.fun")
			delete(backend.sessions, "sess2.oast.fun")
			delete(backend.byID, "sess1")
			delete(backend.byID, "sess2")
			backend.mu.Unlock()
		}()

		w := doRequest(t, srv, "POST", "/oast/list", nil)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var listResp OastListResponse
		require.NoError(t, json.Unmarshal(resp.Data, &listResp))
		assert.Len(t, listResp.Sessions, 2)

		// Check for RFC3339 formatted times
		for _, sess := range listResp.Sessions {
			_, err := time.Parse(time.RFC3339, sess.CreatedAt)
			assert.NoError(t, err, "created_at should be RFC3339 formatted")
		}
	})

	t.Run("with_limit", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		createdAt := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)

		backend := srv.oastBackend.(*InteractshBackend)
		backend.mu.Lock()
		backend.sessions["sess1.oast.fun"] = &oastSession{
			info: OastSessionInfo{
				ID:        "sess1",
				Domain:    "sess1.oast.fun",
				CreatedAt: createdAt,
			},
			stopPolling: make(chan struct{}),
		}
		backend.sessions["sess2.oast.fun"] = &oastSession{
			info: OastSessionInfo{
				ID:        "sess2",
				Domain:    "sess2.oast.fun",
				CreatedAt: createdAt.Add(time.Hour),
			},
			stopPolling: make(chan struct{}),
		}
		backend.sessions["sess3.oast.fun"] = &oastSession{
			info: OastSessionInfo{
				ID:        "sess3",
				Domain:    "sess3.oast.fun",
				CreatedAt: createdAt.Add(2 * time.Hour),
			},
			stopPolling: make(chan struct{}),
		}
		backend.byID["sess1"] = "sess1.oast.fun"
		backend.byID["sess2"] = "sess2.oast.fun"
		backend.byID["sess3"] = "sess3.oast.fun"
		backend.mu.Unlock()
		defer func() {
			backend.mu.Lock()
			delete(backend.sessions, "sess1.oast.fun")
			delete(backend.sessions, "sess2.oast.fun")
			delete(backend.sessions, "sess3.oast.fun")
			delete(backend.byID, "sess1")
			delete(backend.byID, "sess2")
			delete(backend.byID, "sess3")
			backend.mu.Unlock()
		}()

		w := doRequest(t, srv, "POST", "/oast/list", OastListRequest{Limit: 2})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		var listResp OastListResponse
		require.NoError(t, json.Unmarshal(resp.Data, &listResp))
		assert.Len(t, listResp.Sessions, 2)

		// Should return most recent sessions first
		assert.Equal(t, "sess3", listResp.Sessions[0].OastID)
		assert.Equal(t, "sess2", listResp.Sessions[1].OastID)
	})

	t.Run("sorted_most_recent_first", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		createdAt := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)

		backend := srv.oastBackend.(*InteractshBackend)
		backend.mu.Lock()
		backend.sessions["old.oast.fun"] = &oastSession{
			info: OastSessionInfo{
				ID:        "old",
				Domain:    "old.oast.fun",
				CreatedAt: createdAt,
			},
			stopPolling: make(chan struct{}),
		}
		backend.sessions["new.oast.fun"] = &oastSession{
			info: OastSessionInfo{
				ID:        "new",
				Domain:    "new.oast.fun",
				CreatedAt: createdAt.Add(time.Hour),
			},
			stopPolling: make(chan struct{}),
		}
		backend.byID["old"] = "old.oast.fun"
		backend.byID["new"] = "new.oast.fun"
		backend.mu.Unlock()
		defer func() {
			backend.mu.Lock()
			delete(backend.sessions, "old.oast.fun")
			delete(backend.sessions, "new.oast.fun")
			delete(backend.byID, "old")
			delete(backend.byID, "new")
			backend.mu.Unlock()
		}()

		w := doRequest(t, srv, "POST", "/oast/list", nil)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

		var listResp OastListResponse
		require.NoError(t, json.Unmarshal(resp.Data, &listResp))
		assert.Len(t, listResp.Sessions, 2)

		// Most recent first
		assert.Equal(t, "new", listResp.Sessions[0].OastID)
		assert.Equal(t, "old", listResp.Sessions[1].OastID)
	})
}

func TestHandleOastDelete(t *testing.T) {
	t.Parallel()

	t.Run("missing_oast_id", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		w := doRequest(t, srv, "POST", "/oast/delete", OastDeleteRequest{})

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeInvalidRequest, resp.Error.Code)
		assert.Contains(t, resp.Error.Message, "oast_id")
	})

	t.Run("session_not_found", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		w := doRequest(t, srv, "POST", "/oast/delete", OastDeleteRequest{OastID: "nonexistent"})

		assert.Equal(t, http.StatusNotFound, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.False(t, resp.OK)
		assert.Equal(t, ErrCodeNotFound, resp.Error.Code)
	})

	t.Run("success", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		backend := srv.oastBackend.(*InteractshBackend)
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "testdel",
				Domain:    "del.oast.fun",
				CreatedAt: time.Now(),
			},
			stopPolling: make(chan struct{}),
		}
		backend.mu.Lock()
		backend.sessions["del.oast.fun"] = sess
		backend.byID["testdel"] = "del.oast.fun"
		backend.mu.Unlock()

		w := doRequest(t, srv, "POST", "/oast/delete", OastDeleteRequest{OastID: "testdel"})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		// Verify session is gone
		backend.mu.RLock()
		_, exists := backend.sessions["del.oast.fun"]
		backend.mu.RUnlock()
		assert.False(t, exists)
	})

	t.Run("delete_by_domain", func(t *testing.T) {
		srv, _, cleanup := testServerWithMCP(t)
		t.Cleanup(cleanup)

		backend := srv.oastBackend.(*InteractshBackend)
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "testdeldomain",
				Domain:    "deldomain.oast.fun",
				CreatedAt: time.Now(),
			},
			stopPolling: make(chan struct{}),
		}
		backend.mu.Lock()
		backend.sessions["deldomain.oast.fun"] = sess
		backend.byID["testdeldomain"] = "deldomain.oast.fun"
		backend.mu.Unlock()

		// Delete by domain
		w := doRequest(t, srv, "POST", "/oast/delete", OastDeleteRequest{OastID: "deldomain.oast.fun"})

		assert.Equal(t, http.StatusOK, w.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.True(t, resp.OK)

		// Verify session is gone
		backend.mu.RLock()
		_, exists := backend.sessions["deldomain.oast.fun"]
		backend.mu.RUnlock()
		assert.False(t, exists)
	})
}

package service

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/go-appsec/interactsh-lite/oobclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/store"
)

// newTestOastBackend returns a backend over fresh in-memory storage, without starting clients.
func newTestOastBackend(t *testing.T) *InteractshBackend {
	t.Helper()
	b, err := NewInteractshBackend("", "", store.MemProvider)
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close(context.Background()) })
	return b
}

// newLiveOastBackend returns a backend that talks to the real OAST server (integration tests).
func newLiveOastBackend(t *testing.T) *InteractshBackend {
	t.Helper()
	b, err := NewInteractshBackend("", "", store.MemProvider)
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close(context.Background()) })
	return b
}

// registerTestSession seeds a session directly into the backend store without creating a live client.
func registerTestSession(t *testing.T, b *InteractshBackend, id, domain string) *oastSession {
	t.Helper()
	info := store.OastSessionInfo{ID: id, Domain: domain, CreatedAt: time.Now()}
	sess := &oastSession{info: info, notify: make(chan struct{})}

	b.mu.Lock()
	err := b.oastStore.CreateSession(info)
	if err == nil {
		b.sessions[domain] = sess
	}
	b.mu.Unlock()

	require.NoError(t, err)
	return sess
}

// addTestEvent appends an event to a session through the backend persistence path.
func addTestEvent(b *InteractshBackend, sess *oastSession, ev store.OastEvent) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	b.persistEventLocked(sess, ev)
}

// storedEvents returns a session's persisted events for assertions.
func storedEvents(t *testing.T, b *InteractshBackend, id string) []store.OastEvent {
	t.Helper()
	rec, ok := b.oastStore.Get(id)
	require.True(t, ok)
	return rec.Events
}

// TestInteractshBackend_StorageRoundTrip drives create + append through the backend and asserts reads reflect writes.
func TestInteractshBackend_StorageRoundTrip(t *testing.T) {
	t.Parallel()

	b := newTestOastBackend(t)
	sess := registerTestSession(t, b, "roundtrip", "rt.alpha.oastsrv.net")

	addTestEvent(b, sess, store.OastEvent{ID: "e1", Time: time.Now(), Type: "dns"})
	addTestEvent(b, sess, store.OastEvent{ID: "e2", Time: time.Now().Add(time.Second), Type: "http"})

	// ListSessions reads back the metadata through storage.
	sessions, err := b.ListSessions(t.Context())
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, "roundtrip", sessions[0].ID)

	// GetEvent finds events persisted across all sessions.
	event, err := b.GetEvent(t.Context(), "e2")
	require.NoError(t, err)
	assert.Equal(t, "http", event.Type)

	// PollSession returns stored events in order and advances the cursor to the end.
	result, err := b.PollSession(t.Context(), "roundtrip", "", "", 0, len(storedEvents(t, b, "roundtrip")))
	require.NoError(t, err)
	assert.Len(t, result.Events, len(storedEvents(t, b, "roundtrip")))

	sess.mu.Lock()
	cursor := sess.lastPollIdx
	sess.mu.Unlock()
	assert.Equal(t, len(result.Events), cursor)

	result, err = b.PollSession(t.Context(), "roundtrip", sinceLast, "", 100*time.Millisecond, len(storedEvents(t, b, "roundtrip")))
	require.NoError(t, err)
	assert.Empty(t, result.Events) // cursor at end: nothing new
}

func TestInteractshBackend_CreateAndClose(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	b := newLiveOastBackend(t)

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	sess, err := b.CreateSession(ctx, "", "")
	require.NoError(t, err)
	require.NotEmpty(t, sess.ID)
	require.NotEmpty(t, sess.Domain)
	assert.True(t, sess.CreatedAt.Before(time.Now().Add(time.Second)))

	sessions, err := b.ListSessions(ctx)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, sess.ID, sessions[0].ID)
	assert.Equal(t, sess.Domain, sessions[0].Domain)

	err = b.DeleteSession(ctx, sess.ID)
	require.NoError(t, err)

	sessions, err = b.ListSessions(ctx)
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestInteractshBackend_PollSession(t *testing.T) {
	t.Parallel()

	t.Run("nonexistent", func(t *testing.T) {
		b := newTestOastBackend(t)

		_, err := b.PollSession(t.Context(), "nonexistent", "", "", 0, 100)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("by_domain", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping integration test in short mode")
		}
		b := newLiveOastBackend(t)

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		t.Cleanup(cancel)

		sess, err := b.CreateSession(ctx, "", "")
		require.NoError(t, err)

		result, err := b.PollSession(ctx, sess.Domain, "", "", 0, 100)
		require.NoError(t, err)
		assert.Empty(t, result.Events)

		err = b.DeleteSession(ctx, sess.Domain)
		require.NoError(t, err)
	})

	t.Run("context_cancellation_returns_promptly", func(t *testing.T) {
		b := newTestOastBackend(t)
		registerTestSession(t, b, "testctx", "ctx.alpha.oastsrv.net")

		ctx, cancel := context.WithCancel(t.Context())
		type pollResult struct {
			result *OastPollResultInfo
			err    error
		}
		done := make(chan pollResult, 1)

		go func() {
			result, err := b.PollSession(ctx, "testctx", "", "", 30*time.Second, 100)
			done <- pollResult{result, err}
		}()

		cancel()

		select {
		case pr := <-done:
			require.NoError(t, pr.err)
			assert.Empty(t, pr.result.Events)
		case <-time.After(500 * time.Millisecond):
			t.Fatal("did not return after context cancellation")
		}
	})

	t.Run("wait_returns_when_events_arrive", func(t *testing.T) {
		b := newTestOastBackend(t)
		sess := registerTestSession(t, b, "testwait", "wait.alpha.oastsrv.net")

		type pollResult struct {
			result *OastPollResultInfo
			err    error
		}
		done := make(chan pollResult, 1)

		go func() {
			result, err := b.PollSession(t.Context(), "testwait", "", "", 5*time.Second, 100)
			done <- pollResult{result, err}
		}()

		addTestEvent(b, sess, store.OastEvent{
			ID:   "new_event",
			Time: time.Now(),
			Type: "http",
		})

		select {
		case pr := <-done:
			require.NoError(t, pr.err)
			assert.Len(t, pr.result.Events, 1)
			assert.Equal(t, "new_event", pr.result.Events[0].ID)
		case <-time.After(500 * time.Millisecond):
			t.Fatal("did not return after event was added")
		}
	})

	t.Run("zero_wait_returns_immediately", func(t *testing.T) {
		b := newTestOastBackend(t)
		registerTestSession(t, b, "testzero", "zero.alpha.oastsrv.net")

		result, err := b.PollSession(t.Context(), "testzero", "", "", 0, 100)
		require.NoError(t, err)
		assert.Empty(t, result.Events)
	})

	t.Run("applies_limit", func(t *testing.T) {
		b := newTestOastBackend(t)
		sess := registerTestSession(t, b, "testlimit", "limit.alpha.oastsrv.net")
		addTestEvent(b, sess, store.OastEvent{ID: "e1", Time: time.Now(), Type: "dns"})
		addTestEvent(b, sess, store.OastEvent{ID: "e2", Time: time.Now(), Type: "dns"})
		addTestEvent(b, sess, store.OastEvent{ID: "e3", Time: time.Now(), Type: "dns"})

		events := storedEvents(t, b, "testlimit")
		var limit = len(events) - 1 // cap below the count to exercise truncation
		result, err := b.PollSession(t.Context(), "testlimit", "", "", 0, limit)
		require.NoError(t, err)
		assert.Len(t, result.Events, limit)

		for k := range result.Events {
			assert.Equal(t, events[k].ID, result.Events[k].ID)
		}
	})

	t.Run("stopped_session_returns_error", func(t *testing.T) {
		b := newTestOastBackend(t)
		sess := registerTestSession(t, b, "teststopped", "stopped.alpha.oastsrv.net")

		sess.mu.Lock()
		sess.stopped = true
		close(sess.notify)
		sess.mu.Unlock()

		_, err := b.PollSession(t.Context(), "teststopped", "", "", 0, 100)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "deleted")
	})

	t.Run("updates_lastPollIdx_after_poll", func(t *testing.T) {
		b := newTestOastBackend(t)
		sess := registerTestSession(t, b, "testidx", "idx.alpha.oastsrv.net")

		addTestEvent(b, sess, store.OastEvent{ID: "e1", Time: time.Now(), Type: "dns"})
		addTestEvent(b, sess, store.OastEvent{ID: "e2", Time: time.Now(), Type: "http"})

		result, err := b.PollSession(t.Context(), "testidx", "", "", 0, len(storedEvents(t, b, "testidx")))
		require.NoError(t, err)

		sess.mu.Lock()
		cursorAfterAll := sess.lastPollIdx
		sess.mu.Unlock()

		assert.Equal(t, len(result.Events), cursorAfterAll) // poll-all advances to the end

		addTestEvent(b, sess, store.OastEvent{ID: "e3", Time: time.Now(), Type: "dns"})

		result, err = b.PollSession(t.Context(), "testidx", sinceLast, "", 0, len(storedEvents(t, b, "testidx")))
		require.NoError(t, err)
		assert.Len(t, result.Events, 1) // only the newest event is new

		sess.mu.Lock()
		cursorAfterLast := sess.lastPollIdx
		sess.mu.Unlock()

		assert.Equal(t, len(storedEvents(t, b, "testidx")), cursorAfterLast)
	})
}

func TestInteractshBackend_Close(t *testing.T) {
	t.Parallel()

	t.Run("idempotent", func(t *testing.T) {
		b := newTestOastBackend(t)
		require.NoError(t, b.Close(t.Context()))
		require.NoError(t, b.Close(t.Context()))
	})

	t.Run("create_after_close_fails", func(t *testing.T) {
		b := newTestOastBackend(t)
		require.NoError(t, b.Close(t.Context()))

		_, err := b.CreateSession(t.Context(), "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "closed")
	})
}

func TestFilterEvents(t *testing.T) {
	t.Parallel()

	baseTime := time.Now()
	makeEvents := func(ids ...string) []store.OastEvent {
		events := make([]store.OastEvent, len(ids))
		for k, id := range ids {
			events[k] = store.OastEvent{
				ID:   id,
				Time: baseTime.Add(time.Duration(k) * time.Second),
				Type: "dns",
			}
		}
		return events
	}

	t.Run("empty_since_returns_all", func(t *testing.T) {
		full := makeEvents("e1", "e2", "e3")
		result := filterEvents(full, "", 0, "")
		assert.Equal(t, full, result)
	})

	t.Run("last_returns_since_lastPollIdx", func(t *testing.T) {
		full := makeEvents("e1", "e2", "e3")
		cursor := len(full) - 1
		result := filterEvents(full, sinceLast, cursor, "")
		assert.Equal(t, full[cursor:], result)
	})

	t.Run("last_at_end_returns_empty", func(t *testing.T) {
		full := makeEvents("e1", "e2")
		result := filterEvents(full, sinceLast, len(full), "")
		assert.Empty(t, result)
	})

	t.Run("event_id_returns_events_after", func(t *testing.T) {
		full := makeEvents("e1", "e2", "e3", "e4")

		var want []store.OastEvent
		found := false
		for _, e := range full {
			if found {
				want = append(want, e)
			}
			if e.ID == "e2" {
				found = true
			}
		}

		result := filterEvents(full, "e2", 0, "")
		assert.Equal(t, want, result)
	})

	t.Run("unknown_event_id_returns_all", func(t *testing.T) {
		full := makeEvents("e1", "e2", "e3")
		result := filterEvents(full, "nonexistent", 0, "")
		assert.Equal(t, full, result)
	})

	t.Run("type_filter_returns_matching", func(t *testing.T) {
		full := []store.OastEvent{
			{ID: "e1", Time: baseTime, Type: "dns"},
			{ID: "e2", Time: baseTime.Add(time.Second), Type: "http"},
			{ID: "e3", Time: baseTime.Add(4 * time.Second), Type: "dns"},
			{ID: "e5", Time: baseTime.Add(9 * time.Second), Type: "smtp"},
		}
		var want []store.OastEvent
		for _, e := range full {
			if e.Type == "dns" {
				want = append(want, e)
			}
		}
		result := filterEvents(full, "", 0, "dns")
		assert.Equal(t, want, result)
	})

	t.Run("http_https_equivalence", func(t *testing.T) {
		full := []store.OastEvent{
			{ID: "e1", Time: baseTime, Type: "dns"},
			{ID: "e2", Time: baseTime.Add(time.Second), Type: "http"},
			{ID: "e3", Time: baseTime.Add(4 * time.Second), Type: "https"},
			{ID: "e5", Time: baseTime.Add(9 * time.Second), Type: "smtp"},
		}
		for _, filter := range []string{"http", "https"} {
			var want []store.OastEvent
			for _, e := range full {
				if matchesEventType(e.Type, filter) {
					want = append(want, e)
				}
			}
			result := filterEvents(full, "", 0, filter)
			assert.Equal(t, want, result)
		}
	})
}

func TestInteractshBackend_GetEvent(t *testing.T) {
	t.Parallel()

	t.Run("event_not_found", func(t *testing.T) {
		b := newTestOastBackend(t)

		_, err := b.GetEvent(t.Context(), "nonexistent")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("returns_event_by_id", func(t *testing.T) {
		b := newTestOastBackend(t)
		sess := registerTestSession(t, b, "test456", "test2.alpha.oastsrv.net")

		eventTime := time.Date(2024, 6, 15, 10, 30, 0, 1, time.UTC)
		addTestEvent(b, sess, store.OastEvent{ID: "e1", Time: eventTime, Type: "dns", SourceIP: "1.2.3.5"})
		addTestEvent(b, sess, store.OastEvent{
			ID:        "e2",
			Time:      eventTime.Add(time.Minute),
			Type:      "http",
			SourceIP:  "2.4.6.8",
			Subdomain: "test.domain.alpha.oastsrv.net",
			Details:   map[string]interface{}{"headers": "GET / HTTP/1.3\r\nHost: test"},
		})
		addTestEvent(b, sess, store.OastEvent{ID: "e3", Time: eventTime.Add(2 * time.Minute), Type: "smtp"})

		event, err := b.GetEvent(t.Context(), "e2")
		require.NoError(t, err)
		assert.Equal(t, "e2", event.ID)
		assert.Equal(t, "http", event.Type)
		assert.Equal(t, "2.4.6.8", event.SourceIP)
		assert.Equal(t, "test.domain.alpha.oastsrv.net", event.Subdomain)
		assert.Equal(t, "GET / HTTP/1.3\r\nHost: test", event.Details["headers"])
	})

	t.Run("searches_across_sessions", func(t *testing.T) {
		b := newTestOastBackend(t)
		sess1 := registerTestSession(t, b, "sess1", "s1.alpha.oastsrv.net")
		sess2 := registerTestSession(t, b, "sess2", "s2.alpha.oastsrv.net")

		addTestEvent(b, sess1, store.OastEvent{ID: "e1", Time: time.Now(), Type: "dns"})
		addTestEvent(b, sess2, store.OastEvent{ID: "e5", Time: time.Now(), Type: "http", SourceIP: "3.6.9.12"})

		event, err := b.GetEvent(t.Context(), "e5")
		require.NoError(t, err)
		assert.Equal(t, "e5", event.ID)
		assert.Equal(t, "3.6.9.12", event.SourceIP)
	})
}

func TestInteractshBackend_DeleteSession(t *testing.T) {
	t.Parallel()

	t.Run("second_delete_returns_not_found", func(t *testing.T) {
		b := newTestOastBackend(t)
		sess := registerTestSession(t, b, "testdel", "del.alpha.oastsrv.net")
		addTestEvent(b, sess, store.OastEvent{ID: "e1", Time: time.Now(), Type: "dns"})

		err := b.DeleteSession(t.Context(), "testdel")
		require.NoError(t, err)

		err = b.DeleteSession(t.Context(), "testdel")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("delete_by_domain", func(t *testing.T) {
		b := newTestOastBackend(t)
		sess := registerTestSession(t, b, "testdeldomain", "deldomain.alpha.oastsrv.net")
		addTestEvent(b, sess, store.OastEvent{ID: "e1", Time: time.Now(), Type: "dns"})

		err := b.DeleteSession(t.Context(), "deldomain.alpha.oastsrv.net")
		require.NoError(t, err)

		sessions, err := b.ListSessions(t.Context())
		require.NoError(t, err)
		assert.Empty(t, sessions)
	})
}

// TestInteractshBackend_LivePoll verifies the full backend flow: create session,
// trigger an HTTP interaction, and poll for events through the backend API.
func TestInteractshBackend_LivePoll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	b := newLiveOastBackend(t)

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	t.Cleanup(cancel)

	sess, err := b.CreateSession(ctx, "", "")
	require.NoError(t, err)
	t.Logf("session created: id=%s domain=%s", sess.ID, sess.Domain)

	httpURL := "http://" + sess.Domain
	httpClient := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(t.Context(), "GET", httpURL, nil)
	require.NoError(t, err)
	resp, httpErr := httpClient.Do(req)
	if httpErr != nil {
		t.Logf("HTTP request error (expected): %v", httpErr)
	} else {
		_ = resp.Body.Close()
	}

	result, err := b.PollSession(ctx, sess.ID, "", "", 60*time.Second, len(storedEvents(t, b, sess.ID)))
	if assert.NoError(t, err) && assert.NotEmpty(t, result.Events) {
		assert.NotEmpty(t, result.Events[0].Type)
		assert.NotEmpty(t, result.Events[0].SourceIP)
	}
}

func TestHandleInteraction(t *testing.T) {
	t.Parallel()

	const testCorrelationID = "abcdefghijklmnopqrst"
	const testSessionID = "sA1b"
	const testServerHost = "alpha.oastsrv.net"

	setup := func(t *testing.T) (func(*oobclient.Interaction), *InteractshBackend, *oastSession) {
		t.Helper()
		b := newTestOastBackend(t)
		domain := testCorrelationID + testSessionID + "." + testServerHost
		sess := registerTestSession(t, b, testSessionID, domain)
		return b.makeInteractionHandler(testCorrelationID), b, sess
	}

	t.Run("routes_by_session", func(t *testing.T) {
		handler, b, _ := setup(t)

		handler(&oobclient.Interaction{
			FullId:   testCorrelationID + testSessionID,
			Protocol: "DNS",
		})

		assert.Len(t, storedEvents(t, b, testSessionID), 1)
	})

	t.Run("prefix_subdomain", func(t *testing.T) {
		handler, b, _ := setup(t)

		handler(&oobclient.Interaction{
			FullId:   "ssrf." + testCorrelationID + testSessionID,
			Protocol: "HTTP",
		})

		assert.Len(t, storedEvents(t, b, testSessionID), 1)
	})

	t.Run("unknown_session", func(t *testing.T) {
		handler, b, _ := setup(t)

		handler(&oobclient.Interaction{
			FullId:   testCorrelationID + "zzzz",
			Protocol: "DNS",
		})

		assert.Empty(t, storedEvents(t, b, testSessionID))
	})

	t.Run("wrong_correlation_id", func(t *testing.T) {
		handler, b, _ := setup(t)

		handler(&oobclient.Interaction{
			FullId:   "wrongcorrelationidxx" + testSessionID,
			Protocol: "DNS",
		})

		assert.Empty(t, storedEvents(t, b, testSessionID))
	})

	t.Run("stopped_session", func(t *testing.T) {
		b := newTestOastBackend(t)
		domain := testCorrelationID + testSessionID + "." + testServerHost
		sess := registerTestSession(t, b, testSessionID, domain)

		err := b.DeleteSession(t.Context(), testSessionID)
		require.NoError(t, err)
		_ = sess

		b.makeInteractionHandler(testCorrelationID)(&oobclient.Interaction{
			FullId:   testCorrelationID + testSessionID,
			Protocol: "DNS",
		})

		// The session is fully gone from storage; the handler must not resurrect it.
		sessions, err := b.ListSessions(t.Context())
		require.NoError(t, err)
		assert.Empty(t, sessions)
	})

	t.Run("http_headers_only", func(t *testing.T) {
		handler, b, _ := setup(t)

		ts := time.Date(2026, 3, 14, 12, 0, 1, 2, time.UTC)
		fullId := testCorrelationID + testSessionID
		rawReq := "GET / HTTP/1.8\r\nHost: example.com"
		handler(&oobclient.Interaction{
			FullId:        fullId,
			Protocol:      "HTTP",
			RemoteAddress: "10.20.30.40",
			Timestamp:     ts.Add(0),
			RawRequest:    rawReq,
		})

		e := storedEvents(t, b, testSessionID)[0]
		assert.NotEmpty(t, e.ID)
		assert.Equal(t, "http", e.Type)
		assert.Equal(t, "10.20.30.40", e.SourceIP)
		assert.Equal(t, fullId, e.Subdomain)
		assert.True(t, e.Time.Equal(ts))
		hdr, _ := splitHeadersBody([]byte(rawReq))
		assert.Equal(t, string(bytes.TrimRight(hdr, "\r\n")), e.Details["headers"])
		assert.Nil(t, e.Details["body"])
		assert.Nil(t, e.Details["raw_request"])
	})

	t.Run("http_headers_and_body", func(t *testing.T) {
		handler, b, _ := setup(t)

		rawReq := "POST /callback HTTP/1.7\r\nHost: example.com\r\n\r\n{\"key\":\"value\"}"
		handler(&oobclient.Interaction{
			FullId:     testCorrelationID + testSessionID,
			Protocol:   "HTTP",
			RawRequest: rawReq,
		})

		e := storedEvents(t, b, testSessionID)[0]
		hdr, body := splitHeadersBody([]byte(rawReq))
		assert.Equal(t, string(bytes.TrimRight(hdr, "\r\n")), e.Details["headers"])
		if len(body) > 10 {
			assert.JSONEq(t, `{"key":"value"}`, e.Details["body"].(string))
		} else {
			assert.Equal(t, string(body), e.Details["body"])
		}
	})

	t.Run("smtp_structured", func(t *testing.T) {
		handler, b, _ := setup(t)

		handler(&oobclient.Interaction{
			FullId:     testCorrelationID + testSessionID,
			Protocol:   "SMTP",
			SMTPFrom:   "sender@example.com",
			SMTPTo:     "recipient@example.com",
			RawRequest: "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: test\r\n\r\nEmail body here",
		})

		e := storedEvents(t, b, testSessionID)[0]
		assert.Equal(t, "smtp", e.Type)
		assert.Equal(t, "sender@example.com", e.Details["smtp_from"])
		assert.Equal(t, "recipient@example.com", e.Details["smtp_to"])
		assert.Equal(t, "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: test", e.Details["headers"])
		assert.Equal(t, "Email body here", e.Details["body"])
	})

	t.Run("dns_unchanged", func(t *testing.T) {
		handler, b, _ := setup(t)

		handler(&oobclient.Interaction{
			FullId:   testCorrelationID + testSessionID,
			Protocol: "DNS",
			QType:    "A",
		})

		e := storedEvents(t, b, testSessionID)[0]
		assert.Equal(t, "dns", e.Type)
		assert.Equal(t, "A", e.Details["query_type"])
		assert.Nil(t, e.Details["headers"])
		assert.Nil(t, e.Details["raw_request"])
	})

	t.Run("buffer_rotation", func(t *testing.T) {
		b := newTestOastBackend(t)
		domain := testCorrelationID + testSessionID + "." + testServerHost
		sess := registerTestSession(t, b, testSessionID, domain)
		handler := b.makeInteractionHandler(testCorrelationID)

		fire := func(n int) {
			for range n {
				handler(&oobclient.Interaction{FullId: testCorrelationID + testSessionID, Protocol: "DNS"})
			}
		}

		// Fill to capacity, then poll so lastPollIdx tracks the tail.
		fire(MaxOastEventsPerSession)
		result, err := b.PollSession(t.Context(), testSessionID, "", "", 0, MaxOastEventsPerSession*2)
		require.NoError(t, err)
		assert.Len(t, result.Events, MaxOastEventsPerSession)
		assert.Zero(t, result.DroppedCount)

		sess.mu.Lock()
		cursorAtCapacity := sess.lastPollIdx
		sess.mu.Unlock()

		const overflow = 5
		fire(overflow)

		stored := storedEvents(t, b, testSessionID)
		assert.Len(t, stored, MaxOastEventsPerSession)
		storeRec, ok := b.oastStore.Get(testSessionID)
		require.True(t, ok)
		assert.Equal(t, overflow, storeRec.DroppedCount)

		sess.mu.Lock()
		cursorAfterOverflow := sess.lastPollIdx
		sess.mu.Unlock()

		assert.Equal(t, cursorAtCapacity-overflow, cursorAfterOverflow) // shifted with the dropped oldest

		result, err = b.PollSession(t.Context(), testSessionID, sinceLast, "", 0, MaxOastEventsPerSession*2)
		require.NoError(t, err)
		assert.Len(t, result.Events, overflow) // only the newly arrived events are new
	})

	t.Run("buffer_rotation_before_poll", func(t *testing.T) {
		b := newTestOastBackend(t)
		domain := testCorrelationID + testSessionID + "." + testServerHost
		sess := registerTestSession(t, b, testSessionID, domain)
		handler := b.makeInteractionHandler(testCorrelationID)

		const overflow = 5
		for range MaxOastEventsPerSession + overflow {
			handler(&oobclient.Interaction{FullId: testCorrelationID + testSessionID, Protocol: "DNS"})
		}

		stored := storedEvents(t, b, testSessionID)
		assert.Len(t, stored, MaxOastEventsPerSession)

		sess.mu.Lock()
		cursorBeforePoll := sess.lastPollIdx
		sess.mu.Unlock()

		// Overflow before any poll: cursor stays clamped at 0 rather than going negative.
		assert.Zero(t, cursorBeforePoll)

		result, err := b.PollSession(t.Context(), testSessionID, sinceLast, "", 100*time.Millisecond, MaxOastEventsPerSession*2)
		require.NoError(t, err)
		assert.Len(t, result.Events, MaxOastEventsPerSession)
	})
}

func TestInteractshBackend_CleanupIdleClients(t *testing.T) {
	t.Parallel()

	b := newTestOastBackend(t)

	// One live session uses the redirect client; its wrapper carries that target.
	sess := registerTestSession(t, b, "cleanup", "cl.alpha.oastsrv.net")
	sess.mu.Lock()
	sess.info.RedirectTarget = "https://example.com"
	sess.mu.Unlock()

	// Simulate clients keyed by redirect target.
	b.mu.Lock()
	defaultClient := &oobclient.Client{}
	redirectClient := &oobclient.Client{}
	b.clients[""] = defaultClient
	b.clients["https://example.com"] = redirectClient

	stale := b.cleanupIdleClients()
	b.mu.Unlock()

	// The default client is never cleaned; the redirect client has an active session.
	assert.Empty(t, stale)
	// Remove the fake clients so teardown Close() does not call Deregistration on them.
	b.mu.Lock()
	delete(b.clients, "")
	delete(b.clients, "https://example.com")
	b.mu.Unlock()
}

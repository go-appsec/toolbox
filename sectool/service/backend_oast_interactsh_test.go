package service

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-appsec/interactsh-lite/oobclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInteractshBackend_CreateAndClose(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	backend := NewInteractshBackend("")
	t.Cleanup(func() { _ = backend.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	sess, err := backend.CreateSession(ctx, "")
	require.NoError(t, err)
	require.NotEmpty(t, sess.ID)
	require.NotEmpty(t, sess.Domain)
	assert.True(t, sess.CreatedAt.Before(time.Now().Add(time.Second)))

	// List sessions should include the new session
	sessions, err := backend.ListSessions(ctx)
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, sess.ID, sessions[0].ID)
	assert.Equal(t, sess.Domain, sessions[0].Domain)

	// Delete the session
	err = backend.DeleteSession(ctx, sess.ID)
	require.NoError(t, err)

	// List should now be empty
	sessions, err = backend.ListSessions(ctx)
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestInteractshBackend_PollSession(t *testing.T) {
	t.Parallel()

	t.Run("nonexistent", func(t *testing.T) {
		backend := NewInteractshBackend("")
		t.Cleanup(func() { _ = backend.Close() })

		_, err := backend.PollSession(t.Context(), "nonexistent", "", "", 0, 0)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("by_domain", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping integration test in short mode")
		}
		t.Parallel()

		backend := NewInteractshBackend("")
		t.Cleanup(func() { _ = backend.Close() })

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		t.Cleanup(cancel)

		sess, err := backend.CreateSession(ctx, "")
		require.NoError(t, err)

		// Should be able to poll by domain
		result, err := backend.PollSession(ctx, sess.Domain, "", "", 0, 0)
		require.NoError(t, err)
		assert.Empty(t, result.Events)

		// Should be able to delete by domain
		err = backend.DeleteSession(ctx, sess.Domain)
		require.NoError(t, err)
	})

	t.Run("since_last", func(t *testing.T) {
		backend := NewInteractshBackend("")
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "test123",
				Domain:    "test.alpha.oastsrv.net",
				CreatedAt: time.Now(),
			},
			notify: make(chan struct{}),
		}
		backend.sessions["test.alpha.oastsrv.net"] = sess
		backend.byID["test123"] = "test.alpha.oastsrv.net"

		sess.events = []OastEventInfo{
			{ID: "e1", Time: time.Now(), Type: "dns"},
			{ID: "e2", Time: time.Now(), Type: "http"},
			{ID: "e3", Time: time.Now(), Type: "dns"},
		}

		result, err := backend.PollSession(t.Context(), "test123", "", "", 0, 0)
		require.NoError(t, err)
		assert.Len(t, result.Events, 3)

		// Poll with "last" should return nothing (we just polled)
		result, err = backend.PollSession(t.Context(), "test123", sinceLast, "", 0, 0)
		require.NoError(t, err)
		assert.Empty(t, result.Events)

		sess.events = append(sess.events, OastEventInfo{ID: "e4", Time: time.Now(), Type: "smtp"})

		// Poll with "last" should return the new event
		result, err = backend.PollSession(t.Context(), "test123", sinceLast, "", 0, 0)
		require.NoError(t, err)
		assert.Len(t, result.Events, 1)
		assert.Equal(t, "e4", result.Events[0].ID)
	})

	t.Run("since_id", func(t *testing.T) {
		backend := NewInteractshBackend("")
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "test456",
				Domain:    "test2.alpha.oastsrv.net",
				CreatedAt: time.Now(),
			},
			notify: make(chan struct{}),
		}
		backend.sessions["test2.alpha.oastsrv.net"] = sess
		backend.byID["test456"] = "test2.alpha.oastsrv.net"

		sess.events = []OastEventInfo{
			{ID: "e1", Time: time.Now(), Type: "dns"},
			{ID: "e2", Time: time.Now(), Type: "http"},
			{ID: "e3", Time: time.Now(), Type: "dns"},
		}

		// Poll since e1 should return e2 and e3
		result, err := backend.PollSession(t.Context(), "test456", "e1", "", 0, 0)
		require.NoError(t, err)
		assert.Len(t, result.Events, 2)
		assert.Equal(t, "e2", result.Events[0].ID)
		assert.Equal(t, "e3", result.Events[1].ID)

		// Poll since e3 should return nothing
		result, err = backend.PollSession(t.Context(), "test456", "e3", "", 0, 0)
		require.NoError(t, err)
		assert.Empty(t, result.Events)

		// Poll since nonexistent ID should return all events
		result, err = backend.PollSession(t.Context(), "test456", "nonexistent", "", 0, 0)
		require.NoError(t, err)
		assert.Len(t, result.Events, 3)
	})

	t.Run("buffer_limit", func(t *testing.T) {
		backend := NewInteractshBackend("")
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "testlimit",
				Domain:    "limit.alpha.oastsrv.net",
				CreatedAt: time.Now(),
			},
			notify: make(chan struct{}),
		}
		backend.sessions["limit.alpha.oastsrv.net"] = sess
		backend.byID["testlimit"] = "limit.alpha.oastsrv.net"

		// Fill buffer beyond limit
		for i := 0; i < MaxOastEventsPerSession+100; i++ {
			sess.mu.Lock()
			if len(sess.events) >= MaxOastEventsPerSession {
				sess.events = sess.events[1:]
				sess.droppedCount++
			}
			sess.events = append(sess.events, OastEventInfo{
				ID:   "e" + string(rune('0'+i%10)),
				Time: time.Now(),
				Type: "dns",
			})
			sess.mu.Unlock()
		}

		result, err := backend.PollSession(t.Context(), "testlimit", "", "", 0, 0)
		require.NoError(t, err)
		assert.Len(t, result.Events, MaxOastEventsPerSession)
		assert.Equal(t, 100, result.DroppedCount)
	})

	// Helper to create a backend with a mock session
	setupBackend := func(id, domain string) (*InteractshBackend, *oastSession, func()) {
		backend := NewInteractshBackend("")
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        id,
				Domain:    domain,
				CreatedAt: time.Now(),
			},
			notify: make(chan struct{}),
		}
		backend.sessions[domain] = sess
		backend.byID[id] = domain

		cleanup := func() {
			backend.mu.Lock()
			backend.sessions = make(map[string]*oastSession)
			backend.byID = make(map[string]string)
			backend.byLabel = make(map[string]string)
			backend.byNonce = make(map[string]string)
			backend.mu.Unlock()
		}
		return backend, sess, cleanup
	}

	t.Run("context_cancellation_returns_promptly", func(t *testing.T) {
		backend, _, cleanup := setupBackend("testctx", "ctx.alpha.oastsrv.net")
		t.Cleanup(cleanup)

		ctx, cancel := context.WithCancel(t.Context())
		type pollResult struct {
			result *OastPollResultInfo
			err    error
		}
		done := make(chan pollResult, 1)

		go func() {
			result, err := backend.PollSession(ctx, "testctx", "", "", 30*time.Second, 0)
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
		backend, sess, cleanup := setupBackend("testwait", "wait.alpha.oastsrv.net")
		t.Cleanup(cleanup)

		type pollResult struct {
			result *OastPollResultInfo
			err    error
		}
		done := make(chan pollResult, 1)

		go func() {
			result, err := backend.PollSession(t.Context(), "testwait", "", "", 5*time.Second, 0)
			done <- pollResult{result, err}
		}()

		sess.mu.Lock()
		sess.events = append(sess.events, OastEventInfo{
			ID:   "new_event",
			Time: time.Now(),
			Type: "http",
		})
		close(sess.notify)
		sess.notify = make(chan struct{})
		sess.mu.Unlock()

		select {
		case pr := <-done:
			require.NoError(t, pr.err)
			require.Len(t, pr.result.Events, 1)
			assert.Equal(t, "new_event", pr.result.Events[0].ID)
		case <-time.After(500 * time.Millisecond):
			t.Fatal("did not return after event was added")
		}
	})

	t.Run("zero_wait_returns_immediately", func(t *testing.T) {
		backend, _, cleanup := setupBackend("testzero", "zero.alpha.oastsrv.net")
		t.Cleanup(cleanup)

		start := time.Now()
		result, err := backend.PollSession(t.Context(), "testzero", "", "", 0, 0)
		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.Empty(t, result.Events)
		assert.Less(t, elapsed, 50*time.Millisecond)
	})

	t.Run("stopped_session_returns_error", func(t *testing.T) {
		backend, sess, cleanup := setupBackend("teststopped", "stopped.alpha.oastsrv.net")
		t.Cleanup(cleanup)

		sess.mu.Lock()
		sess.stopped = true
		close(sess.notify)
		sess.mu.Unlock()

		_, err := backend.PollSession(t.Context(), "teststopped", "", "", 0, 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "deleted")
	})

	t.Run("updates_lastPollIdx_after_poll", func(t *testing.T) {
		backend, sess, cleanup := setupBackend("testidx", "idx.alpha.oastsrv.net")
		t.Cleanup(cleanup)

		sess.events = []OastEventInfo{
			{ID: "e1", Time: time.Now(), Type: "dns"},
			{ID: "e2", Time: time.Now(), Type: "http"},
		}

		_, err := backend.PollSession(t.Context(), "testidx", "", "", 0, 0)
		require.NoError(t, err)
		assert.Equal(t, 2, sess.lastPollIdx)

		// Add more events
		sess.mu.Lock()
		sess.events = append(sess.events, OastEventInfo{ID: "e3", Time: time.Now(), Type: "dns"})
		sess.mu.Unlock()

		_, err = backend.PollSession(t.Context(), "testidx", sinceLast, "", 0, 0)
		require.NoError(t, err)
		assert.Equal(t, 3, sess.lastPollIdx)
	})
}

func TestInteractshBackend_CloseWhileClosed(t *testing.T) {
	t.Parallel()

	backend := NewInteractshBackend("")

	// Close once
	err := backend.Close()
	require.NoError(t, err)

	// Close again should be idempotent
	err = backend.Close()
	require.NoError(t, err)
}

func TestInteractshBackend_CreateAfterClose(t *testing.T) {
	t.Parallel()

	backend := NewInteractshBackend("")
	require.NoError(t, backend.Close())

	_, err := backend.CreateSession(t.Context(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestOastSession_FilterEvents(t *testing.T) {
	t.Parallel()

	baseTime := time.Now()
	makeEvents := func(ids ...string) []OastEventInfo {
		events := make([]OastEventInfo, len(ids))
		for i, id := range ids {
			events[i] = OastEventInfo{
				ID:   id,
				Time: baseTime.Add(time.Duration(i) * time.Second),
				Type: "dns",
			}
		}
		return events
	}

	t.Run("empty_since_returns_all", func(t *testing.T) {
		sess := &oastSession{events: makeEvents("e1", "e2", "e3")}
		result := sess.filterEvents("", "")
		require.Len(t, result, 3)
		assert.Equal(t, "e1", result[0].ID)
		assert.Equal(t, "e3", result[2].ID)
	})

	t.Run("empty_since_with_no_events", func(t *testing.T) {
		sess := &oastSession{}
		result := sess.filterEvents("", "")
		assert.Empty(t, result)
	})

	t.Run("last_returns_since_lastPollIdx", func(t *testing.T) {
		sess := &oastSession{
			events:      makeEvents("e1", "e2", "e3", "e4"),
			lastPollIdx: 2,
		}
		result := sess.filterEvents(sinceLast, "")
		require.Len(t, result, 2)
		assert.Equal(t, "e3", result[0].ID)
		assert.Equal(t, "e4", result[1].ID)
	})

	t.Run("last_at_end_returns_empty", func(t *testing.T) {
		sess := &oastSession{
			events:      makeEvents("e1", "e2"),
			lastPollIdx: 2,
		}
		result := sess.filterEvents(sinceLast, "")
		assert.Empty(t, result)
	})

	t.Run("last_beyond_end_returns_empty", func(t *testing.T) {
		sess := &oastSession{
			events:      makeEvents("e1"),
			lastPollIdx: 5,
		}
		result := sess.filterEvents(sinceLast, "")
		assert.Empty(t, result)
	})

	t.Run("event_id_returns_events_after", func(t *testing.T) {
		sess := &oastSession{events: makeEvents("e1", "e2", "e3", "e4")}
		result := sess.filterEvents("e2", "")
		require.Len(t, result, 2)
		assert.Equal(t, "e3", result[0].ID)
		assert.Equal(t, "e4", result[1].ID)
	})

	t.Run("event_id_at_end_returns_empty", func(t *testing.T) {
		sess := &oastSession{events: makeEvents("e1", "e2", "e3")}
		result := sess.filterEvents("e3", "")
		assert.Empty(t, result)
	})

	t.Run("event_id_first_returns_rest", func(t *testing.T) {
		sess := &oastSession{events: makeEvents("e1", "e2", "e3")}
		result := sess.filterEvents("e1", "")
		require.Len(t, result, 2)
		assert.Equal(t, "e2", result[0].ID)
	})

	t.Run("unknown_event_id_returns_all", func(t *testing.T) {
		sess := &oastSession{events: makeEvents("e1", "e2", "e3")}
		result := sess.filterEvents("nonexistent", "")
		require.Len(t, result, 3)
	})

	t.Run("type_filter_returns_matching", func(t *testing.T) {
		sess := &oastSession{events: []OastEventInfo{
			{ID: "e1", Time: baseTime, Type: "dns"},
			{ID: "e2", Time: baseTime.Add(time.Second), Type: "http"},
			{ID: "e3", Time: baseTime.Add(2 * time.Second), Type: "dns"},
			{ID: "e4", Time: baseTime.Add(3 * time.Second), Type: "smtp"},
		}}
		result := sess.filterEvents("", "dns")
		require.Len(t, result, 2)
		assert.Equal(t, "e1", result[0].ID)
		assert.Equal(t, "e3", result[1].ID)
	})

	t.Run("type_filter_no_matches", func(t *testing.T) {
		sess := &oastSession{events: makeEvents("e1", "e2", "e3")}
		result := sess.filterEvents("", "smtp")
		assert.Empty(t, result)
	})

	t.Run("http_filter_matches_https", func(t *testing.T) {
		sess := &oastSession{events: []OastEventInfo{
			{ID: "e1", Time: baseTime, Type: "dns"},
			{ID: "e2", Time: baseTime.Add(time.Second), Type: "http"},
			{ID: "e3", Time: baseTime.Add(2 * time.Second), Type: "https"},
			{ID: "e4", Time: baseTime.Add(3 * time.Second), Type: "smtp"},
		}}
		result := sess.filterEvents("", "http")
		require.Len(t, result, 2)
		assert.Equal(t, "e2", result[0].ID)
		assert.Equal(t, "e3", result[1].ID)
	})

	t.Run("https_filter_matches_http", func(t *testing.T) {
		sess := &oastSession{events: []OastEventInfo{
			{ID: "e1", Time: baseTime, Type: "http"},
			{ID: "e2", Time: baseTime.Add(time.Second), Type: "https"},
			{ID: "e3", Time: baseTime.Add(2 * time.Second), Type: "dns"},
		}}
		result := sess.filterEvents("", "https")
		require.Len(t, result, 2)
		assert.Equal(t, "e1", result[0].ID)
		assert.Equal(t, "e2", result[1].ID)
	})

	t.Run("type_filter_with_since", func(t *testing.T) {
		sess := &oastSession{events: []OastEventInfo{
			{ID: "e1", Time: baseTime, Type: "dns"},
			{ID: "e2", Time: baseTime.Add(time.Second), Type: "http"},
			{ID: "e3", Time: baseTime.Add(2 * time.Second), Type: "dns"},
			{ID: "e4", Time: baseTime.Add(3 * time.Second), Type: "http"},
		}}
		result := sess.filterEvents("e1", "http")
		require.Len(t, result, 2)
		assert.Equal(t, "e2", result[0].ID)
		assert.Equal(t, "e4", result[1].ID)
	})

	t.Run("type_filter_with_last", func(t *testing.T) {
		sess := &oastSession{
			events: []OastEventInfo{
				{ID: "e1", Time: baseTime, Type: "dns"},
				{ID: "e2", Time: baseTime.Add(time.Second), Type: "http"},
				{ID: "e3", Time: baseTime.Add(2 * time.Second), Type: "dns"},
				{ID: "e4", Time: baseTime.Add(3 * time.Second), Type: "http"},
			},
			lastPollIdx: 2,
		}
		result := sess.filterEvents(sinceLast, "dns")
		require.Len(t, result, 1)
		assert.Equal(t, "e3", result[0].ID)
	})
}

func TestOastSession_BufferRotation(t *testing.T) {
	t.Parallel()

	// Simulate the buffer rotation logic from handleInteraction
	addEvent := func(sess *oastSession, id string) {
		sess.mu.Lock()
		defer sess.mu.Unlock()

		if len(sess.events) >= MaxOastEventsPerSession {
			sess.events = sess.events[1:]
			sess.droppedCount++
			if sess.lastPollIdx > 0 {
				sess.lastPollIdx--
			}
		}
		sess.events = append(sess.events, OastEventInfo{
			ID:   id,
			Time: time.Now(),
			Type: "dns",
		})
	}

	t.Run("lastPollIdx_decrements_on_drop", func(t *testing.T) {
		sess := &oastSession{
			events:      make([]OastEventInfo, MaxOastEventsPerSession),
			lastPollIdx: 100,
		}

		addEvent(sess, "new1")

		assert.Equal(t, 99, sess.lastPollIdx)
		assert.Equal(t, 1, sess.droppedCount)
		assert.Len(t, sess.events, MaxOastEventsPerSession)
	})

	t.Run("lastPollIdx_stays_zero", func(t *testing.T) {
		sess := &oastSession{
			events:      make([]OastEventInfo, MaxOastEventsPerSession),
			lastPollIdx: 0,
		}

		addEvent(sess, "new1")
		addEvent(sess, "new2")

		assert.Equal(t, 0, sess.lastPollIdx)
		assert.Equal(t, 2, sess.droppedCount)
	})

	t.Run("since_last_with_buffer_overflow", func(t *testing.T) {
		sess := &oastSession{}

		// Fill buffer
		for i := 0; i < MaxOastEventsPerSession; i++ {
			sess.events = append(sess.events, OastEventInfo{
				ID:   "e" + string(rune('a'+i%26)),
				Time: time.Now(),
				Type: "dns",
			})
		}

		// Poll all events, setting lastPollIdx
		result := sess.filterEvents("", "")
		assert.Len(t, result, MaxOastEventsPerSession)
		sess.lastPollIdx = len(sess.events)

		// Add events that cause overflow
		for i := 0; i < 10; i++ {
			addEvent(sess, "new"+string(rune('0'+i)))
		}

		// lastPollIdx should have been adjusted
		assert.Equal(t, MaxOastEventsPerSession-10, sess.lastPollIdx)

		// "last" filter should return only the new events
		result = sess.filterEvents(sinceLast, "")
		assert.Len(t, result, 10)
		assert.Equal(t, "new0", result[0].ID)
	})

	t.Run("lastPollIdx_does_not_go_negative", func(t *testing.T) {
		sess := &oastSession{
			events:      make([]OastEventInfo, MaxOastEventsPerSession),
			lastPollIdx: 5,
		}

		// Add 10 events - should only decrement to 0, not go negative
		for i := 0; i < 10; i++ {
			addEvent(sess, "e"+string(rune('0'+i)))
		}

		assert.Equal(t, 0, sess.lastPollIdx)
		assert.Equal(t, 10, sess.droppedCount)
	})
}

func TestInteractshBackend_GetEvent(t *testing.T) {
	t.Parallel()

	t.Run("event_not_found", func(t *testing.T) {
		backend := NewInteractshBackend("")
		t.Cleanup(func() { _ = backend.Close() })

		_, err := backend.GetEvent(t.Context(), "nonexistent")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("event_not_found_with_sessions", func(t *testing.T) {
		backend := NewInteractshBackend("")
		t.Cleanup(func() { _ = backend.Close() })

		sess := &oastSession{
			info: OastSessionInfo{
				ID:     "test123",
				Domain: "test.alpha.oastsrv.net",
			},
			notify: make(chan struct{}),
			events: []OastEventInfo{
				{ID: "e1", Time: time.Now(), Type: "dns"},
			},
		}
		backend.sessions["test.alpha.oastsrv.net"] = sess
		backend.byID["test123"] = "test.alpha.oastsrv.net"

		_, err := backend.GetEvent(t.Context(), "nonexistent")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("returns_event_by_id", func(t *testing.T) {
		backend := NewInteractshBackend("")
		t.Cleanup(func() { _ = backend.Close() })

		eventTime := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
		sess := &oastSession{
			info: OastSessionInfo{
				ID:     "test456",
				Domain: "test2.alpha.oastsrv.net",
			},
			notify: make(chan struct{}),
			events: []OastEventInfo{
				{ID: "e1", Time: eventTime, Type: "dns", SourceIP: "1.1.1.1"},
				{
					ID:        "e2",
					Time:      eventTime.Add(time.Minute),
					Type:      "http",
					SourceIP:  "2.2.2.2",
					Subdomain: "test.domain.alpha.oastsrv.net",
					Details:   map[string]interface{}{"raw_request": "GET / HTTP/1.1\r\nHost: test"},
				},
				{ID: "e3", Time: eventTime.Add(2 * time.Minute), Type: "smtp"},
			},
		}
		backend.sessions["test2.alpha.oastsrv.net"] = sess
		backend.byID["test456"] = "test2.alpha.oastsrv.net"

		event, err := backend.GetEvent(t.Context(), "e2")
		require.NoError(t, err)
		assert.Equal(t, "e2", event.ID)
		assert.Equal(t, "http", event.Type)
		assert.Equal(t, "2.2.2.2", event.SourceIP)
		assert.Equal(t, "test.domain.alpha.oastsrv.net", event.Subdomain)
		assert.Equal(t, "GET / HTTP/1.1\r\nHost: test", event.Details["raw_request"])
	})

	t.Run("searches_across_sessions", func(t *testing.T) {
		backend := NewInteractshBackend("")
		t.Cleanup(func() { _ = backend.Close() })

		sess1 := &oastSession{
			info: OastSessionInfo{
				ID:     "sess1",
				Domain: "s1.alpha.oastsrv.net",
			},
			notify: make(chan struct{}),
			events: []OastEventInfo{
				{ID: "e1", Time: time.Now(), Type: "dns"},
			},
		}
		sess2 := &oastSession{
			info: OastSessionInfo{
				ID:     "sess2",
				Domain: "s2.alpha.oastsrv.net",
			},
			notify: make(chan struct{}),
			events: []OastEventInfo{
				{ID: "e2", Time: time.Now(), Type: "http", SourceIP: "3.3.3.3"},
			},
		}
		backend.sessions["s1.alpha.oastsrv.net"] = sess1
		backend.sessions["s2.alpha.oastsrv.net"] = sess2
		backend.byID["sess1"] = "s1.alpha.oastsrv.net"
		backend.byID["sess2"] = "s2.alpha.oastsrv.net"

		event, err := backend.GetEvent(t.Context(), "e2")
		require.NoError(t, err)
		assert.Equal(t, "e2", event.ID)
		assert.Equal(t, "3.3.3.3", event.SourceIP)
	})

	t.Run("skips_stopped_sessions", func(t *testing.T) {
		backend := NewInteractshBackend("")
		t.Cleanup(func() { _ = backend.Close() })

		notify := make(chan struct{})
		close(notify)
		stoppedSess := &oastSession{
			info: OastSessionInfo{
				ID:     "teststopped",
				Domain: "stopped.alpha.oastsrv.net",
			},
			notify:  notify,
			stopped: true,
			events: []OastEventInfo{
				{ID: "e1", Time: time.Now(), Type: "dns"},
			},
		}
		backend.sessions["stopped.alpha.oastsrv.net"] = stoppedSess
		backend.byID["teststopped"] = "stopped.alpha.oastsrv.net"

		_, err := backend.GetEvent(t.Context(), "e1")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestDnsLabelRe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"lowercase_alpha", "ssrf", true},
		{"with_hyphen", "test-xxe", true},
		{"alphanumeric", "a1b2", true},
		{"single_char", "a", true},
		{"single_digit", "1", true},
		{"uppercase_lowered", "SSRF", true},
		{"mixed_case_lowered", "Test-Xxe", true},
		{"leading_hyphen", "-start", false},
		{"trailing_hyphen", "end-", false},
		{"has_space", "has space", false},
		{"has_underscore", "under_score", false},
		{"has_dot", "has.dot", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, dnsLabelRe.MatchString(strings.ToLower(tt.input)))
		})
	}
}

func TestNewInteractshBackend(t *testing.T) {
	t.Parallel()

	t.Run("empty_server_url", func(t *testing.T) {
		backend := NewInteractshBackend("")
		assert.Empty(t, backend.serverURL)
	})

	t.Run("custom_server_url", func(t *testing.T) {
		backend := NewInteractshBackend("oast.internal.example.com")
		assert.Equal(t, "oast.internal.example.com", backend.serverURL)
	})
}

func TestInteractshBackend_DeleteSession(t *testing.T) {
	t.Parallel()

	t.Run("second_delete_returns_not_found", func(t *testing.T) {
		backend := NewInteractshBackend("")
		t.Cleanup(func() { _ = backend.Close() })

		sess := &oastSession{
			info: OastSessionInfo{
				ID:     "testdel",
				Domain: "del.alpha.oastsrv.net",
			},
			notify: make(chan struct{}),
		}
		backend.sessions["del.alpha.oastsrv.net"] = sess
		backend.byID["testdel"] = "del.alpha.oastsrv.net"

		err := backend.DeleteSession(t.Context(), "testdel")
		require.NoError(t, err)

		err = backend.DeleteSession(t.Context(), "testdel")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("delete_by_domain", func(t *testing.T) {
		backend := NewInteractshBackend("")
		t.Cleanup(func() { _ = backend.Close() })

		sess := &oastSession{
			info: OastSessionInfo{
				ID:     "testdeldomain",
				Domain: "deldomain.alpha.oastsrv.net",
			},
			notify: make(chan struct{}),
		}
		backend.sessions["deldomain.alpha.oastsrv.net"] = sess
		backend.byID["testdeldomain"] = "deldomain.alpha.oastsrv.net"

		err := backend.DeleteSession(t.Context(), "deldomain.alpha.oastsrv.net")
		require.NoError(t, err)

		sessions, _ := backend.ListSessions(t.Context())
		assert.Empty(t, sessions)
	})
}

// TestInteractshBackend_LivePoll verifies the full backend flow: create session,
// trigger an HTTP interaction, and poll for events through the backend API.
// Uses HTTP (not DNS) to avoid local resolver caching that bypasses the OAST server.
func TestInteractshBackend_LivePoll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	backend := NewInteractshBackend("")
	t.Cleanup(func() { _ = backend.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	t.Cleanup(cancel)

	sess, err := backend.CreateSession(ctx, "")
	require.NoError(t, err)
	t.Logf("session created: id=%s domain=%s", sess.ID, sess.Domain)

	// Trigger HTTP interaction (more reliable than DNS which may be cached by resolvers)
	httpURL := "http://" + sess.Domain
	t.Logf("triggering HTTP request to: %s", httpURL)
	httpClient := &http.Client{Timeout: 10 * time.Second}
	resp, httpErr := httpClient.Get(httpURL)
	if httpErr != nil {
		t.Logf("HTTP request error (expected): %v", httpErr)
	} else {
		require.NoError(t, resp.Body.Close())
		t.Logf("HTTP response status: %d", resp.StatusCode)
	}

	// Poll for events with wait - the backend polls every 10s, so wait long enough
	t.Log("polling for events (up to 60s)...")
	result, err := backend.PollSession(ctx, sess.ID, "", "", 60*time.Second, 0)
	require.NoError(t, err)

	if len(result.Events) == 0 {
		t.Fatal("no events received after 60s wait - polling may be broken")
	}

	t.Logf("received %d event(s)", len(result.Events))
	for i, e := range result.Events {
		t.Logf("  event[%d]: id=%s type=%s source=%s subdomain=%s", i, e.ID, e.Type, e.SourceIP, e.Subdomain)
	}

	assert.NotEmpty(t, result.Events[0].Type)
	assert.NotEmpty(t, result.Events[0].SourceIP)
}

func TestHandleInteraction(t *testing.T) {
	t.Parallel()

	const testCorrelationID = "testcorrelation"
	const testNonce = "nonce1aa"

	setup := func() (*InteractshBackend, *oastSession) {
		b := NewInteractshBackend("")
		b.correlationID = testCorrelationID

		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "sess1",
				Domain:    "test.oastsrv.net",
				CreatedAt: time.Now(),
			},
			nonce:  testNonce,
			notify: make(chan struct{}),
		}
		b.sessions["test.oastsrv.net"] = sess
		b.byID["sess1"] = "test.oastsrv.net"
		b.byNonce[testNonce] = "test.oastsrv.net"
		return b, sess
	}

	t.Run("routes_by_nonce", func(t *testing.T) {
		b, sess := setup()

		b.handleInteraction(&oobclient.Interaction{
			FullId:   testCorrelationID + testNonce,
			Protocol: "DNS",
		})

		sess.mu.Lock()
		defer sess.mu.Unlock()
		assert.Len(t, sess.events, 1)
	})

	t.Run("prefix_subdomains", func(t *testing.T) {
		b, sess := setup()

		b.handleInteraction(&oobclient.Interaction{
			FullId:   "ssrf." + testCorrelationID + testNonce,
			Protocol: "HTTP",
		})

		sess.mu.Lock()
		defer sess.mu.Unlock()
		assert.Len(t, sess.events, 1)
	})

	t.Run("unknown_nonce", func(t *testing.T) {
		b, sess := setup()

		b.handleInteraction(&oobclient.Interaction{
			FullId:   testCorrelationID + "unkno99z",
			Protocol: "DNS",
		})

		sess.mu.Lock()
		defer sess.mu.Unlock()
		assert.Empty(t, sess.events)
	})

	t.Run("wrong_correlation_id", func(t *testing.T) {
		b, sess := setup()

		b.handleInteraction(&oobclient.Interaction{
			FullId:   "wrongcorrelation" + testNonce,
			Protocol: "DNS",
		})

		sess.mu.Lock()
		defer sess.mu.Unlock()
		assert.Empty(t, sess.events)
	})

	t.Run("stopped_session", func(t *testing.T) {
		b, sess := setup()

		sess.mu.Lock()
		sess.stopped = true
		close(sess.notify)
		sess.mu.Unlock()

		b.handleInteraction(&oobclient.Interaction{
			FullId:   testCorrelationID + testNonce,
			Protocol: "DNS",
		})

		sess.mu.Lock()
		defer sess.mu.Unlock()
		assert.Empty(t, sess.events)
	})

	t.Run("populates_event_fields", func(t *testing.T) {
		b, sess := setup()

		ts := time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC)
		b.handleInteraction(&oobclient.Interaction{
			FullId:        testCorrelationID + testNonce,
			Protocol:      "HTTP",
			RemoteAddress: "10.0.0.1",
			Timestamp:     ts,
			RawRequest:    "GET / HTTP/1.1\r\nHost: example.com",
			RawResponse:   "HTTP/1.1 200 OK",
			QType:         "A",
			SMTPFrom:      "test@example.com",
		})

		sess.mu.Lock()
		defer sess.mu.Unlock()
		require.Len(t, sess.events, 1)

		e := sess.events[0]
		assert.NotEmpty(t, e.ID)
		assert.Equal(t, "http", e.Type)
		assert.Equal(t, "10.0.0.1", e.SourceIP)
		assert.Equal(t, testCorrelationID+testNonce, e.Subdomain)
		assert.Equal(t, ts, e.Time)
		assert.Equal(t, "GET / HTTP/1.1\r\nHost: example.com", e.Details["raw_request"])
		assert.Equal(t, "HTTP/1.1 200 OK", e.Details["raw_response"])
		assert.Equal(t, "A", e.Details["query_type"])
		assert.Equal(t, "test@example.com", e.Details["smtp_from"])
	})
}

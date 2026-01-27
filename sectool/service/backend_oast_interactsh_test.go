package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInteractshBackend_CreateAndClose(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()

	backend := NewInteractshBackend()
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
		backend := NewInteractshBackend()
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

		backend := NewInteractshBackend()
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
		backend := NewInteractshBackend()
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "test123",
				Domain:    "test.oast.fun",
				CreatedAt: time.Now(),
			},
			notify:      make(chan struct{}),
			stopPolling: make(chan struct{}),
		}
		backend.sessions["test.oast.fun"] = sess
		backend.byID["test123"] = "test.oast.fun"

		sess.events = []OastEventInfo{
			{ID: "e1", Time: time.Now(), Type: "dns"},
			{ID: "e2", Time: time.Now(), Type: "http"},
			{ID: "e3", Time: time.Now(), Type: "dns"},
		}

		result, err := backend.PollSession(t.Context(), "test123", "", "", 0, 0)
		require.NoError(t, err)
		assert.Len(t, result.Events, 3)

		// Poll with "last" should return nothing (we just polled)
		result, err = backend.PollSession(t.Context(), "test123", "last", "", 0, 0)
		require.NoError(t, err)
		assert.Empty(t, result.Events)

		sess.events = append(sess.events, OastEventInfo{ID: "e4", Time: time.Now(), Type: "smtp"})

		// Poll with "last" should return the new event
		result, err = backend.PollSession(t.Context(), "test123", "last", "", 0, 0)
		require.NoError(t, err)
		assert.Len(t, result.Events, 1)
		assert.Equal(t, "e4", result.Events[0].ID)
	})

	t.Run("since_id", func(t *testing.T) {
		backend := NewInteractshBackend()
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "test456",
				Domain:    "test2.oast.fun",
				CreatedAt: time.Now(),
			},
			notify:      make(chan struct{}),
			stopPolling: make(chan struct{}),
		}
		backend.sessions["test2.oast.fun"] = sess
		backend.byID["test456"] = "test2.oast.fun"

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
		backend := NewInteractshBackend()
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        "testlimit",
				Domain:    "limit.oast.fun",
				CreatedAt: time.Now(),
			},
			notify:      make(chan struct{}),
			stopPolling: make(chan struct{}),
		}
		backend.sessions["limit.oast.fun"] = sess
		backend.byID["testlimit"] = "limit.oast.fun"

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
		backend := NewInteractshBackend()
		sess := &oastSession{
			info: OastSessionInfo{
				ID:        id,
				Domain:    domain,
				CreatedAt: time.Now(),
			},
			notify:      make(chan struct{}),
			stopPolling: make(chan struct{}),
		}
		backend.sessions[domain] = sess
		backend.byID[id] = domain

		cleanup := func() {
			backend.mu.Lock()
			backend.sessions = make(map[string]*oastSession)
			backend.byID = make(map[string]string)
			backend.byLabel = make(map[string]string)
			backend.mu.Unlock()
		}
		return backend, sess, cleanup
	}

	t.Run("context_cancellation_returns_promptly", func(t *testing.T) {
		backend, _, cleanup := setupBackend("testctx", "ctx.oast.fun")
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

		time.Sleep(50 * time.Millisecond)
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
		backend, sess, cleanup := setupBackend("testwait", "wait.oast.fun")
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

		time.Sleep(20 * time.Millisecond)
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
		backend, _, cleanup := setupBackend("testzero", "zero.oast.fun")
		t.Cleanup(cleanup)

		start := time.Now()
		result, err := backend.PollSession(t.Context(), "testzero", "", "", 0, 0)
		elapsed := time.Since(start)

		require.NoError(t, err)
		assert.Empty(t, result.Events)
		assert.Less(t, elapsed, 50*time.Millisecond)
	})

	t.Run("stopped_session_returns_error", func(t *testing.T) {
		backend, sess, cleanup := setupBackend("teststopped", "stopped.oast.fun")
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
		backend, sess, cleanup := setupBackend("testidx", "idx.oast.fun")
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

		_, err = backend.PollSession(t.Context(), "testidx", "last", "", 0, 0)
		require.NoError(t, err)
		assert.Equal(t, 3, sess.lastPollIdx)
	})
}

func TestInteractshBackend_CloseWhileClosed(t *testing.T) {
	t.Parallel()

	backend := NewInteractshBackend()

	// Close once
	err := backend.Close()
	require.NoError(t, err)

	// Close again should be idempotent
	err = backend.Close()
	require.NoError(t, err)
}

func TestInteractshBackend_CreateAfterClose(t *testing.T) {
	t.Parallel()

	backend := NewInteractshBackend()
	_ = backend.Close()

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
		result := sess.filterEvents("last", "")
		require.Len(t, result, 2)
		assert.Equal(t, "e3", result[0].ID)
		assert.Equal(t, "e4", result[1].ID)
	})

	t.Run("last_at_end_returns_empty", func(t *testing.T) {
		sess := &oastSession{
			events:      makeEvents("e1", "e2"),
			lastPollIdx: 2,
		}
		result := sess.filterEvents("last", "")
		assert.Empty(t, result)
	})

	t.Run("last_beyond_end_returns_empty", func(t *testing.T) {
		sess := &oastSession{
			events:      makeEvents("e1"),
			lastPollIdx: 5,
		}
		result := sess.filterEvents("last", "")
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
		result := sess.filterEvents("", "http")
		assert.Empty(t, result)
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
		result := sess.filterEvents("last", "dns")
		require.Len(t, result, 1)
		assert.Equal(t, "e3", result[0].ID)
	})
}

func TestOastSession_BufferRotation(t *testing.T) {
	t.Parallel()

	// Simulate the buffer rotation logic from pollLoop's callback
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
		result = sess.filterEvents("last", "")
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

	t.Run("session_not_found", func(t *testing.T) {
		backend := NewInteractshBackend()
		t.Cleanup(func() { _ = backend.Close() })

		_, err := backend.GetEvent(t.Context(), "nonexistent", "event1")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("event_not_found", func(t *testing.T) {
		backend := NewInteractshBackend()
		t.Cleanup(func() { _ = backend.Close() })

		sess := &oastSession{
			info: OastSessionInfo{
				ID:     "test123",
				Domain: "test.oast.fun",
			},
			notify:      make(chan struct{}),
			stopPolling: make(chan struct{}),
			events: []OastEventInfo{
				{ID: "e1", Time: time.Now(), Type: "dns"},
			},
		}
		backend.sessions["test.oast.fun"] = sess
		backend.byID["test123"] = "test.oast.fun"

		_, err := backend.GetEvent(t.Context(), "test123", "nonexistent")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("returns_event_by_id", func(t *testing.T) {
		backend := NewInteractshBackend()
		t.Cleanup(func() { _ = backend.Close() })

		eventTime := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
		sess := &oastSession{
			info: OastSessionInfo{
				ID:     "test456",
				Domain: "test2.oast.fun",
			},
			notify:      make(chan struct{}),
			stopPolling: make(chan struct{}),
			events: []OastEventInfo{
				{ID: "e1", Time: eventTime, Type: "dns", SourceIP: "1.1.1.1"},
				{
					ID:        "e2",
					Time:      eventTime.Add(time.Minute),
					Type:      "http",
					SourceIP:  "2.2.2.2",
					Subdomain: "test.domain.oast.fun",
					Details:   map[string]interface{}{"raw_request": "GET / HTTP/1.1\r\nHost: test"},
				},
				{ID: "e3", Time: eventTime.Add(2 * time.Minute), Type: "smtp"},
			},
		}
		backend.sessions["test2.oast.fun"] = sess
		backend.byID["test456"] = "test2.oast.fun"

		event, err := backend.GetEvent(t.Context(), "test456", "e2")
		require.NoError(t, err)
		assert.Equal(t, "e2", event.ID)
		assert.Equal(t, "http", event.Type)
		assert.Equal(t, "2.2.2.2", event.SourceIP)
		assert.Equal(t, "test.domain.oast.fun", event.Subdomain)
		assert.Equal(t, "GET / HTTP/1.1\r\nHost: test", event.Details["raw_request"])
	})

	t.Run("by_domain", func(t *testing.T) {
		backend := NewInteractshBackend()
		t.Cleanup(func() { _ = backend.Close() })

		sess := &oastSession{
			info: OastSessionInfo{
				ID:     "testdom",
				Domain: "domain.oast.fun",
			},
			notify:      make(chan struct{}),
			stopPolling: make(chan struct{}),
			events: []OastEventInfo{
				{ID: "evt1", Time: time.Now(), Type: "dns"},
			},
		}
		backend.sessions["domain.oast.fun"] = sess
		backend.byID["testdom"] = "domain.oast.fun"

		event, err := backend.GetEvent(t.Context(), "domain.oast.fun", "evt1")
		require.NoError(t, err)
		assert.Equal(t, "evt1", event.ID)
	})

	t.Run("stopped_session_returns_error", func(t *testing.T) {
		backend := NewInteractshBackend()
		t.Cleanup(func() { _ = backend.Close() })

		notify := make(chan struct{})
		close(notify) // already stopped
		sess := &oastSession{
			info: OastSessionInfo{
				ID:     "teststopped",
				Domain: "stopped.oast.fun",
			},
			notify:      notify,
			stopPolling: make(chan struct{}),
			stopped:     true,
			events: []OastEventInfo{
				{ID: "e1", Time: time.Now(), Type: "dns"},
			},
		}
		backend.sessions["stopped.oast.fun"] = sess
		backend.byID["teststopped"] = "stopped.oast.fun"

		_, err := backend.GetEvent(t.Context(), "teststopped", "e1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "deleted")
	})
}

func TestInteractshBackend_DeleteSession(t *testing.T) {
	t.Parallel()

	t.Run("second_delete_returns_not_found", func(t *testing.T) {
		backend := NewInteractshBackend()
		t.Cleanup(func() { _ = backend.Close() })

		sess := &oastSession{
			info: OastSessionInfo{
				ID:     "testdel",
				Domain: "del.oast.fun",
			},
			notify:      make(chan struct{}),
			stopPolling: make(chan struct{}),
		}
		backend.sessions["del.oast.fun"] = sess
		backend.byID["testdel"] = "del.oast.fun"

		err := backend.DeleteSession(t.Context(), "testdel")
		require.NoError(t, err)

		err = backend.DeleteSession(t.Context(), "testdel")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("delete_by_domain", func(t *testing.T) {
		backend := NewInteractshBackend()
		t.Cleanup(func() { _ = backend.Close() })

		sess := &oastSession{
			info: OastSessionInfo{
				ID:     "testdeldomain",
				Domain: "deldomain.oast.fun",
			},
			notify:      make(chan struct{}),
			stopPolling: make(chan struct{}),
		}
		backend.sessions["deldomain.oast.fun"] = sess
		backend.byID["testdeldomain"] = "deldomain.oast.fun"

		err := backend.DeleteSession(t.Context(), "deldomain.oast.fun")
		require.NoError(t, err)

		sessions, _ := backend.ListSessions(t.Context())
		assert.Empty(t, sessions)
	})
}

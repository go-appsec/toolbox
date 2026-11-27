package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

func TestParseWaitDuration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{name: "empty_defaults", input: "", want: 30 * time.Second},
		{name: "explicit_duration", input: "5s", want: 5 * time.Second},
		{name: "zero_disables", input: "0s", want: 0},
		{name: "negative_clamps_to_zero", input: "-3s", want: 0},
		{name: "over_cap_clamps", input: "1h", want: maxPollWait},
		{name: "at_cap", input: "120s", want: 120 * time.Second},
		{name: "invalid_string", input: "soon", wantErr: true},
		{name: "missing_unit", input: "30", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseWaitDuration(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFlowNotifier_Notify(t *testing.T) {
	t.Parallel()

	t.Run("wakes_existing_watcher", func(t *testing.T) {
		n := newFlowNotifier()
		ch := n.Watch()

		n.Notify()

		assert.True(t, isClosed(ch))
	})

	t.Run("watches_survive_replacement", func(t *testing.T) {
		n := newFlowNotifier()
		first := n.Watch()
		n.Notify()
		second := n.Watch()

		assert.True(t, isClosed(first))
		assert.False(t, isClosed(second))
	})

	t.Run("coalesces_bursts", func(t *testing.T) {
		n := &flowNotifier{ch: make(chan struct{}), throttle: time.Hour}

		ch := n.Watch()
		n.Notify()
		n.Notify() // within the throttle window: dropped for the re-check tick to recover

		assert.True(t, isClosed(ch))
		assert.False(t, isClosed(n.Watch()))
	})
}

// isClosed reports whether receiving from ch would complete immediately.
func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestWaitForFlowMatch(t *testing.T) {
	t.Parallel()

	okEntries := []flowEntry{{flowID: "abc"}}
	collectMatches := func() ([]flowEntry, int, error) { return okEntries, 1, nil }
	collectEmpty := func() ([]flowEntry, int, error) { return nil, 0, nil }

	t.Run("returns_existing_matches", func(t *testing.T) {
		filtered, totalMatched, timedOut, err := waitForFlowMatch(
			context.Background(), newFlowNotifier(), nil, maxPollWait, flowRecheckInterval, collectMatches)

		require.NoError(t, err)
		assert.False(t, timedOut)
		assert.Len(t, filtered, 1)
		assert.Equal(t, 1, totalMatched)
	})

	t.Run("zero_wait_skips_polling", func(t *testing.T) {
		filtered, _, timedOut, err := waitForFlowMatch(
			context.Background(), newFlowNotifier(), nil, 0, flowRecheckInterval, collectEmpty)

		require.NoError(t, err)
		assert.False(t, timedOut)
		assert.Empty(t, filtered)
	})

	t.Run("cancelled_context_not_timeout", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // pre-cancelled: the select must take ctx.Done over the deadline

		_, _, timedOut, err := waitForFlowMatch(
			ctx, newFlowNotifier(), nil, maxPollWait, flowRecheckInterval, collectEmpty)

		require.NoError(t, err)
		assert.False(t, timedOut)
	})

	t.Run("closed_shutdown_not_timeout", func(t *testing.T) {
		shutdown := make(chan struct{})
		close(shutdown) // pre-closed: the select must take shutdown over the deadline

		_, _, timedOut, err := waitForFlowMatch(
			context.Background(), newFlowNotifier(), shutdown, maxPollWait, flowRecheckInterval, collectEmpty)

		require.NoError(t, err)
		assert.False(t, timedOut)
	})

	t.Run("notify_wake_refetches", func(t *testing.T) {
		n := newFlowNotifier()
		calls := 0
		collect := func() ([]flowEntry, int, error) {
			calls++
			switch calls {
			case 2:
				n.Notify() // this pass runs after the watch grab
				return nil, 0, nil
			case 1:
				return nil, 0, nil
			default:
				return okEntries, 1, nil
			}
		}

		// recheck is beyond the wait: only the notify wake can reach the third pass
		filtered, totalMatched, timedOut, err := waitForFlowMatch(
			context.Background(), n, nil, time.Second, time.Hour, collect)

		require.NoError(t, err)
		assert.False(t, timedOut)
		assert.Len(t, filtered, 1)
		assert.Equal(t, 1, totalMatched)
	})

	t.Run("recheck_ticker_refetches", func(t *testing.T) {
		calls := 0
		collect := func() ([]flowEntry, int, error) {
			calls++
			if calls < 3 {
				return nil, 0, nil
			}
			return okEntries, 1, nil
		}

		filtered, _, timedOut, err := waitForFlowMatch(
			context.Background(), newFlowNotifier(), nil, time.Second, time.Millisecond, collect)

		require.NoError(t, err)
		assert.False(t, timedOut)
		assert.Len(t, filtered, 1)
	})

	t.Run("wait_expiry_reports_timeout", func(t *testing.T) {
		_, _, timedOut, err := waitForFlowMatch(
			context.Background(), newFlowNotifier(), nil, 5*time.Millisecond, time.Hour, collectEmpty)

		require.NoError(t, err)
		assert.True(t, timedOut)
	})

	t.Run("late_change_returned_on_expiry", func(t *testing.T) {
		calls := 0
		collect := func() ([]flowEntry, int, error) {
			calls++
			if calls == 1 {
				return nil, 0, nil
			}
			return okEntries, 1, nil // only the final pass sees it: the throttle dropped the wake
		}

		filtered, _, timedOut, err := waitForFlowMatch(
			context.Background(), newFlowNotifier(), nil, 5*time.Millisecond, time.Hour, collect)

		require.NoError(t, err)
		assert.False(t, timedOut)
		assert.Len(t, filtered, 1)
	})
}

func TestWireFlowChangeHooks(t *testing.T) {
	t.Parallel()

	backend, err := NewNativeProxyBackend(t.Context(), 0, t.TempDir(), 0, store.MemProvider, proxy.TimeoutConfig{}, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close(context.Background()) })

	srv, err := newServer(MCPServerFlags{}, t.TempDir(), store.MemProvider, backend, nil, nil)
	require.NoError(t, err)
	// unthrottled so back-to-back subtests each get their own wake
	srv.flowChanges = &flowNotifier{ch: make(chan struct{})}
	srv.wireFlowChangeHooks()

	t.Run("native_history_store", func(t *testing.T) {
		ch := srv.flowChanges.Watch()

		backend.History().Store(&types.Flow{Request: &types.Message{Method: "GET"}, StartedAt: time.Now()})

		assert.True(t, isClosed(ch))
	})

	t.Run("replay_store", func(t *testing.T) {
		ch := srv.flowChanges.Watch()

		srv.replayHistoryStore.Store(&store.ReplayHistoryEntry{ReplayHistoryMeta: store.ReplayHistoryMeta{FlowID: "f1"}})

		assert.True(t, isClosed(ch))
	})
}

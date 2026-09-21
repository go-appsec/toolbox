package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

func newTestCrawlStore(t *testing.T) *CrawlStore {
	t.Helper()

	storage := NewMemStorage()
	t.Cleanup(func() { _ = storage.Close() })
	return NewCrawlStore(storage)
}

func testSession(id, label string) *CrawlSessionData {
	if id == "" {
		id = "s1"
	}
	return &CrawlSessionData{
		CrawlSessionInfo: CrawlSessionInfo{
			ID:        id,
			Label:     label,
			CreatedAt: time.Now(),
			State:     "running",
		},
		StartedAt:    time.Now(),
		LastActivity: time.Now(),
	}
}

func testFlow(id string) *CrawlFlow {
	return &CrawlFlow{
		ID:             id,
		URL:            "https://example.com/" + id,
		Host:           "example.com",
		Path:           "/" + id,
		Method:         "GET",
		StatusCode:     200,
		ContentType:    "text/html",
		ResponseLength: 4,
		Request:        []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Response:       []byte("HTTP/1.1 201 Created\r\n\r\nok"),
		DiscoveredAt:   time.Now(),
	}
}

func TestCrawlStore_CreateAndGet(t *testing.T) {
	t.Parallel()

	t.Run("create_get_roundtrip", func(t *testing.T) {
		s := newTestCrawlStore(t)
		sess := testSession("s1", "alpha")

		require.NoError(t, s.Create(sess))

		got, ok := s.GetSession("s1")
		require.True(t, ok)
		assert.Equal(t, "s1", got.ID)
		assert.Equal(t, "alpha", got.Label)
		assert.Equal(t, "running", got.State)

		byLabel, ok := s.GetSession("alpha")
		require.True(t, ok)
		assert.Equal(t, "s1", byLabel.ID)
	})

	t.Run("duplicate_id_rejected", func(t *testing.T) {
		s := newTestCrawlStore(t)
		require.NoError(t, s.Create(testSession("s1", "")))
		err := s.Create(testSession("s1", ""))
		assert.ErrorContains(t, err, "already exists")
	})

	t.Run("duplicate_label_rejected", func(t *testing.T) {
		s := newTestCrawlStore(t)
		require.NoError(t, s.Create(testSession("s1", "alpha")))
		err := s.Create(testSession("s2", "alpha"))
		assert.ErrorContains(t, err, "already in use")
	})

	t.Run("unknown_returns_false", func(t *testing.T) {
		s := newTestCrawlStore(t)
		_, ok := s.GetSession("missing")
		assert.False(t, ok)
	})
}

func TestCrawlStore_AppendAndReadFlows(t *testing.T) {
	t.Parallel()

	t.Run("flows_preserve_order", func(t *testing.T) {
		s := newTestCrawlStore(t)
		require.NoError(t, s.Create(testSession("s1", "")))

		for _, id := range []string{"f3", "f1", "f2"} {
			require.NoError(t, s.AppendFlow("s1", testFlow(id)))
		}

		flows, ok := s.Flows("s1")
		require.True(t, ok)
		ids := make([]string, len(flows))
		for i, f := range flows {
			ids[i] = f.ID
		}
		assert.Equal(t, []string{"f3", "f1", "f2"}, ids)

		got, ok := s.GetFlow("f1")
		require.True(t, ok)
		assert.Equal(t, "s1", got.SessionID)
		assert.Equal(t, "/f1", got.Path)
	})

	t.Run("flow_roundtrip_bytes", func(t *testing.T) {
		s := newTestCrawlStore(t)
		require.NoError(t, s.Create(testSession("s1", "")))
		f := testFlow("fx")
		require.NoError(t, s.AppendFlow("s1", f))

		got, _ := s.GetFlow("fx")
		assert.Equal(t, f.Request, got.Request)
		assert.Equal(t, f.Response, got.Response)
	})

	t.Run("flows_missing_session", func(t *testing.T) {
		s := newTestCrawlStore(t)
		err := s.AppendFlow("nope", testFlow("f1"))
		assert.ErrorContains(t, err, "not found")
	})
}

func TestCrawlStore_FormsAndErrors(t *testing.T) {
	t.Parallel()

	t.Run("forms_and_errors_roundtrip", func(t *testing.T) {
		s := newTestCrawlStore(t)
		require.NoError(t, s.Create(testSession("s1", "")))

		form := protocol.CrawlForm{
			FormID:  "fmt",
			URL:     "https://example.com/",
			Action:  "/submit",
			Method:  "POST",
			HasCSRF: true,
			Inputs:  []protocol.FormInput{{Name: "q", Type: "text"}},
		}
		crawlErr := protocol.CrawlError{URL: "https://example.com/boom", Status: 500, Error: "dial tcp"}
		require.NoError(t, s.AppendForm("s1", form))
		require.NoError(t, s.AppendError("s1", crawlErr))

		forms, ok := s.Forms("s1")
		require.True(t, ok)
		assert.Equal(t, []protocol.CrawlForm{form}, forms)

		errs, ok := s.Errors("s1")
		require.True(t, ok)
		assert.Equal(t, []protocol.CrawlError{crawlErr}, errs)
	})
}

func TestCrawlStore_StateAndActivity(t *testing.T) {
	t.Parallel()

	t.Run("update_state_persists", func(t *testing.T) {
		s := newTestCrawlStore(t)
		require.NoError(t, s.Create(testSession("s1", "")))

		require.NoError(t, s.UpdateState("s1", "completed"))

		got, _ := s.GetSession("s1")
		assert.Equal(t, "completed", got.State)

		err := s.UpdateState("missing", "stopped")
		assert.ErrorContains(t, err, "not found")
	})

	t.Run("activity_advances_on_mutation", func(t *testing.T) {
		s := newTestCrawlStore(t)
		require.NoError(t, s.Create(testSession("s1", "")))

		before, _ := s.GetSession("s1")
		time.Sleep(time.Millisecond)
		require.NoError(t, s.AppendFlow("s1", testFlow("f1")))

		after, _ := s.GetSession("s1")
		assert.True(t, after.LastActivity.After(before.LastActivity))
	})
}

func TestCrawlStore_SessionsAndDelete(t *testing.T) {
	t.Parallel()

	t.Run("list_sessions", func(t *testing.T) {
		s := newTestCrawlStore(t)
		require.NoError(t, s.Create(testSession("s1", "")))
		require.NoError(t, s.Create(testSession("s2", "beta")))

		all := s.Sessions()
		assert.Len(t, all, 2)
		assert.Equal(t, 2, s.Count())
	})

	t.Run("delete_removes_results_and_label", func(t *testing.T) {
		s := newTestCrawlStore(t)
		require.NoError(t, s.Create(testSession("s1", "alpha")))
		require.NoError(t, s.AppendFlow("s1", testFlow("f1")))

		require.NoError(t, s.Delete("s1"))

		assert.Equal(t, 0, s.Count())
		_, ok := s.GetSession("s1")
		assert.False(t, ok)
		_, ok = s.GetSession("alpha")
		assert.False(t, ok)

		err := s.AppendFlow("s1", testFlow("f2"))
		assert.ErrorContains(t, err, "not found")
	})

	t.Run("delete_missing_is_noop", func(t *testing.T) {
		s := newTestCrawlStore(t)
		require.NoError(t, s.Delete("missing"))
	})
}

func TestCrawlStore_HydrateFromStorage(t *testing.T) {
	t.Parallel()

	t.Run("fresh_store_reads_stored_session", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })

		s1 := NewCrawlStore(storage)
		require.NoError(t, s1.Create(testSession("s1", "alpha")))
		for _, id := range []string{"f1", "f2"} {
			require.NoError(t, s1.AppendFlow("s1", testFlow(id)))
		}

		s2 := NewCrawlStore(storage)
		got, ok := s2.GetSession("alpha")
		require.True(t, ok)
		assert.Equal(t, "s1", got.ID)

		flows, ok := s2.Flows("s1")
		require.True(t, ok)
		assert.Len(t, flows, 2)
		assert.Equal(t, "f1", flows[0].ID)
	})
}

func TestCrawlStore_UpdateCursor(t *testing.T) {
	t.Parallel()

	storage := NewMemStorage()
	t.Cleanup(func() { _ = storage.Close() })
	s := NewCrawlStore(storage)
	require.NoError(t, s.Create(testSession("s1", "")))

	require.NoError(t, s.UpdateCursor("s1", 5))
	got, ok := s.GetSession("s1")
	require.True(t, ok)
	assert.Equal(t, 5, got.LastReturnedIdx)

	// A fresh store over the same storage simulates a restart
	restarted := NewCrawlStore(storage)
	got, ok = restarted.GetSession("s1")
	require.True(t, ok)
	assert.Equal(t, 5, got.LastReturnedIdx)

	assert.ErrorContains(t, s.UpdateCursor("missing", 1), "not found")
}

package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestOastStore(t *testing.T) (*OastStore, Storage) {
	t.Helper()
	st := NewMemStorage()
	return NewOastStore(st), st
}

func testInfo(id string) OastSessionInfo {
	return OastSessionInfo{
		ID:        id,
		Domain:    id + ".alpha.oastsrv.net",
		CreatedAt: time.Now(),
	}
}

func TestOastStore_CreateAndGet(t *testing.T) {
	t.Parallel()

	s, _ := newTestOastStore(t)
	err := s.CreateSession(testInfo("sess1"))
	require.NoError(t, err)

	rec, ok := s.Get("sess1")
	require.True(t, ok)
	assert.Equal(t, "sess1", rec.ID)
	assert.Empty(t, rec.Events)

	_, ok = s.Get("missing")
	assert.False(t, ok)
}

func TestOastStore_ResolveByIDLabelDomain(t *testing.T) {
	t.Parallel()

	s, _ := newTestOastStore(t)
	err := s.CreateSession(OastSessionInfo{
		ID:        "sess1",
		Domain:    "dom.alpha.oastsrv.net",
		Label:     "mylabel",
		CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	for _, identifier := range []string{"sess1", "mylabel", "dom.alpha.oastsrv.net"} {
		rec, ok := s.Resolve(identifier)
		require.True(t, ok, identifier)
		assert.Equal(t, "sess1", rec.ID, identifier)
	}

	_, ok := s.Resolve("nope")
	assert.False(t, ok)
}

func TestOastStore_SessionByLabel(t *testing.T) {
	t.Parallel()

	s, _ := newTestOastStore(t)
	err := s.CreateSession(OastSessionInfo{ID: "sess1", Domain: "d1.oastsrv.net", Label: "lbl"})
	require.NoError(t, err)

	rec, ok := s.SessionByLabel("lbl")
	require.True(t, ok)
	assert.Equal(t, "sess1", rec.ID)

	_, ok = s.SessionByLabel("absent")
	assert.False(t, ok)
}

func TestOastStore_AppendEventTrims(t *testing.T) {
	t.Parallel()

	s, _ := newTestOastStore(t)
	err := s.CreateSession(testInfo("sess1"))
	require.NoError(t, err)

	const max = 3
	for i := range max + 2 {
		dropped, err := s.AppendEvent("sess1", OastEvent{ID: string(rune('a' + i))}, max)
		require.NoError(t, err)
		if i < max {
			assert.False(t, dropped)
		} else {
			assert.True(t, dropped)
		}
	}

	rec, ok := s.Get("sess1")
	require.True(t, ok)
	assert.Len(t, rec.Events, max)
	assert.Equal(t, 2, rec.DroppedCount)
	assert.Equal(t, string(rune('c')), rec.Events[0].ID) // oldest dropped
}

func TestOastStore_AppendEventMissingSession(t *testing.T) {
	t.Parallel()

	s, _ := newTestOastStore(t)
	_, err := s.AppendEvent("ghost", OastEvent{ID: "e"}, 5)
	assert.ErrorIs(t, err, ErrOastNotFound)
}

func TestOastStore_CreateSessionLabelConflict(t *testing.T) {
	t.Parallel()

	s, _ := newTestOastStore(t)
	require.NoError(t, s.CreateSession(OastSessionInfo{ID: "a", Domain: "a.oastsrv.net", Label: "lbl"}))

	err := s.CreateSession(OastSessionInfo{ID: "b", Domain: "b.oastsrv.net", Label: "lbl"})
	require.ErrorIs(t, err, ErrOastLabelExists)

	// Same-ID re-registration keeps its label.
	assert.NoError(t, s.CreateSession(OastSessionInfo{ID: "a", Domain: "a.oastsrv.net", Label: "lbl"}))
}

func TestOastStore_FindEvent(t *testing.T) {
	t.Parallel()

	s, _ := newTestOastStore(t)
	require.NoError(t, s.CreateSession(testInfo("a")))
	require.NoError(t, s.CreateSession(testInfo("b")))
	var err error
	_, err = s.AppendEvent("a", OastEvent{ID: "a1"}, 0)
	require.NoError(t, err)
	_, err = s.AppendEvent("b", OastEvent{ID: "b1"}, 0)
	require.NoError(t, err)

	ev, ok := s.FindEvent("b1")
	require.True(t, ok)
	assert.Equal(t, "b1", ev.ID)

	_, ok = s.FindEvent("missing")
	assert.False(t, ok)
}

// failSetStorage fails Set for one key to exercise rollback paths.
type failSetStorage struct {
	Storage
	failKey string
}

func (s *failSetStorage) Set(key string, blob []byte) error {
	if key == s.failKey {
		return assert.AnError
	}
	return s.Storage.Set(key, blob)
}

func TestOastStore_AppendEventRollsBackOnPersistFailure(t *testing.T) {
	t.Parallel()

	st := &failSetStorage{Storage: NewMemStorage()}
	s := NewOastStore(st)
	require.NoError(t, s.CreateSession(testInfo("sess1")))

	st.failKey = oastSessionKeyPrefix + "sess1" // fail the record write, not the event write
	_, err := s.AppendEvent("sess1", OastEvent{ID: "e1"}, 0)
	require.ErrorIs(t, err, assert.AnError)

	rec, ok := s.Get("sess1")
	require.True(t, ok)
	assert.Empty(t, rec.Events)
	assert.Equal(t, 0, rec.EventCount)
	_, found, err := st.Get(oastEventKeyPrefix + "sess1:0")
	require.NoError(t, err)
	assert.False(t, found, "appended event should not be orphaned")
}

func TestOastStore_DeleteRemovesIndices(t *testing.T) {
	t.Parallel()

	s, _ := newTestOastStore(t)
	err := s.CreateSession(OastSessionInfo{ID: "sess1", Domain: "dom.oastsrv.net", Label: "lbl"})
	require.NoError(t, err)

	err = s.Delete("sess1")
	require.NoError(t, err)

	assert.Empty(t, s.List())
	_, ok := s.Get("sess1")
	assert.False(t, ok)
	_, ok = s.Resolve("dom.oastsrv.net")
	assert.False(t, ok)
	_, ok = s.SessionByLabel("lbl")
	assert.False(t, ok)

	// Delete is idempotent.
	err = s.Delete("sess1")
	require.NoError(t, err)
}

func TestOastStore_ListExcludesReverseIndices(t *testing.T) {
	t.Parallel()

	s, _ := newTestOastStore(t)
	err := s.CreateSession(testInfo("a"))
	require.NoError(t, err)
	err = s.CreateSession(OastSessionInfo{ID: "b", Domain: "bd.oastsrv.net", Label: "blabel"})
	require.NoError(t, err)

	list := s.List()
	assert.Len(t, list, 2)
}

func TestOastStore_UpdatePollCursor(t *testing.T) {
	t.Parallel()

	s, storage := newTestOastStore(t)
	require.NoError(t, s.CreateSession(testInfo("sess1")))

	require.NoError(t, s.UpdatePollCursor("sess1", 7))
	rec, ok := s.Get("sess1")
	require.True(t, ok)
	assert.Equal(t, 7, rec.LastPollIdx)

	// A fresh store over the same storage simulates a restart
	restarted := NewOastStore(storage)
	rec, ok = restarted.Get("sess1")
	require.True(t, ok)
	assert.Equal(t, 7, rec.LastPollIdx)

	assert.ErrorIs(t, s.UpdatePollCursor("missing", 1), ErrOastNotFound)
}

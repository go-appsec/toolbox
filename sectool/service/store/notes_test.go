package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoteStore(t *testing.T) {
	t.Parallel()

	t.Run("save_and_get", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		note := &NoteMeta{
			NoteID:  "n1",
			Type:    "finding",
			FlowIDs: []string{"f1", "f2"},
			Content: "XSS in search param",
		}
		require.NoError(t, ns.Save(note))

		got, ok := ns.Get("n1")
		require.True(t, ok)
		assert.Equal(t, "n1", got.NoteID)
		assert.Equal(t, "finding", got.Type)
		assert.Equal(t, []string{"f1", "f2"}, got.FlowIDs)
		assert.Equal(t, "XSS in search param", got.Content)
		assert.False(t, got.CreatedAt.IsZero())
		assert.False(t, got.UpdatedAt.IsZero())
	})

	t.Run("update_note", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		note := &NoteMeta{
			NoteID:  "n1",
			Type:    "finding",
			FlowIDs: []string{"f1"},
			Content: "original",
		}
		require.NoError(t, ns.Save(note))
		original, _ := ns.Get("n1")
		origCreated := original.CreatedAt

		updated := &NoteMeta{
			NoteID:    "n1",
			Type:      "finding",
			FlowIDs:   []string{"f1", "f3"},
			Content:   "updated content",
			CreatedAt: origCreated,
		}
		require.NoError(t, ns.Save(updated))

		got, ok := ns.Get("n1")
		require.True(t, ok)
		assert.Equal(t, "updated content", got.Content)
		assert.Equal(t, []string{"f1", "f3"}, got.FlowIDs)
		assert.True(t, got.CreatedAt.Equal(origCreated))
		assert.True(t, got.UpdatedAt.After(origCreated))
		assert.Equal(t, 1, ns.Count())
	})

	t.Run("delete_note", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		note := &NoteMeta{
			NoteID:  "n1",
			Type:    "finding",
			FlowIDs: []string{"f1"},
			Content: "to delete",
		}
		require.NoError(t, ns.Save(note))
		assert.Equal(t, 1, ns.Count())

		require.NoError(t, ns.Delete("n1"))
		assert.Equal(t, 0, ns.Count())

		_, ok := ns.Get("n1")
		assert.False(t, ok)
	})

	t.Run("list_all", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		baseTime := time.Now()
		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n1", Type: "finding", FlowIDs: []string{"f1"}, Content: "first", CreatedAt: baseTime}))
		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n2", Type: "note", FlowIDs: []string{"f2"}, Content: "second", CreatedAt: baseTime.Add(time.Millisecond)}))
		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n3", Type: "result", FlowIDs: []string{"f3"}, Content: "third", CreatedAt: baseTime.Add(2 * time.Millisecond)}))

		notes := ns.List(NoteListOptions{})
		require.Len(t, notes, 3)
		assert.Equal(t, "n1", notes[0].NoteID)
		assert.Equal(t, "n2", notes[1].NoteID)
		assert.Equal(t, "n3", notes[2].NoteID)
	})

	t.Run("list_filter_type", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n1", Type: "finding", FlowIDs: []string{"f1"}, Content: "a"}))
		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n2", Type: "note", FlowIDs: []string{"f2"}, Content: "b"}))
		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n3", Type: "finding", FlowIDs: []string{"f3"}, Content: "c"}))

		notes := ns.List(NoteListOptions{Type: "finding"})
		require.Len(t, notes, 2)
		assert.Equal(t, "n1", notes[0].NoteID)
		assert.Equal(t, "n3", notes[1].NoteID)
	})

	t.Run("list_filter_flow_id", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n1", Type: "finding", FlowIDs: []string{"f1", "f2"}, Content: "a"}))
		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n2", Type: "note", FlowIDs: []string{"f3"}, Content: "b"}))

		notes := ns.List(NoteListOptions{FlowIDs: []string{"f2"}})
		require.Len(t, notes, 1)
		assert.Equal(t, "n1", notes[0].NoteID)
	})

	t.Run("list_filter_multiple_flow_ids", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n1", Type: "finding", FlowIDs: []string{"f1"}, Content: "a"}))
		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n2", Type: "note", FlowIDs: []string{"f2"}, Content: "b"}))
		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n3", Type: "note", FlowIDs: []string{"f3"}, Content: "c"}))

		notes := ns.List(NoteListOptions{FlowIDs: []string{"f1", "f3"}})
		require.Len(t, notes, 2)
		assert.Equal(t, "n1", notes[0].NoteID)
		assert.Equal(t, "n3", notes[1].NoteID)
	})

	t.Run("list_filter_contains", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n1", Type: "finding", FlowIDs: []string{"f1"}, Content: "XSS in search"}))
		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n2", Type: "note", FlowIDs: []string{"f2"}, Content: "CSRF token missing"}))
		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n3", Type: "finding", FlowIDs: []string{"f3"}, Content: "Reflected xss found"}))

		notes := ns.List(NoteListOptions{Contains: "xss"})
		require.Len(t, notes, 2)
		assert.Equal(t, "n1", notes[0].NoteID)
		assert.Equal(t, "n3", notes[1].NoteID)
	})

	t.Run("list_paging", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		baseTime := time.Now()
		for i := range 5 {
			require.NoError(t, ns.Save(&NoteMeta{
				NoteID:    "n" + string(rune('1'+i)),
				Type:      "note",
				FlowIDs:   []string{"f1"},
				Content:   "note " + string(rune('1'+i)),
				CreatedAt: baseTime.Add(time.Duration(i) * time.Millisecond),
			}))
		}

		// First page
		page1 := ns.List(NoteListOptions{Limit: 2})
		require.Len(t, page1, 2)
		assert.Equal(t, "n1", page1[0].NoteID)
		assert.Equal(t, "n2", page1[1].NoteID)

		// Second page using after_id cursor (inclusive)
		page2 := ns.List(NoteListOptions{Limit: 2, AfterID: "n3"})
		require.Len(t, page2, 2)
		assert.Equal(t, "n3", page2[0].NoteID)
		assert.Equal(t, "n4", page2[1].NoteID)
	})

	t.Run("for_flow_ids_batch", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n1", Type: "finding", FlowIDs: []string{"f1", "f2"}, Content: "shared"}))
		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n2", Type: "note", FlowIDs: []string{"f2"}, Content: "f2 only"}))

		result := ns.ForFlowIDs([]string{"f1", "f2", "f99"})

		require.Len(t, result["f1"], 1)
		assert.Equal(t, "n1", result["f1"][0].NoteID)

		require.Len(t, result["f2"], 2)
		assert.Empty(t, result["f99"])
	})

	t.Run("reverse_index_cleanup", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n1", Type: "finding", FlowIDs: []string{"f1", "f2"}, Content: "test"}))

		// Verify reverse index has entries
		notes := ns.List(NoteListOptions{FlowIDs: []string{"f1"}})
		require.Len(t, notes, 1)

		// Delete the note
		require.NoError(t, ns.Delete("n1"))

		// Reverse index should be cleaned up
		notes = ns.List(NoteListOptions{FlowIDs: []string{"f1"}})
		assert.Empty(t, notes)
		notes = ns.List(NoteListOptions{FlowIDs: []string{"f2"}})
		assert.Empty(t, notes)
	})

	t.Run("update_changes_reverse_index", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		note := &NoteMeta{NoteID: "n1", Type: "finding", FlowIDs: []string{"f1", "f2"}, Content: "test"}
		require.NoError(t, ns.Save(note))

		// Update: remove f2, add f3
		updated := &NoteMeta{NoteID: "n1", Type: "finding", FlowIDs: []string{"f1", "f3"}, Content: "test", CreatedAt: note.CreatedAt}
		require.NoError(t, ns.Save(updated))

		// f1 should still find the note
		notes := ns.List(NoteListOptions{FlowIDs: []string{"f1"}})
		require.Len(t, notes, 1)

		// f2 should no longer find the note
		notes = ns.List(NoteListOptions{FlowIDs: []string{"f2"}})
		assert.Empty(t, notes)

		// f3 should now find the note
		notes = ns.List(NoteListOptions{FlowIDs: []string{"f3"}})
		require.Len(t, notes, 1)
	})

	t.Run("duplicate_flow_ids", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n1", Type: "finding", FlowIDs: []string{"f1", "f1"}, Content: "dup"}))

		assert.Equal(t, []string{"n1"}, ns.reverseIndexLookup("f1"))

		result := ns.ForFlowIDs([]string{"f1"})
		assert.Len(t, result["f1"], 1)
	})

	t.Run("count", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		assert.Equal(t, 0, ns.Count())

		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n1", Type: "note", FlowIDs: []string{"f1"}, Content: "a"}))
		assert.Equal(t, 1, ns.Count())

		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n2", Type: "note", FlowIDs: []string{"f2"}, Content: "b"}))
		assert.Equal(t, 2, ns.Count())

		require.NoError(t, ns.Delete("n1"))
		assert.Equal(t, 1, ns.Count())
	})
}

func TestNoteStoreCreate(t *testing.T) {
	t.Parallel()

	t.Run("assigns_unique_id", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		note := &NoteMeta{Type: "finding", FlowIDs: []string{"f1"}, Content: "x"}
		require.NoError(t, ns.Create(note))

		assert.NotEmpty(t, note.NoteID)
		assert.False(t, note.CreatedAt.IsZero())
		assert.False(t, note.UpdatedAt.IsZero())
		assert.Equal(t, 1, ns.Count())

		got, ok := ns.Get(note.NoteID)
		require.True(t, ok)
		assert.Equal(t, note.NoteID, got.NoteID)

		assert.Equal(t, []string{note.NoteID}, ns.reverseIndexLookup("f1"))
	})

	t.Run("distinct_ids", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		seen := make(map[string]struct{})
		for range 50 {
			note := &NoteMeta{Type: "note", Content: "x"}
			require.NoError(t, ns.Create(note))
			_, dup := seen[note.NoteID]
			assert.False(t, dup)
			seen[note.NoteID] = struct{}{}
		}
		assert.Equal(t, 50, ns.Count())
	})
}

func TestNoteStoreSplitReferencedFlows(t *testing.T) {
	t.Parallel()

	t.Run("empty_input", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n1", FlowIDs: []string{"f1"}, Content: "x"}))
		retained, other := ns.SplitReferencedFlows(nil)
		assert.Empty(t, retained)
		assert.Empty(t, other)
	})

	t.Run("none_referenced", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n1", FlowIDs: []string{"f1"}, Content: "x"}))
		retained, other := ns.SplitReferencedFlows([]string{"other1", "other2"})
		assert.Empty(t, retained)
		assert.Equal(t, []string{"other1", "other2"}, other)
	})

	t.Run("partial", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n1", FlowIDs: []string{"f1", "f3"}, Content: "x"}))
		retained, other := ns.SplitReferencedFlows([]string{"f1", "f2", "f3", "f4"})
		assert.Equal(t, []string{"f1", "f3"}, retained)
		assert.Equal(t, []string{"f2", "f4"}, other)
	})

	t.Run("all_referenced", func(t *testing.T) {
		storage := NewMemStorage()
		t.Cleanup(func() { _ = storage.Close() })
		ns := NewNoteStore(storage)

		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n1", FlowIDs: []string{"f1", "f2"}, Content: "a"}))
		require.NoError(t, ns.Save(&NoteMeta{NoteID: "n2", FlowIDs: []string{"f3"}, Content: "b"}))
		referenced, other := ns.SplitReferencedFlows([]string{"f1", "f2", "f3"})
		assert.Equal(t, []string{"f1", "f2", "f3"}, referenced)
		assert.Empty(t, other)
	})
}

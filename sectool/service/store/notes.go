package store

import (
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-analyze/bulk"
)

const reverseIndexPrefix = "_fn:"

// NoteMeta holds metadata and content for a saved note.
type NoteMeta struct {
	NoteID    string    `msgpack:"nid"`
	Type      string    `msgpack:"t"`
	FlowIDs   []string  `msgpack:"fids"`
	Content   string    `msgpack:"c"`
	CreatedAt time.Time `msgpack:"ca"`
	UpdatedAt time.Time `msgpack:"ua"`
}

// NoteListOptions controls filtering and pagination for note listing.
type NoteListOptions struct {
	Type     string
	FlowIDs  []string
	Contains string
	AfterID  string
	Limit    int
}

// NoteStore manages notes with thread-safe access and reverse index for flow lookups.
type NoteStore struct {
	storage Storage
	mu      sync.RWMutex
	count   int
}

// NewNoteStore creates a new NoteStore backed by the given storage.
func NewNoteStore(storage Storage) *NoteStore {
	return &NoteStore{storage: storage}
}

// Save upserts a note and maintains the reverse flow index.
func (s *NoteStore) Save(note *NoteMeta) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	isNew := note.CreatedAt.IsZero()
	if isNew {
		note.CreatedAt = now
	}
	note.UpdatedAt = now

	// Load existing note to diff flow_ids for reverse index
	var oldFlowIDs []string
	if !isNew {
		if existing, ok := s.getLocked(note.NoteID); ok {
			oldFlowIDs = existing.FlowIDs
		} else {
			// note_id provided but not found - treat as new
			isNew = true
			note.CreatedAt = now
		}
	}

	if data, err := Serialize(note); err != nil {
		return err
	} else if err = s.storage.Set(note.NoteID, data); err != nil {
		return err
	}

	// Update reverse index
	s.updateReverseIndex(note.NoteID, oldFlowIDs, note.FlowIDs)

	if isNew {
		s.count++
	}
	return nil
}

// Get retrieves a note by ID.
func (s *NoteStore) Get(noteID string) (*NoteMeta, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.getLocked(noteID)
}

// getLocked retrieves a note. Caller must hold mu.
func (s *NoteStore) getLocked(noteID string) (*NoteMeta, bool) {
	data, found, err := s.storage.Get(noteID)
	if err != nil || !found {
		return nil, false
	}
	var meta NoteMeta
	if err := Deserialize(data, &meta); err != nil {
		log.Printf("note store deserialize error: %v", err)
		return nil, false
	}
	return &meta, true
}

// Delete removes a note and cleans up the reverse index.
func (s *NoteStore) Delete(noteID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.getLocked(noteID)
	if !ok {
		return nil
	}

	if err := s.storage.Delete(noteID); err != nil {
		return err
	}

	// Remove from reverse index
	s.updateReverseIndex(noteID, existing.FlowIDs, nil)
	s.count--
	return nil
}

// List returns notes matching the given options, sorted by created_at.
func (s *NoteStore) List(opts NoteListOptions) []*NoteMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// If filtering by flow_ids, use reverse index for efficiency
	var candidateIDs []string
	if len(opts.FlowIDs) > 0 {
		seen := make(map[string]struct{})
		for _, fid := range opts.FlowIDs {
			for _, nid := range s.reverseIndexLookup(fid) {
				if _, ok := seen[nid]; !ok {
					seen[nid] = struct{}{}
					candidateIDs = append(candidateIDs, nid)
				}
			}
		}
		if len(candidateIDs) == 0 {
			return nil
		}
	}

	var notes []*NoteMeta
	if candidateIDs != nil {
		for _, id := range candidateIDs {
			if note, ok := s.getLocked(id); ok {
				notes = append(notes, note)
			}
		}
	} else {
		for _, key := range s.noteKeys() {
			if note, ok := s.getLocked(key); ok {
				notes = append(notes, note)
			}
		}
	}

	// Apply filters
	if opts.Type != "" || opts.Contains != "" {
		containsLower := strings.ToLower(opts.Contains)
		notes = bulk.SliceFilterInPlace(func(n *NoteMeta) bool {
			if opts.Type != "" && !strings.EqualFold(n.Type, opts.Type) {
				return false
			} else if opts.Contains != "" && !strings.Contains(strings.ToLower(n.Content), containsLower) {
				return false
			}
			return true
		}, notes)
	}

	// Sort by created_at
	sort.Slice(notes, func(i, j int) bool {
		return notes[i].CreatedAt.Before(notes[j].CreatedAt)
	})

	// Apply after_id cursor
	if opts.AfterID != "" {
		for i, n := range notes {
			if n.NoteID == opts.AfterID {
				notes = notes[i:]
				break
			}
		}
	}

	// Apply limit
	if opts.Limit > 0 && len(notes) > opts.Limit {
		notes = notes[:opts.Limit]
	}

	return notes
}

// ForFlowIDs returns notes associated with the given flow IDs, grouped by flow_id.
func (s *NoteStore) ForFlowIDs(flowIDs []string) map[string][]*NoteMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string][]*NoteMeta)
	seen := make(map[string]*NoteMeta) // dedup notes across flow_ids

	for _, fid := range flowIDs {
		noteIDs := s.reverseIndexLookup(fid)
		for _, nid := range noteIDs {
			note, ok := seen[nid]
			if !ok {
				note, ok = s.getLocked(nid)
				if !ok {
					continue
				}
				seen[nid] = note
			}
			result[fid] = append(result[fid], note)
		}
	}

	return result
}

// Count returns the number of stored notes.
func (s *NoteStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.count
}

func (s *NoteStore) Close() error {
	return s.storage.Close()
}

// noteKeys returns all note keys (excluding reverse index keys). Caller must hold mu.
func (s *NoteStore) noteKeys() []string {
	return bulk.SliceFilterInPlace(func(k string) bool {
		return !strings.HasPrefix(k, reverseIndexPrefix)
	}, s.storage.KeySet())
}

// updateReverseIndex maintains _fn:<flow_id> -> []note_id mappings.
// Caller must hold mu.
func (s *NoteStore) updateReverseIndex(noteID string, oldFlowIDs, newFlowIDs []string) {
	oldSet := bulk.SliceToSet(oldFlowIDs)
	newSet := bulk.SliceToSet(newFlowIDs)

	// Remove from flows no longer referenced
	for _, fid := range oldFlowIDs {
		if _, ok := newSet[fid]; !ok {
			s.removeFromReverseIndex(fid, noteID)
		}
	}

	// Add to newly referenced flows
	for _, fid := range newFlowIDs {
		if _, ok := oldSet[fid]; !ok {
			s.addToReverseIndex(fid, noteID)
		}
	}
}

// reverseIndexLookup returns note IDs for a flow_id. Caller must hold mu.
func (s *NoteStore) reverseIndexLookup(flowID string) []string {
	key := reverseIndexPrefix + flowID
	data, found, err := s.storage.Get(key)
	if err != nil || !found {
		return nil
	}
	var noteIDs []string
	if err := Deserialize(data, &noteIDs); err != nil {
		log.Printf("note store reverse index deserialize error: %v", err)
		return nil
	}
	return noteIDs
}

// addToReverseIndex adds a note_id to a flow_id's reverse index. Caller must hold mu.
func (s *NoteStore) addToReverseIndex(flowID, noteID string) {
	noteIDs := s.reverseIndexLookup(flowID)
	noteIDs = append(noteIDs, noteID)
	s.saveReverseIndex(flowID, noteIDs)
}

// removeFromReverseIndex removes a note_id from a flow_id's reverse index. Caller must hold mu.
func (s *NoteStore) removeFromReverseIndex(flowID, noteID string) {
	noteIDs := s.reverseIndexLookup(flowID)
	filtered := bulk.SliceFilterInPlace(func(id string) bool { return id != noteID }, noteIDs)
	if len(filtered) == 0 {
		_ = s.storage.Delete(reverseIndexPrefix + flowID)
	} else {
		s.saveReverseIndex(flowID, filtered)
	}
}

// saveReverseIndex persists a flow_id's note ID list. Caller must hold mu.
func (s *NoteStore) saveReverseIndex(flowID string, noteIDs []string) {
	data, err := Serialize(&noteIDs)
	if err != nil {
		log.Printf("note store reverse index serialize error: %v", err)
		return
	}
	if err := s.storage.Set(reverseIndexPrefix+flowID, data); err != nil {
		log.Printf("note store reverse index save error: %v", err)
	}
}

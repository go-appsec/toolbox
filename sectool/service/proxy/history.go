package proxy

import (
	"cmp"
	"log"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/ids"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

const (
	historyKeyPrefix  = "proxy:history:f:"
	historyPayloadSuf = ":p"
)

func historyMetaKey(flowID string) string {
	return historyKeyPrefix + flowID
}

func historyPayloadKey(flowID string) string {
	return historyKeyPrefix + flowID + historyPayloadSuf
}

// orderedFlow is the in-memory ordering record for a stored history entry.
type orderedFlow struct {
	flowID    string
	timestamp time.Time
}

// lessOrder is the canonical (timestamp, flow_id) order. flow_id breaks ties so
// same-instant captures sort deterministically across recovery and platform clock resolution.
func lessOrder(aTime time.Time, aID string, bTime time.Time, bID string) bool {
	if !aTime.Equal(bTime) {
		return aTime.Before(bTime)
	}
	return aID < bID
}

// HistoryStore provides typed access to proxy history backed by store.Storage.
// Entries are keyed by flow_id; merge ordering uses (Timestamp, FlowID).
type HistoryStore struct {
	mu              sync.RWMutex
	storage         store.Storage
	flowOrder       []orderedFlow        // ordered by (timestamp, flowID) ascending
	timestampByFlow map[string]time.Time // flow_id -> timestamp, for cursor resolution
	childOrder      map[string][]string  // parent flow_id -> child flow_ids in emission order
	captureFilter   atomic.Value         // stores CaptureFilter
}

// newHistoryStore creates a history store using the provided storage backend.
// Recovers in-memory ordering by scanning meta keys.
func newHistoryStore(storage store.Storage) *HistoryStore {
	h := &HistoryStore{
		storage:         storage,
		timestampByFlow: make(map[string]time.Time),
		childOrder:      make(map[string][]string),
	}
	h.recover()
	return h
}

// recover rebuilds in-memory order from persisted keys: top-level ordering from
// meta keys, and the parent child index from payload-only child flows.
func (h *HistoryStore) recover() {
	var payloadKeys []string
	for _, key := range h.storage.KeySet() {
		if !strings.HasPrefix(key, historyKeyPrefix) {
			continue
		}
		if strings.HasSuffix(key, historyPayloadSuf) {
			payloadKeys = append(payloadKeys, key)
			continue
		}
		data, found, err := h.storage.Get(key)
		if err != nil || !found {
			continue
		}
		var meta types.HistoryMeta
		if err := store.Deserialize(data, &meta); err != nil {
			log.Printf("proxy: history recover deserialize error %s: %v", key, err)
			continue
		}
		if meta.FlowID == "" {
			continue
		}
		ts := meta.Timestamp.UTC()
		h.flowOrder = append(h.flowOrder, orderedFlow{flowID: meta.FlowID, timestamp: ts})
		h.timestampByFlow[meta.FlowID] = ts
	}
	slices.SortFunc(h.flowOrder, func(a, b orderedFlow) int {
		return cmp.Or(a.timestamp.Compare(b.timestamp), cmp.Compare(a.flowID, b.flowID))
	})
	h.recoverChildOrder(payloadKeys)
}

// recoverChildOrder rebuilds the parent child index from payload-only child
// flows (children carry no meta key). Live emission order is in-memory only; on
// recovery it is approximated by (started_at, flow_id), matching the top-level
// ordering. This runs only when a store is rebuilt over existing storage; the
// history store is ephemeral, so it does not occur across process restarts.
func (h *HistoryStore) recoverChildOrder(payloadKeys []string) {
	type childRec struct {
		parent, id string
		ts         time.Time
	}
	var children []childRec
	for _, key := range payloadKeys {
		fid := strings.TrimSuffix(strings.TrimPrefix(key, historyKeyPrefix), historyPayloadSuf)
		if _, ok := h.timestampByFlow[fid]; ok {
			continue // top-level flow, already ordered via its meta key
		}
		data, found, err := h.storage.Get(key)
		if err != nil || !found {
			continue
		}
		var flow types.Flow
		if err := store.Deserialize(data, &flow); err != nil || flow.ParentFlowID == "" {
			continue
		}
		children = append(children, childRec{parent: flow.ParentFlowID, id: fid, ts: flow.StartedAt.UTC()})
	}
	slices.SortStableFunc(children, func(a, b childRec) int {
		return cmp.Or(a.ts.Compare(b.ts), cmp.Compare(a.id, b.id))
	})
	for _, c := range children {
		h.childOrder[c.parent] = append(h.childOrder[c.parent], c.id)
	}
}

// Store mints a flow_id, assigns it to flow, persists, and returns the flow_id.
// flow.StartedAt must be set by the caller. Child flows (ParentFlowID set) are
// stored payload-only: no meta key and absent from the listing order.
func (h *HistoryStore) Store(flow *types.Flow) string {
	h.mu.Lock()
	defer h.mu.Unlock()

	flowID := h.mintUniqueFlowIDLocked()
	flow.FlowID = flowID
	ts := flow.StartedAt.UTC()
	flow.StartedAt = ts

	h.writePayloadLocked(flow)
	if flow.ParentFlowID != "" {
		h.childOrder[flow.ParentFlowID] = append(h.childOrder[flow.ParentFlowID], flowID)
		return flowID
	}
	h.writeMetaLocked(flow)
	h.insertOrderLocked(orderedFlow{flowID: flowID, timestamp: ts})
	h.timestampByFlow[flowID] = ts
	return flowID
}

// Complete attaches a late response and/or completion to an already-stored
// flow: the two-phase form used for deferred responses and session/stream
// teardown. resp, when non-nil, populates the response side; a non-zero
// completedAt sets CompletedAt; annotations merge over existing keys. Returns
// false when flowID is unknown.
func (h *HistoryStore) Complete(flowID string, resp *types.Message, completedAt time.Time, annotations map[string]any) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	flow, ok := h.Get(flowID)
	if !ok {
		return false
	}
	if resp != nil {
		flow.Response = resp
	}
	if !completedAt.IsZero() {
		flow.CompletedAt = completedAt.UTC()
	}
	if len(annotations) > 0 {
		if flow.Annotations == nil {
			flow.Annotations = make(map[string]any, len(annotations))
		}
		maps.Copy(flow.Annotations, annotations)
	}
	h.writePayloadLocked(flow)
	if flow.ParentFlowID == "" {
		h.writeMetaLocked(flow)
	}
	return true
}

// SetInvokedBy records the originating sidecar on an already-stored flow.
// Returns false when flowID is unknown.
func (h *HistoryStore) SetInvokedBy(flowID, invokedBy string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	flow, ok := h.Get(flowID)
	if !ok {
		return false
	}
	flow.InvokedBy = invokedBy
	h.writePayloadLocked(flow)
	if flow.ParentFlowID == "" {
		h.writeMetaLocked(flow)
	}
	return true
}

// mintUniqueFlowIDLocked generates a flow_id, retrying on collision. Caller must hold mu.
// Probes the payload key so child flows (which have no meta key) are also covered.
func (h *HistoryStore) mintUniqueFlowIDLocked() string {
	for {
		candidate := ids.Generate(ids.DefaultLength)
		if _, exists := h.timestampByFlow[candidate]; exists {
			continue
		} else if _, found, _ := h.storage.Get(historyPayloadKey(candidate)); found {
			continue
		}
		return candidate
	}
}

// writePayloadLocked serializes and writes the payload key for a flow. Caller must hold mu.
func (h *HistoryStore) writePayloadLocked(flow *types.Flow) {
	payloadData, err := store.Serialize(flow)
	if err != nil {
		log.Printf("proxy: serialize history flow %s: %v", flow.FlowID, err)
		return
	}
	if err := h.storage.Set(historyPayloadKey(flow.FlowID), payloadData); err != nil {
		log.Printf("proxy: save history payload %s: %v", flow.FlowID, err)
	}
}

// writeMetaLocked serializes and writes the meta key for a flow. Caller must hold mu.
// Must run after writePayloadLocked: a torn write leaves an invisible orphan payload.
func (h *HistoryStore) writeMetaLocked(flow *types.Flow) {
	meta := flow.ExtractMeta()
	metaData, err := store.Serialize(&meta)
	if err != nil {
		log.Printf("proxy: serialize history meta %s: %v", flow.FlowID, err)
		return
	}
	if err := h.storage.Set(historyMetaKey(flow.FlowID), metaData); err != nil {
		log.Printf("proxy: save history meta %s: %v", flow.FlowID, err)
	}
}

// insertOrderLocked inserts e into flowOrder, preserving (timestamp, flowID) ascending order.
// Caller must hold mu.
func (h *HistoryStore) insertOrderLocked(e orderedFlow) {
	idx := sort.Search(len(h.flowOrder), func(i int) bool {
		return !lessOrder(h.flowOrder[i].timestamp, h.flowOrder[i].flowID, e.timestamp, e.flowID)
	})
	h.flowOrder = slices.Insert(h.flowOrder, idx, e)
}

// Get retrieves a flow by flow_id.
func (h *HistoryStore) Get(flowID string) (*types.Flow, bool) {
	data, found, err := h.storage.Get(historyPayloadKey(flowID))
	if err != nil || !found {
		return nil, false
	}
	var flow types.Flow
	if err := store.Deserialize(data, &flow); err != nil {
		return nil, false
	}
	// msgpack timestamps lose timezone info; normalize to UTC
	flow.StartedAt = flow.StartedAt.UTC()
	flow.CompletedAt = flow.CompletedAt.UTC()
	return &flow, true
}

// Children returns the child flows of parentFlowID in emission order.
func (h *HistoryStore) Children(parentFlowID string) []*types.Flow {
	h.mu.RLock()
	childIDs := slices.Clone(h.childOrder[parentFlowID])
	h.mu.RUnlock()

	flows := make([]*types.Flow, 0, len(childIDs))
	for _, fid := range childIDs {
		if f, ok := h.Get(fid); ok {
			flows = append(flows, f)
		}
	}
	return flows
}

// GetMeta retrieves lightweight metadata for an entry by flow_id.
func (h *HistoryStore) GetMeta(flowID string) (*types.HistoryMeta, bool) {
	data, found, err := h.storage.Get(historyMetaKey(flowID))
	if err != nil || !found {
		return nil, false
	}
	var meta types.HistoryMeta
	if err := store.Deserialize(data, &meta); err != nil {
		return nil, false
	}
	meta.Timestamp = meta.Timestamp.UTC()
	return &meta, true
}

// Page returns up to count flows strictly after afterFlowID, ordered oldest-first.
func (h *HistoryStore) Page(count int, afterFlowID string) []*types.Flow {
	if count <= 0 {
		return nil
	}
	flowIDs := h.pageFlowIDs(count, afterFlowID)
	flows := make([]*types.Flow, 0, len(flowIDs))
	for _, fid := range flowIDs {
		if f, ok := h.Get(fid); ok {
			flows = append(flows, f)
		}
	}
	return flows
}

// PageMeta returns up to count meta entries strictly after afterFlowID, ordered oldest-first.
func (h *HistoryStore) PageMeta(count int, afterFlowID string) []types.HistoryMeta {
	if count <= 0 {
		return nil
	}
	flowIDs := h.pageFlowIDs(count, afterFlowID)
	metas := make([]types.HistoryMeta, 0, len(flowIDs))
	for _, fid := range flowIDs {
		if m, ok := h.GetMeta(fid); ok {
			metas = append(metas, *m)
		}
	}
	return metas
}

// pageFlowIDs returns up to count flow IDs after afterFlowID, oldest-first.
// Copies the slice while holding the lock so a concurrent Store cannot realloc the backing array.
func (h *HistoryStore) pageFlowIDs(count int, afterFlowID string) []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var startIdx int
	if afterFlowID != "" {
		if ts, ok := h.timestampByFlow[afterFlowID]; ok {
			startIdx = sort.Search(len(h.flowOrder), func(i int) bool {
				return lessOrder(ts, afterFlowID, h.flowOrder[i].timestamp, h.flowOrder[i].flowID)
			})
		}
	}
	end := min(startIdx+count, len(h.flowOrder))
	if startIdx >= end {
		return nil
	}
	flowIDs := make([]string, 0, end-startIdx)
	for i := startIdx; i < end; i++ {
		flowIDs = append(flowIDs, h.flowOrder[i].flowID)
	}
	return flowIDs
}

// Count returns the number of entries currently stored.
func (h *HistoryStore) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return len(h.flowOrder)
}

// Delete removes entries by flow_id. Idempotent; unknown ids are skipped.
// Returns the number of entries actually removed.
func (h *HistoryStore) Delete(flowIDs ...string) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	var deleted int
	for _, fid := range flowIDs {
		if ts, ok := h.timestampByFlow[fid]; ok {
			// Top-level flow: drop meta, payload, ordering, and its child index
			if err := h.storage.Delete(historyMetaKey(fid)); err != nil {
				log.Printf("proxy: delete history meta %s: %v", fid, err)
				continue
			}
			if err := h.storage.Delete(historyPayloadKey(fid)); err != nil {
				log.Printf("proxy: delete history payload %s: %v", fid, err)
			}
			delete(h.timestampByFlow, fid)
			delete(h.childOrder, fid)
			idx := sort.Search(len(h.flowOrder), func(i int) bool {
				return !lessOrder(h.flowOrder[i].timestamp, h.flowOrder[i].flowID, ts, fid)
			})
			if idx < len(h.flowOrder) && h.flowOrder[idx].flowID == fid {
				h.flowOrder = slices.Delete(h.flowOrder, idx, idx+1)
			}
			deleted++
			continue
		}

		// Child flow (payload-only) or unknown id
		flow, ok := h.Get(fid)
		if !ok {
			continue
		}
		if flow.ParentFlowID != "" {
			siblings := h.childOrder[flow.ParentFlowID]
			if i := slices.Index(siblings, fid); i >= 0 {
				h.childOrder[flow.ParentFlowID] = slices.Delete(siblings, i, i+1)
			}
		}
		delete(h.childOrder, fid) // drop fid's own child index if it nested further
		if err := h.storage.Delete(historyPayloadKey(fid)); err != nil {
			log.Printf("proxy: delete history payload %s: %v", fid, err)
		}
		deleted++
	}
	return deleted
}

// Close closes the underlying storage.
func (h *HistoryStore) Close() {
	_ = h.storage.Close()
}

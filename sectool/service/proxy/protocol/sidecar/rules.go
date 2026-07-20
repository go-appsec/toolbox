package sidecar

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// syncRulesTimeout bounds one sync_rules push, so an unresponsive sidecar can't
// wedge later pushes behind it.
const syncRulesTimeout = 10 * time.Second

// PushRules sends every connected sidecar its current rule snapshot, waiting for
// each to ack.
func (m *Manager) PushRules(ctx context.Context) {
	m.mu.Lock()
	recs := bulk.MapValuesSlice(m.records)
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, rec := range recs {
		wg.Add(1)
		go func(rec *Record) {
			defer wg.Done()
			rec.pushRules(ctx, m.rules)
		}(rec)
	}
	wg.Wait()
}

// pushRules sends the adapter's current rules and waits for the ack, serialized
// against other pushes to this sidecar.
func (r *Record) pushRules(ctx context.Context, src RuleSource) {
	r.pushMu.Lock() // lock order pushMu -> rule store
	defer r.pushMu.Unlock()

	if !r.alive() {
		return
	}
	// read under pushMu so the last push to acquire it carries the newest rules
	rules := src.RuleSnapshot(r.Name)

	ctx, cancel := context.WithTimeout(ctx, syncRulesTimeout)
	defer cancel()
	var res wire.SyncRulesResult
	if rerr := r.peer.Call(ctx, wire.MethodSyncRules, wire.SyncRulesParams{Rules: rules}, &res); rerr != nil {
		// fail open: a sidecar that can't apply rules still captures its traffic
		log.Printf("sidecar[%s]: sync_rules rejected: %s", r.Name, rerr.Message)
	}
}

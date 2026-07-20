package sidecar

import (
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// handleRegister validates and stores a registration, returning the new record
// and the result, or an error.
func (m *Manager) handleRegister(peer *wire.Peer, p *wire.RegisterParams) (*Record, *wire.RegisterResult, *wire.Error) {
	if p.Name == "" {
		return nil, nil, wire.NewError(wire.CodeRegistrationRejected, "register: name is required")
	}
	if p.ProtocolVersion.Major != wire.VersionMajor {
		return nil, nil, wire.NewError(wire.CodeVersionUnsupported,
			fmt.Sprintf("contract major mismatch: sectool %d, sidecar %d", wire.VersionMajor, p.ProtocolVersion.Major)).
			WithData(&wire.ErrorData{Adapter: p.Name})
	}
	if p.ProtocolVersion.Minor > wire.VersionMinor {
		return nil, nil, wire.NewError(wire.CodeVersionUnsupported,
			fmt.Sprintf("contract minor too new: sectool %d.%d, sidecar %d.%d",
				wire.VersionMajor, wire.VersionMinor, p.ProtocolVersion.Major, p.ProtocolVersion.Minor)).
			WithData(&wire.ErrorData{Adapter: p.Name})
	}
	effMinor := p.ProtocolVersion.Minor // Older-or-equal minor is supported
	if effMinor < 0 {
		effMinor = 0
	}
	if p.InstanceID != "" {
		if _, err := uuid.Parse(p.InstanceID); err != nil {
			return nil, nil, wire.NewError(wire.CodeRegistrationRejected, "register: instance_id must be a valid UUID").
				WithData(&wire.ErrorData{Adapter: p.Name})
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var carried *resumeEntry
	if p.InstanceID != "" {
		if st, ok := m.resumeState[p.InstanceID]; ok {
			if p.Resume {
				carried = st
			}
			delete(m.resumeState, p.InstanceID)
		}
	}

	// reconnect or stale record replaces; live record with a different instance conflicts
	if existing, ok := m.records[p.Name]; ok {
		reconnect := p.InstanceID != "" && existing.InstanceID == p.InstanceID
		switch {
		case reconnect:
			if p.Resume && carried == nil {
				carried = &resumeEntry{ownedFlows: existing.ownedFlows, inFlight: existing.inFlight}
			}
			m.removeLocked(existing)
		case !existing.alive():
			m.removeLocked(existing)
		default:
			return nil, nil, wire.NewError(wire.CodeDuplicateRegistration,
				"adapter name already registered: "+p.Name).
				WithData(&wire.ErrorData{Adapter: p.Name, ConflictAdapter: existing.Name})
		}
	}

	if rpcErr := m.checkConflicts(p); rpcErr != nil {
		return nil, nil, rpcErr
	}

	now := m.now()
	rec := &Record{
		Name:         p.Name,
		ProtoVersion: wire.ProtocolVersion{Major: wire.VersionMajor, Minor: effMinor},
		Protocols:    p.Protocols,
		Capabilities: p.Capabilities,
		MCPTools:     p.MCPTools,
		InstanceID:   p.InstanceID,
		peer:         peer,
		resume:       p.Resume,
		liveness:     Liveness{LastPongRecv: now},
	}
	rec.healthy.Store(true)
	rec.bridge = newBridge(rec, m.flows)
	if carried != nil {
		rec.ownedFlows, rec.inFlight = carried.ownedFlows, carried.inFlight
	} else {
		rec.ownedFlows, rec.inFlight = map[string]struct{}{}, map[string]struct{}{}
	}

	m.records[p.Name] = rec
	if p.InstanceID != "" {
		m.byInstance[p.InstanceID] = rec
	}

	instanceTag := p.InstanceID
	if instanceTag == "" {
		instanceTag = "-"
	}
	log.Printf("sidecar[%s]: registered instance_id=%s", p.Name, instanceTag)

	return rec, &wire.RegisterResult{
		ProtocolVersion: rec.ProtoVersion,
		ServerTime:      now.Format(time.RFC3339Nano),
	}, nil
}

// activateClaims opens the claim seam for a freshly registered record. Call once
// the record is seeded, so no stream is routed to a sidecar without its rules.
func (m *Manager) activateClaims(rec *Record) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.records[rec.Name] != rec {
		return // replaced or disconnected while seeding
	}
	if len(rec.Capabilities.EarlyClaims) > 0 {
		m.registry.InsertEarly(rec.bridge)
	}
	if len(rec.Capabilities.UpgradeClaims) > 0 {
		m.reorderUpgradeClaims()
	}
}

// reorderUpgradeClaims re-inserts every upgrade-claiming sidecar bridge so the
// most-specific matchers are evaluated first (ahead of the built-in adapters). A
// record with several upgrade claims is ranked by its most-specific one. Callers
// hold mu.
func (m *Manager) reorderUpgradeClaims() {
	recs := make([]*Record, 0, len(m.records))
	for _, r := range m.records {
		if len(r.Capabilities.UpgradeClaims) > 0 {
			recs = append(recs, r)
		}
	}
	slices.SortStableFunc(recs, func(a, b *Record) int {
		ac, bc := mostSpecificUpgrade(a.Capabilities.UpgradeClaims), mostSpecificUpgrade(b.Capabilities.UpgradeClaims)
		switch {
		case dominates(ac, bc):
			return -1
		case dominates(bc, ac):
			return 1
		default:
			return 0
		}
	})
	for _, r := range recs {
		m.registry.RemoveUpgrade(r.Name)
	}
	// InsertUpgrade prepends: insert least-specific first to leave most-specific at front
	for i := len(recs) - 1; i >= 0; i-- {
		m.registry.InsertUpgrade(recs[i].bridge)
	}
}

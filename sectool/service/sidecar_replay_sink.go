package service

import (
	"bytes"
	"slices"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/ids"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// replayRoutingSink is a sidecar.FlowSink that diverts sidecar-performed replays
// (annotated replay=true) into the ReplayHistoryStore so they report source "replay"
// like native replays; every other flow passes through to proxy history. Its Get
// falls back to the replay store so a chained replay can fetch its source request.
type replayRoutingSink struct {
	history sidecar.FlowSink // the proxy HistoryStore
	replay  *store.ReplayHistoryStore
}

var _ sidecar.FlowSink = (*replayRoutingSink)(nil)

func (s *replayRoutingSink) Store(flow *types.Flow) string {
	if v, _ := flow.Annotations[wire.AnnotationReplay].(bool); v {
		id := ids.Generate(ids.DefaultLength)
		s.replay.Store(flowToReplayEntry(id, flow))
		return id
	}
	return s.history.Store(flow)
}

// Complete attaches a response to an already-stored flow, routing replay-owned
// flow ids (unknown to proxy history) to the replay store.
func (s *replayRoutingSink) Complete(flowID string, resp *types.Message, completedAt time.Time, annotations map[string]any) bool {
	if s.history.Complete(flowID, resp, completedAt, annotations) {
		return true
	}
	var status int
	var respHeaders, respBody []byte
	if resp != nil {
		status = resp.StatusCode
		var buf bytes.Buffer
		respHeaders, respBody = splitHeadersBody((&types.Flow{Response: resp}).FormatResponse(&buf))
		respHeaders = slices.Clone(respHeaders)
		respBody = slices.Clone(respBody)
	}
	return s.replay.Complete(flowID, respHeaders, respBody, status, completedAt)
}

func (s *replayRoutingSink) SetInvokedBy(flowID, invokedBy string) bool {
	return s.history.SetInvokedBy(flowID, invokedBy)
}

func (s *replayRoutingSink) ShouldCapture(flow *types.Flow) bool {
	return s.history.ShouldCapture(flow)
}

// Get resolves a flow from proxy history, falling back to the replay store so a
// chained replay of a sidecar replay can fetch its source request.
func (s *replayRoutingSink) Get(flowID string) (*types.Flow, bool) {
	if f, ok := s.history.Get(flowID); ok {
		return f, true
	}
	if entry, ok := s.replay.Get(flowID); ok {
		if f := replayEntryToFlow(entry); f != nil {
			return f, true
		}
	}
	return nil, false
}

// flowToReplayEntry converts a completed sidecar replay flow into a ReplayHistoryEntry.
func flowToReplayEntry(id string, flow *types.Flow) *store.ReplayHistoryEntry {
	var buf bytes.Buffer
	// FormatRequest/FormatResponse share buf (each Reset()s it), so clone before reuse.
	rawReq := slices.Clone(flow.FormatRequest(&buf))
	method, host, path := extractRequestMeta(string(rawReq))
	respHeaders, respBody := splitHeadersBody(flow.FormatResponse(&buf))

	var duration time.Duration
	if !flow.CompletedAt.IsZero() {
		duration = flow.CompletedAt.Sub(flow.StartedAt)
	}
	var status int
	if flow.Response != nil {
		status = flow.Response.StatusCode
	}

	return &store.ReplayHistoryEntry{
		FlowID:       id,
		CreatedAt:    flow.StartedAt,
		RawRequest:   rawReq,
		Method:       method,
		Host:         host,
		Path:         path,
		Scheme:       flow.Scheme,
		Port:         flow.Port,
		Protocol:     flow.ProtocolTag,
		RespHeaders:  slices.Clone(respHeaders),
		RespBody:     slices.Clone(respBody),
		RespStatus:   status,
		Duration:     duration,
		SourceFlowID: flow.ParentFlowID,
		Annotations:  flow.Annotations,
		InvokedBy:    flow.InvokedBy,
		Adapter:      flow.Adapter,
	}
}

// replayEntryToFlow reconstructs a store Flow from a replay entry so the FlowSink Get
// can serve a chained replay's source lookup; returns nil if the request won't parse.
func replayEntryToFlow(entry *store.ReplayHistoryEntry) *types.Flow {
	parsed, err := proxy.ParseRequest(bytes.NewReader(entry.RawRequest))
	if err != nil {
		return nil
	}
	return &types.Flow{
		FlowID:       entry.FlowID,
		Adapter:      entry.Adapter,
		ProtocolTag:  entry.Protocol,
		ParentFlowID: entry.SourceFlowID,
		Scheme:       entry.Scheme,
		Port:         entry.Port,
		Request:      types.RequestToMessage(parsed),
		StartedAt:    entry.CreatedAt,
		Annotations:  entry.Annotations,
		InvokedBy:    entry.InvokedBy,
	}
}

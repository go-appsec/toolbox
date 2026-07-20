package sidecar

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// FlowSink persists sidecar-emitted flows into sectool's unified history.
// Satisfied by *proxy.HistoryStore.
type FlowSink interface {
	Store(*types.Flow) string
	Complete(flowID string, resp *types.Message, completedAt time.Time, annotations map[string]any) bool
	SetInvokedBy(flowID, invokedBy string) bool
	Get(flowID string) (*types.Flow, bool)
	ShouldCapture(*types.Flow) bool
}

// CoreService dispatches core MCP tools and reports their names.
type CoreService interface {
	// CoreInvoke dispatches a core MCP tool by name.
	CoreInvoke(ctx context.Context, tool string, params json.RawMessage) (content string, isErr bool, err error)
	// CoreToolNames lists core tool names for registration-time collision checks.
	CoreToolNames() []string
}

// RuleSource returns the current rule snapshot for a named adapter.
type RuleSource interface {
	// RuleSnapshot returns the rules scoped to the adapter, in apply order.
	RuleSnapshot(adapter string) []wire.Rule
}

func (s *session) handlePushFlow(p *wire.Flow) (any, *wire.Error) {
	rec := s.record()
	if rec == nil {
		return nil, wire.NewError(wire.CodeNotRegistered, "push_flow: register first")
	}

	// Re-targeting an existing flow: two-phase completion or session/stream teardown
	if p.FlowID != "" {
		if !rec.owns(p.FlowID) {
			return nil, wire.NewError(wire.CodeFlowRejected, "push_flow: flow not owned by adapter").
				WithData(&wire.ErrorData{Adapter: rec.Name, FlowID: p.FlowID})
		} else if !s.m.flows.Complete(p.FlowID, flowMessageToMessage(p.Response), p.CompletedAt, p.Annotations) {
			return nil, wire.NewError(wire.CodeFlowRejected, "push_flow: unknown flow_id").
				WithData(&wire.ErrorData{Adapter: rec.Name, FlowID: p.FlowID})
		}
		rec.markComplete(p.FlowID)
		return wire.PushFlowResult{FlowID: p.FlowID}, nil
	}

	flow := wireFlowToFlow(rec, p, s.m.now())
	if !s.m.flows.ShouldCapture(flow) {
		// excluded by capture filter: empty flow_id signals "not captured"
		return wire.PushFlowResult{}, nil
	}
	flowID := s.m.flows.Store(flow)
	rec.trackOwned(flowID, flow.Response == nil && flow.CompletedAt.IsZero())
	return wire.PushFlowResult{FlowID: flowID}, nil
}

func (s *session) handleCoreInvoke(ctx context.Context, p *wire.CoreInvokeParams) (any, *wire.Error) {
	rec := s.record()
	if rec == nil {
		return nil, wire.NewError(wire.CodeNotRegistered, "core_invoke: register first")
	}
	content, isErr, err := s.m.coreInvoke.CoreInvoke(ctx, p.Tool, p.Params)
	if err != nil {
		return nil, wire.NewError(wire.CodeCoreInvokeRejected, "core_invoke: "+err.Error()).
			WithData(&wire.ErrorData{Adapter: rec.Name})
	}
	return wire.CoreInvokeResult{Content: content, IsError: isErr}, nil
}

func (s *session) handleLog(p *wire.LogParams) {
	level := p.Level
	if level == "" {
		level = "info"
	}
	if len(p.Fields) > 0 {
		log.Printf("sidecar[%s] %s: %s %v", s.adapterName(), level, p.Message, p.Fields)
	} else {
		log.Printf("sidecar[%s] %s: %s", s.adapterName(), level, p.Message)
	}
}

func (s *session) handleReportMetrics(p *wire.ReportMetricsParams) {
	log.Printf("sidecar[%s] metrics: counters=%v gauges=%v", s.adapterName(), p.Counters, p.Gauges)
}

func (s *session) adapterName() string {
	if rec := s.record(); rec != nil {
		return rec.Name
	}
	return "?"
}

// wireFlowToFlow converts a pushed wire flow into a store Flow, stamping the
// emitting adapter's identity.
func wireFlowToFlow(rec *Record, p *wire.Flow, now time.Time) *types.Flow {
	f := &types.Flow{
		Adapter:           rec.Name,
		ProtocolTag:       p.ProtocolTag,
		Direction:         p.Direction,
		ParentFlowID:      p.ParentFlowID,
		Scheme:            p.Scheme,
		Port:              p.Port,
		Request:           flowMessageToMessage(p.Request),
		Response:          flowMessageToMessage(p.Response),
		StartedAt:         p.StartedAt,
		CompletedAt:       p.CompletedAt,
		Annotations:       p.Annotations,
		SidecarInstanceID: rec.InstanceID,
	}
	if f.StartedAt.IsZero() {
		f.StartedAt = now
	}
	return f
}

// flowToWireFlow converts a stored flow into its wire form. Inverse of
// wireFlowToFlow.
func flowToWireFlow(f *types.Flow) *wire.Flow {
	if f == nil {
		return nil
	}
	return &wire.Flow{
		FlowID:       f.FlowID,
		Adapter:      f.Adapter,
		ProtocolTag:  f.ProtocolTag,
		Direction:    f.Direction,
		ParentFlowID: f.ParentFlowID,
		Scheme:       f.Scheme,
		Port:         f.Port,
		Request:      messageToFlowMessage(f.Request),
		Response:     messageToFlowMessage(f.Response),
		StartedAt:    f.StartedAt,
		CompletedAt:  f.CompletedAt,
		Annotations:  f.Annotations,
	}
}

// messageToFlowMessage converts a stored message side into its wire form. Inverse
// of flowMessageToMessage.
func messageToFlowMessage(m *types.Message) *wire.FlowMessage {
	if m == nil {
		return nil
	}
	fm := &wire.FlowMessage{
		Method:     m.Method,
		Path:       m.Path,
		Query:      m.Query,
		StatusCode: m.StatusCode,
		StatusText: m.StatusText,
		Body:       m.Body,
		BodyRaw:    m.BodyRaw,
	}
	if len(m.Headers) > 0 {
		fm.Headers = make([]wire.Header, len(m.Headers))
		for i, h := range m.Headers {
			fm.Headers[i] = wire.Header{Name: h.Name, Value: h.Value}
		}
	}
	if m.BodyCodec != nil {
		fm.BodyCodec = &wire.BodyCodec{Transforms: m.BodyCodec.Transforms, ContentType: m.BodyCodec.ContentType}
	}
	return fm
}

func flowMessageToMessage(m *wire.FlowMessage) *types.Message {
	if m == nil {
		return nil
	}
	// default HTTP version so the envelope serializes a parseable request/status line
	msg := &types.Message{
		Method:     m.Method,
		Path:       m.Path,
		Query:      m.Query,
		Version:    "HTTP/1.1",
		StatusCode: m.StatusCode,
		StatusText: m.StatusText,
		Body:       m.Body,
		BodyRaw:    m.BodyRaw,
	}
	if len(m.Headers) > 0 {
		msg.Headers = make(types.Headers, len(m.Headers))
		for i, h := range m.Headers {
			msg.Headers[i] = types.Header{Name: h.Name, Value: h.Value}
		}
	}
	if m.BodyCodec != nil {
		msg.BodyCodec = &types.BodyCodec{Transforms: m.BodyCodec.Transforms, ContentType: m.BodyCodec.ContentType}
	}
	return msg
}

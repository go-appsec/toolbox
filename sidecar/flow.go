package sidecar

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// PushFlow emits a captured flow and returns the flow_id sectool assigned. Leave
// flow.FlowID empty on first emission; set it to re-target an existing flow for
// two-phase completion or session/stream teardown. A returned empty flow_id (with
// no error) means the flow was excluded by the operator's capture filter and not
// stored; do not attempt two-phase completion against it.
func (c *Conn) PushFlow(ctx context.Context, flow wire.Flow) (string, error) {
	// replay sink needs a response to record single-phase
	if flow.FlowID == "" && flow.Response == nil {
		if replay, _ := flow.Annotations[wire.AnnotationReplay].(bool); replay {
			flow.Response = &wire.FlowMessage{StatusCode: http.StatusNoContent, StatusText: "No Content"}
		}
	}
	var res wire.PushFlowResult
	if rpcErr := c.peer.Call(ctx, wire.MethodPushFlow, flow, &res); rpcErr != nil {
		return "", rpcErr
	}
	return res.FlowID, nil
}

// Annotation keys and phase values for captured/mutated audit pairs.
const (
	annotationPhase        = "phase"
	annotationFiredRules   = "fired_rules"
	annotationParentFlowID = "parent_flow_id"
	phaseCaptured          = "captured"
	phaseMutated           = "mutated"
)

// EmitMutatedPair emits the captured (pre-mutation) and mutated (post-mutation) audit
// pair for a message a rule changed on the hot path, returning the assigned flow ids.
// The captured flow is tagged phase=captured, the mutated flow phase=mutated with a
// parent_flow_id link back; any structural ParentFlowID on the inputs is preserved.
func (c *Conn) EmitMutatedPair(ctx context.Context, captured, mutated wire.Flow, firedRules []string) (capturedID, mutatedID string, err error) {
	if captured.Annotations == nil {
		captured.Annotations = map[string]any{}
	}
	captured.Annotations[annotationPhase] = phaseCaptured
	capturedID, err = c.PushFlow(ctx, captured)
	if err != nil {
		return "", "", err
	}

	if mutated.Annotations == nil {
		mutated.Annotations = map[string]any{}
	}
	mutated.Annotations[annotationPhase] = phaseMutated
	mutated.Annotations[annotationFiredRules] = firedRules
	if capturedID != "" {
		mutated.Annotations[annotationParentFlowID] = capturedID
	}
	mutatedID, err = c.PushFlow(ctx, mutated)
	if err != nil {
		return capturedID, "", err
	}
	return capturedID, mutatedID, nil
}

// CompleteFlow attaches a late response and/or completion to flowID: the
// two-phase form for deferred responses and session/stream teardown.
func (c *Conn) CompleteFlow(ctx context.Context, flowID string, resp *wire.FlowMessage, completedAt time.Time) error {
	_, err := c.PushFlow(ctx, wire.Flow{FlowID: flowID, Response: resp, CompletedAt: completedAt})
	return err
}

// Log emits a structured diagnostic log line.
func (c *Conn) Log(level, message string, fields map[string]any) error {
	return c.peer.Notify(wire.MethodLog, wire.LogParams{Level: level, Message: message, Fields: fields})
}

// ReportMetrics emits counter and gauge samples.
func (c *Conn) ReportMetrics(counters map[string]int64, gauges map[string]float64) error {
	return c.peer.Notify(wire.MethodReportMetrics, wire.ReportMetricsParams{Counters: counters, Gauges: gauges})
}

// CoreInvoke invokes a core MCP tool by name and returns its result.
func (c *Conn) CoreInvoke(ctx context.Context, tool string, params any) (wire.CoreInvokeResult, error) {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return wire.CoreInvokeResult{}, err
		}
		raw = b
	}
	var res wire.CoreInvokeResult
	if rpcErr := c.peer.Call(ctx, wire.MethodCoreInvoke, wire.CoreInvokeParams{Tool: tool, Params: raw}, &res); rpcErr != nil {
		return wire.CoreInvokeResult{}, rpcErr
	}
	return res, nil
}

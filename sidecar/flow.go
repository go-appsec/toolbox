package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// ErrEmptyFlowID is returned by CompleteFlow for an empty flowID.
var ErrEmptyFlowID = errors.New("sidecar: CompleteFlow requires a non-empty flow_id")

// PushFlow emits a captured flow and returns the flow_id sectool assigned. Leave flow.FlowID empty to
// store a new flow, or set it to re-target an existing flow. On success with captured false the
// operator's capture filter excluded the flow: nothing was stored and flowID is empty. Never pass
// that empty id onward as a parent_flow_id, CompleteFlow target, or state key.
func (c *Conn) PushFlow(ctx context.Context, flow wire.Flow) (flowID string, captured bool, err error) {
	var res wire.PushFlowResult
	if rpcErr := c.peer.Call(ctx, wire.MethodPushFlow, flow, &res); rpcErr != nil {
		return "", false, rpcErr
	}
	return res.FlowID, res.FlowID != "", nil
}

// CompleteFlow attaches a late response and/or completion to flowID: the
// two-phase form for deferred responses and session/stream teardown. flowID must
// be a non-empty id from a captured PushFlow. An empty one errors with
// ErrEmptyFlowID instead of storing a junk flow.
func (c *Conn) CompleteFlow(ctx context.Context, flowID string, resp *wire.FlowMessage, completedAt time.Time) error {
	if flowID == "" {
		return ErrEmptyFlowID
	}
	_, _, err := c.PushFlow(ctx, wire.Flow{FlowID: flowID, Response: resp, CompletedAt: completedAt})
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

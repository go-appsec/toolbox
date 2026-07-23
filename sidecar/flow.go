package sidecar

import (
	"context"
	"encoding/json"
	"time"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// PushFlow emits a captured flow and returns the flow_id sectool assigned. Leave flow.FlowID empty to
// store a new flow, or set it to re-target an existing flow. A returned empty flow_id with no error
// means the operator's capture filter excluded the flow; it was not stored and cannot be re-targeted.
func (c *Conn) PushFlow(ctx context.Context, flow wire.Flow) (string, error) {
	var res wire.PushFlowResult
	if rpcErr := c.peer.Call(ctx, wire.MethodPushFlow, flow, &res); rpcErr != nil {
		return "", rpcErr
	}
	return res.FlowID, nil
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

package sidecar

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// invokeToolTimeout bounds a delegated tool call, which may do real work.
const invokeToolTimeout = 60 * time.Second

// AdapterTools returns each healthy adapter's MCP tools keyed by adapter name,
// as a single consistent snapshot.
func (m *Manager) AdapterTools() map[string][]wire.MCPTool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]wire.MCPTool, len(m.records))
	for _, r := range m.records {
		if r.Healthy() {
			out[r.Name] = slices.Clone(r.MCPTools)
		}
	}
	return out
}

// InvokeTool delegates a sidecar-registered tool call to its owning adapter and
// returns the tool's result.
func (m *Manager) InvokeTool(ctx context.Context, name string, args json.RawMessage) (wire.InvokeToolResult, *wire.Error) {
	m.mu.Lock()
	var rec *Record
	for _, r := range m.records {
		if !r.Healthy() {
			continue
		}
		if slices.ContainsFunc(r.MCPTools, func(t wire.MCPTool) bool { return t.Name == name }) {
			rec = r
			break
		}
	}
	m.mu.Unlock()
	if rec == nil {
		return wire.InvokeToolResult{}, wire.NewError(wire.CodeUnknownDestAdapter, "invoke_tool: unknown tool: "+name)
	}
	ctx, cancel := context.WithTimeout(ctx, invokeToolTimeout)
	defer cancel()
	var res wire.InvokeToolResult
	if rpcErr := rec.peer.Call(ctx, wire.MethodInvokeTool, wire.InvokeToolParams{Name: name, Arguments: args}, &res); rpcErr != nil {
		return wire.InvokeToolResult{}, rpcErr
	}
	return res, nil
}

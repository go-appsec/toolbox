package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/go-analyze/bulk"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// syncSidecarTools recomposes the advertised tool list to match the connected
// adapter set: every connected sidecar's tools are registered, disconnected ones
// removed, and the core tools gain sidecar-conditional params (proxy_poll
// adapter/protocol_tag, proxy_rule_add adapter) while any sidecar is connected.
// With none connected the surface returns to the core baseline. It is invoked
// whenever the registry changes; serialized so concurrent changes converge.
func (m *mcpServer) syncSidecarTools() {
	mgr := m.sidecars
	if mgr == nil {
		return
	}
	m.sidecarMu.Lock()
	defer m.sidecarMu.Unlock()

	byAdapter := mgr.AdapterTools()
	names := bulk.MapKeysSlice(byAdapter)
	slices.Sort(names)

	desired := make(map[string]struct{})
	var add []server.ServerTool
	for _, adapter := range names {
		for _, tool := range byAdapter[adapter] {
			desired[tool.Name] = struct{}{}
			schemaRaw := tool.InputSchema
			if len(schemaRaw) == 0 {
				schemaRaw = json.RawMessage(`{"type":"object"}`)
			}
			schema, err := compileToolSchema(schemaRaw)
			if err != nil {
				// Expose the tool but skip validation when its schema does not compile
				log.Printf("sidecar tool %q (%s): input_schema does not compile: %v", tool.Name, adapter, err)
			}
			add = append(add, server.ServerTool{
				Tool:    sidecarToolDef(tool, schemaRaw),
				Handler: m.delegateSidecarTool(tool.Name, schema),
			})
		}
	}
	if len(add) > 0 {
		m.server.AddTools(add...)
	}
	for name := range m.sidecarToolNames {
		if _, ok := desired[name]; !ok {
			m.server.DeleteTools(name)
		}
	}
	m.sidecarToolNames = desired

	switch {
	case len(names) > 0:
		pollParams := []mcp.ToolOption{
			mcp.WithString("adapter", mcp.Description("Filter by emitting adapter name glob (*, ?), e.g. 'sectool' or a sidecar name")),
			mcp.WithString("protocol_tag", mcp.Description("Filter by protocol tag glob (*, ?), e.g. 'http/1.1' or 'mqtt/3.publish'")),
		}
		ruleParam := mcp.WithString("adapter", mcp.Description(fmt.Sprintf(
			"Adapter scope: empty applies to all adapters; %q targets the in-process proxy and Burp; or a sidecar name (%s)",
			types.AdapterScopeCore, strings.Join(names, ", "))))
		m.server.AddTool(m.proxyPollTool(pollParams...), m.handleProxyPoll)
		m.server.AddTool(m.proxyRuleAddTool(ruleParam), m.handleProxyRuleAdd)
		m.sidecarCoreParams = true
	case m.sidecarCoreParams:
		// last sidecar disconnected: restore the byte-identical core schema
		m.server.AddTool(m.proxyPollTool(), m.handleProxyPoll)
		m.server.AddTool(m.proxyRuleAddTool(), m.handleProxyRuleAdd)
		m.sidecarCoreParams = false
	}
}

// delegateSidecarTool returns a handler that validates the client arguments
// against the tool's schema and delegates the call to the owning sidecar.
func (m *mcpServer) delegateSidecarTool(name string, schema *jsonschema.Schema) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if r := m.requireWorkflow(); r != nil {
			return r, nil
		}
		args, err := json.Marshal(req.GetArguments())
		if err != nil {
			return errorResultFromErr("invalid arguments", err), nil
		}
		if schema != nil {
			inst, ierr := jsonschema.UnmarshalJSON(bytes.NewReader(args))
			if ierr != nil {
				return errorResultFromErr("invalid arguments", ierr), nil
			}
			if verr := schema.Validate(inst); verr != nil {
				return errorResultFromErr("invalid arguments", verr), nil
			}
		}
		res, rpcErr := m.sidecars.InvokeTool(ctx, name, args)
		if rpcErr != nil {
			return errorResult(rpcErr.Error()), nil
		}
		return sidecarToolResult(res), nil
	}
}

// sidecarToolDef builds an MCP tool definition from a sidecar's declaration,
// carrying its raw input_schema and optional annotations verbatim.
func sidecarToolDef(t wire.MCPTool, schemaRaw json.RawMessage) mcp.Tool {
	out := mcp.Tool{
		Name:           t.Name,
		Description:    t.Description,
		RawInputSchema: schemaRaw,
	}
	if len(t.Annotations) > 0 {
		_ = json.Unmarshal(t.Annotations, &out.Annotations)
	}
	return out
}

// sidecarToolResult converts a sidecar tool result into an MCP result, returning
// its text and optional structured content to the client verbatim.
func sidecarToolResult(res wire.InvokeToolResult) *mcp.CallToolResult {
	out := mcp.NewToolResultText(res.Content)
	if len(res.StructuredContent) > 0 {
		var sc any
		if err := json.Unmarshal(res.StructuredContent, &sc); err == nil {
			out.StructuredContent = sc
		}
	}
	out.IsError = res.IsError
	return out
}

// compileToolSchema compiles a JSON Schema for argument validation.
func compileToolSchema(raw json.RawMessage) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("tool.json", doc); err != nil {
		return nil, err
	}
	return c.Compile("tool.json")
}

// sidecarToolsSection lists connected sidecars' tools for the workflow
// instructions, or empty when none are registered.
func (m *mcpServer) sidecarToolsSection() string {
	mgr := m.sidecars
	if mgr == nil {
		return ""
	}
	byAdapter := mgr.AdapterTools()
	names := bulk.MapKeysSlice(byAdapter)
	slices.Sort(names)
	var b strings.Builder
	for _, adapter := range names {
		for _, tool := range byAdapter[adapter] {
			if b.Len() == 0 {
				b.WriteString("\n\n## Sidecar Tools\n\nProtocol adapters contribute these tools:\n")
			}
			fmt.Fprintf(&b, "- %s (%s): %s\n", tool.Name, adapter, tool.Description)
		}
	}
	return b.String()
}

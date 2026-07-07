package sidecar

import (
	"errors"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// Registration declares the adapter's identity and capabilities for the register handshake.
type Registration struct {
	Name         string
	Protocols    []string
	Capabilities wire.Capabilities
	MCPTools     []wire.MCPTool
	InstanceID   string
	Resume       bool
	// ProtocolVersion defaults to the SDK's compiled contract version when left zero.
	ProtocolVersion wire.ProtocolVersion
}

func (r Registration) toParams() wire.RegisterParams {
	pv := r.ProtocolVersion
	if pv.Major == 0 && pv.Minor == 0 {
		pv = wire.ProtocolVersion{Major: wire.VersionMajor, Minor: wire.VersionMinor}
	}
	return wire.RegisterParams{
		Name:            r.Name,
		ProtocolVersion: pv,
		Protocols:       r.Protocols,
		Capabilities:    r.Capabilities,
		MCPTools:        r.MCPTools,
		InstanceID:      r.InstanceID,
		Resume:          r.Resume,
	}
}

// Handler is the sidecar's inbound callback surface. Embed BaseHandler to get
// no-op defaults and override only the callbacks the adapter implements.
type Handler interface {
	// --- Lifecycle ---

	// OnShutdown is invoked when sectool requests a graceful close. The SDK
	// acknowledges automatically after this returns, so the sidecar should
	// finish in-flight work here before returning.
	OnShutdown(drainSeconds int)

	// --- Byte stream (early_claim adapters) ---

	// OnStreamOpen and OnStreamDeliver receive the claimed stream's events and
	// return bytes for sectool to write back (possibly to a different stream_id).
	// Inbound chunks are raw transport bytes, not aligned to protocol frames; use
	// Reassembler to accumulate complete frames. OnStreamEnded reports teardown.
	OnStreamOpen(wire.StreamOpenParams) ([]wire.StreamWrite, error)
	OnStreamDeliver(wire.StreamWriteParams) ([]wire.StreamWrite, error)
	OnStreamEnded(wire.StreamEndedParams)

	// OnClaimProbe decides a probe-based early_claim: true takes the connection,
	// false declines so sectool tries the next claim (or falls through to HTTP).
	// An error is reported as a probe fault and declines.
	OnClaimProbe(wire.ClaimProbeParams) (bool, error)

	// --- Request / origination ---

	// OnSidecarSend serves both replay of the adapter's own flows and origination
	// (injection_target), returning the produced flow ids.
	OnSidecarSend(wire.SidecarSendParams) (wire.SidecarSendResult, error)

	// OnInvokeTool handles a validated MCP tool call (Registration.MCPTools)
	// delegated from a client and returns the result content. The handler may
	// read sectool state (Conn.CoreInvoke) and emit flows (Conn.PushFlow).
	OnInvokeTool(wire.InvokeToolParams) (wire.InvokeToolResult, error)
}

// BaseHandler provides no-op/decline defaults for every Handler callback. Embed
// it and override only the callbacks the adapter supports.
type BaseHandler struct{}

func (BaseHandler) OnShutdown(int) {}

func (BaseHandler) OnStreamOpen(wire.StreamOpenParams) ([]wire.StreamWrite, error) {
	return nil, nil
}

func (BaseHandler) OnStreamDeliver(wire.StreamWriteParams) ([]wire.StreamWrite, error) {
	return nil, nil
}

func (BaseHandler) OnStreamEnded(wire.StreamEndedParams) {}

func (BaseHandler) OnClaimProbe(wire.ClaimProbeParams) (bool, error) { return false, nil }

func (BaseHandler) OnSidecarSend(wire.SidecarSendParams) (wire.SidecarSendResult, error) {
	return wire.SidecarSendResult{}, errors.New("sidecar_send: not implemented")
}

func (BaseHandler) OnInvokeTool(wire.InvokeToolParams) (wire.InvokeToolResult, error) {
	return wire.InvokeToolResult{}, errors.New("invoke_tool: not implemented")
}

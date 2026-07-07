package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// ErrVersionUnsupported is returned by Dial when sectool rejects the
// registration because the sidecar's contract version is unsupported.
var ErrVersionUnsupported = errors.New("sidecar: protocol version unsupported")

// registerTimeout bounds the registration handshake.
const registerTimeout = 10 * time.Second

// Conn is a registered connection to sectool.
type Conn struct {
	peer  *wire.Peer
	name  string
	rules *RuleCache

	mu      sync.Mutex
	handler Handler
}

// Dial connects to sectool at addr, performs the register handshake, and returns
// the established connection.
func Dial(addr string, reg Registration) (*Conn, error) {
	network := networkFor(addr)
	raw, err := net.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("sidecar: dial %s %s: %w", network, addr, err)
	}

	c := &Conn{handler: BaseHandler{}, name: reg.Name, rules: &RuleCache{adapter: reg.Name}}
	c.peer = wire.NewPeer(raw, connHandler{c})
	go func() { _ = c.peer.Run(context.Background()) }()

	ctx, cancel := context.WithTimeout(context.Background(), registerTimeout)
	defer cancel()
	var result wire.RegisterResult
	if rpcErr := c.peer.Call(ctx, wire.MethodRegister, reg.toParams(), &result); rpcErr != nil {
		_ = c.peer.Close()
		if rpcErr.Code == wire.CodeVersionUnsupported {
			return nil, fmt.Errorf("%w: %s", ErrVersionUnsupported, rpcErr.Message)
		}
		return nil, fmt.Errorf("sidecar: register: %w", rpcErr)
	}

	_ = c.rules.replace(0, result.RulesSnapshot)
	return c, nil
}

// Serve installs the inbound handler and blocks until ctx is cancelled or the
// connection closes (e.g. after sectool's shutdown). Returns ctx.Err() on
// cancellation, nil on a clean remote close.
func (c *Conn) Serve(ctx context.Context, h Handler) error {
	if h == nil {
		h = BaseHandler{}
	}
	c.mu.Lock()
	c.handler = h
	c.mu.Unlock()

	select {
	case <-ctx.Done():
		_ = c.peer.Close()
		return ctx.Err()
	case <-c.peer.Done():
		return nil
	}
}

// Rules returns the hot-path rule cache, kept current by sectool's sync_rules pushes.
func (c *Conn) Rules() *RuleCache { return c.rules }

// Close terminates the connection.
func (c *Conn) Close() error { return c.peer.Close() }

func (c *Conn) currentHandler() Handler {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.handler
}

// connHandler routes inbound traffic to the user handler.
type connHandler struct{ c *Conn }

func (h connHandler) HandleRequest(_ context.Context, method string, params json.RawMessage) (any, *wire.Error) {
	handler := h.c.currentHandler()
	switch method {
	case wire.MethodShutdown:
		var p wire.ShutdownParams
		_ = json.Unmarshal(params, &p)
		handler.OnShutdown(p.DrainSeconds)
		return wire.ShutdownResult{Ack: true}, nil
	case wire.MethodStreamOpen:
		var p wire.StreamOpenParams
		_ = json.Unmarshal(params, &p)
		writes, err := handler.OnStreamOpen(p)
		if err != nil {
			return nil, wire.NewError(wire.CodeTransportInternal, err.Error())
		}
		return wire.StreamResult{Writes: writes}, nil
	case wire.MethodStreamDeliver:
		var p wire.StreamWriteParams
		_ = json.Unmarshal(params, &p)
		writes, err := handler.OnStreamDeliver(p)
		if err != nil {
			return nil, wire.NewError(wire.CodeTransportInternal, err.Error())
		}
		return wire.StreamResult{Writes: writes}, nil
	case wire.MethodClaimProbe:
		var p wire.ClaimProbeParams
		_ = json.Unmarshal(params, &p)
		claim, err := handler.OnClaimProbe(p)
		if err != nil {
			return nil, wire.NewError(wire.CodeClaimProbeFault, "claim_probe: "+err.Error())
		}
		return wire.ClaimProbeResult{Claim: claim}, nil
	case wire.MethodSyncRules:
		var p wire.SyncRulesParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, wire.NewError(wire.CodeRuleRejected, "sync_rules: invalid params")
		}
		if err := h.c.rules.replace(p.SnapshotVersion, p.Rules); err != nil {
			return nil, wire.NewError(wire.CodeRuleRejected, "sync_rules: "+err.Error())
		}
		return wire.SyncRulesResult{Ack: true, AppliedVersion: p.SnapshotVersion}, nil
	case wire.MethodSidecarSend:
		var p wire.SidecarSendParams
		_ = json.Unmarshal(params, &p)
		res, err := handler.OnSidecarSend(p)
		if err != nil {
			return nil, wire.NewError(wire.CodeTransportInternal, "sidecar_send: "+err.Error())
		}
		return res, nil
	case wire.MethodInvokeTool:
		var p wire.InvokeToolParams
		_ = json.Unmarshal(params, &p)
		res, err := handler.OnInvokeTool(p)
		if err != nil {
			return nil, wire.NewError(wire.CodeTransportInternal, "invoke_tool: "+err.Error())
		}
		return res, nil
	case wire.MethodPing:
		return struct{}{}, nil
	default:
		return nil, wire.NewError(-32601, "method not found: "+method)
	}
}

func (h connHandler) HandleNotification(_ context.Context, method string, params json.RawMessage) {
	switch method {
	case wire.MethodPing:
		_ = h.c.peer.Notify(wire.MethodPong, nil)
	case wire.MethodStreamEnded:
		var p wire.StreamEndedParams
		_ = json.Unmarshal(params, &p)
		h.c.currentHandler().OnStreamEnded(p)
	}
}

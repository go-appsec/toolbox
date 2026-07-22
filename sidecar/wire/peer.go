package wire

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ErrPeerClosed is returned when an operation is attempted on a closed peer.
var ErrPeerClosed = errors.New("sidecar: peer closed")

// writeTimeout bounds one frame write, so a peer that stops reading can't wedge
// every other sender behind the write lock.
const writeTimeout = 20 * time.Second

// notifyQueue bounds the inbound notifications waiting on the dispatch goroutine.
const notifyQueue = 128

// Handler processes inbound requests and notifications from the remote peer.
// HandleRequest returns either a result (marshaled to the JSON-RPC response) or
// an *Error. HandleNotification has no reply.
type Handler interface {
	HandleRequest(ctx context.Context, method string, params json.RawMessage) (any, *Error)
	HandleNotification(ctx context.Context, method string, params json.RawMessage)
}

// HandlerFuncs adapts ordinary functions to the Handler interface. A nil
// Request function replies "method not found"; a nil Notification is a no-op.
type HandlerFuncs struct {
	Request      func(ctx context.Context, method string, params json.RawMessage) (any, *Error)
	Notification func(ctx context.Context, method string, params json.RawMessage)
}

func (h HandlerFuncs) HandleRequest(ctx context.Context, method string, params json.RawMessage) (any, *Error) {
	if h.Request == nil {
		return nil, NewError(-32601, "method not found: "+method)
	}
	return h.Request(ctx, method, params)
}

func (h HandlerFuncs) HandleNotification(ctx context.Context, method string, params json.RawMessage) {
	if h.Notification != nil {
		h.Notification(ctx, method, params)
	}
}

// Peer is a both-directions JSON-RPC 2.0 endpoint over one length-prefixed
// stream. Either side may issue Requests (Call) and Notifications (Notify).
// Inbound notifications are handled one at a time in the order they arrive, so a
// HandleNotification implementation must return promptly. Requests are handled
// concurrently and responses are delivered as soon as they are read.
type Peer struct {
	rw       net.Conn
	h        Handler
	writeMu  sync.Mutex
	nextID   atomic.Uint64
	pending  sync.Map // uint64 -> chan *Message
	notifyCh chan *Message
	closed   atomic.Bool
	done     chan struct{}
}

// NewPeer wraps conn with the given inbound Handler. Call Run to start the reader.
func NewPeer(conn net.Conn, h Handler) *Peer {
	if h == nil {
		h = HandlerFuncs{}
	}
	return &Peer{rw: conn, h: h, notifyCh: make(chan *Message, notifyQueue), done: make(chan struct{})}
}

// SetHandler swaps the inbound handler. Safe to call before Run starts handling
// traffic (e.g. between Dial's handshake and Serve).
func (p *Peer) SetHandler(h Handler) {
	if h == nil {
		h = HandlerFuncs{}
	}
	p.h = h
}

// Run reads and dispatches messages until the connection closes or errors.
// Returns nil on a clean close (local Close or remote EOF), otherwise the read
// error.
func (p *Peer) Run(ctx context.Context) error {
	go p.dispatchNotifications(ctx)
	for {
		payload, err := ReadFrame(p.rw)
		if err != nil {
			wasClosed := p.closed.Load()
			_ = p.closeWithErr()
			if wasClosed || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		var msg Message
		if err := json.Unmarshal(payload, &msg); err != nil {
			continue // skip malformed frame; well-behaved peers do not send these
		}
		switch {
		case msg.IsResponse():
			p.deliverResponse(&msg)
		case msg.IsRequest():
			// dispatch on a fresh goroutine so a handler awaiting a nested Call never blocks the reader
			m := msg
			go p.dispatchRequest(ctx, &m)
		case msg.IsNotification():
			// queued for a single consumer so stream writes keep the order they were sent
			m := msg
			select {
			case p.notifyCh <- &m:
			case <-p.done:
			}
		}
	}
}

// dispatchNotifications handles queued notifications in arrival order, keeping the
// read loop free.
func (p *Peer) dispatchNotifications(ctx context.Context) {
	for {
		select {
		case msg := <-p.notifyCh:
			p.h.HandleNotification(ctx, msg.Method, msg.Params)
		case <-p.done:
			return
		}
	}
}

func (p *Peer) deliverResponse(msg *Message) {
	id, err := strconv.ParseUint(string(msg.ID), 10, 64)
	if err != nil {
		return
	}
	if ch, ok := p.pending.LoadAndDelete(id); ok {
		ch.(chan *Message) <- msg // buffered cap 1; never blocks
	}
}

func (p *Peer) dispatchRequest(ctx context.Context, msg *Message) {
	result, rpcErr := p.h.HandleRequest(ctx, msg.Method, msg.Params)
	resp := &Message{JSONRPC: JSONRPCVersion, ID: msg.ID}
	if rpcErr != nil {
		resp.Error = rpcErr
	} else if raw, err := json.Marshal(result); err != nil {
		resp.Error = NewError(-32603, "marshal result: "+err.Error())
	} else {
		resp.Result = raw
	}
	_ = p.writeMessage(resp)
}

func (p *Peer) writeMessage(msg *Message) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if p.closed.Load() {
		return ErrPeerClosed
	}
	_ = p.rw.SetWriteDeadline(time.Now().Add(writeTimeout))
	defer func() { _ = p.rw.SetWriteDeadline(time.Time{}) }()
	if err := WriteFrame(p.rw, payload); err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// peer stopped reading: close so every other sender and pending caller wakes
			_ = p.closeWithErr()
		}
		return err
	}
	return nil
}

// Call issues a request and blocks until the response arrives, ctx is cancelled,
// or the peer closes. params and result may be nil. A non-nil return is the
// remote *Error or a transport-level *Error.
func (p *Peer) Call(ctx context.Context, method string, params, result any) *Error {
	if p.closed.Load() {
		return NewError(CodeTransportInternal, "peer closed")
	}
	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return NewError(CodeTransportInternal, "marshal params: "+err.Error())
		}
		rawParams = b
	}
	id := p.nextID.Add(1)
	ch := make(chan *Message, 1)
	p.pending.Store(id, ch)
	defer p.pending.Delete(id)

	req := &Message{
		JSONRPC: JSONRPCVersion,
		ID:      json.RawMessage(strconv.FormatUint(id, 10)),
		Method:  method,
		Params:  rawParams,
	}
	if err := p.writeMessage(req); err != nil {
		return NewError(CodeTransportInternal, "write request: "+err.Error())
	}

	select {
	case <-ctx.Done():
		return NewError(CodeTransportInternal, "context done: "+ctx.Err().Error())
	case <-p.done:
		return NewError(CodeTransportInternal, "peer closed")
	case resp := <-ch:
		if resp.Error != nil {
			return resp.Error
		}
		if result != nil && len(resp.Result) > 0 {
			if err := json.Unmarshal(resp.Result, result); err != nil {
				return NewError(CodeTransportInternal, "unmarshal result: "+err.Error())
			}
		}
		return nil
	}
}

// Notify sends a fire-and-forget notification.
func (p *Peer) Notify(method string, params any) error {
	var rawParams json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		rawParams = b
	}
	return p.writeMessage(&Message{JSONRPC: JSONRPCVersion, Method: method, Params: rawParams})
}

// Done returns a channel closed when the peer closes.
func (p *Peer) Done() <-chan struct{} { return p.done }

// Closed reports whether the peer has been closed.
func (p *Peer) Closed() bool { return p.closed.Load() }

// Close closes the underlying connection and wakes any pending callers.
func (p *Peer) Close() error { return p.closeWithErr() }

func (p *Peer) closeWithErr() error {
	if p.closed.Swap(true) {
		return nil
	}
	close(p.done)
	return p.rw.Close()
}

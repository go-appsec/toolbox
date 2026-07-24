package sidecar

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// CloseStream proactively closes an open stream (client-facing or a dialed upstream).
// It closes after the writes already sent for that stream, or immediately when abort
// drops them. It is the companion to the stream events delivered to a Handler.
func (c *Conn) CloseStream(streamID, reason string, abort bool) error {
	return c.peer.Notify(wire.MethodCloseStream, wire.StreamEndedParams{StreamID: streamID, Reason: reason, Abort: abort})
}

// StreamWrite proactively writes bytes to an open stream without a triggering event,
// for keepalives and output produced by a synchronous state machine. Bytes reach the
// stream in send order, including against writes returned from stream events.
func (c *Conn) StreamWrite(streamID string, data []byte) error {
	return c.peer.Notify(wire.MethodStreamWrite, wire.StreamWriteParams{StreamID: streamID, Data: data})
}

// Forward builds the writes for a stream event Response that send data out a paired stream.
func Forward(toStreamID string, data []byte) []wire.StreamWrite {
	return []wire.StreamWrite{{StreamID: toStreamID, Data: data}}
}

// sendWrites emits a handler's writes as stream_write notifications so they share
// the ordered path with proactive writes, and replies naming the streams touched.
func (c *Conn) sendWrites(writes []wire.StreamWrite) (any, *wire.Error) {
	wroteTo := make([]string, 0, len(writes))
	for _, w := range writes {
		if err := c.peer.Notify(wire.MethodStreamWrite, wire.StreamWriteParams(w)); err != nil {
			return nil, wire.NewError(wire.CodeTransportInternal, "stream_write: "+err.Error())
		}
		wroteTo = append(wroteTo, w.StreamID)
	}
	return wire.StreamResult{WroteTo: wroteTo}, nil
}

// StreamConn is a net.Conn over one claimed byte stream, so a blocking library state machine can
// run unmodified atop the async stream events. Read returns bytes delivered by stream_deliver.
// Write and Close emit stream_write and close_stream. Obtain one from a StreamRouter.
type StreamConn struct {
	conn     *Conn
	streamID string
	open     wire.StreamOpenParams

	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	ended  bool // stream_ended seen, no more inbound bytes
	closed bool // Close called locally, or the transport dropped

	// read deadline, guarded by mu so a blocked Read and the timer never race a wakeup
	readPast  bool
	readGen   int
	readTimer *time.Timer
	// write deadline; Write never blocks, so a stored time suffices
	writeAt time.Time
}

// newStreamConn builds a StreamConn for a freshly opened stream.
func newStreamConn(conn *Conn, open wire.StreamOpenParams) *StreamConn {
	c := &StreamConn{conn: conn, streamID: open.StreamID, open: open}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// StreamID returns the stream's identifier.
func (c *StreamConn) StreamID() string { return c.streamID }

// Open returns the stream_open params: host, path, peer, and (upgrade claims only)
// the triggering request's flow id and headers.
func (c *StreamConn) Open() wire.StreamOpenParams { return c.open }

// deliver appends inbound bytes and wakes a blocked Read.
func (c *StreamConn) deliver(data []byte) {
	c.mu.Lock()
	if !c.ended && !c.closed {
		c.buf = append(c.buf, data...)
	}
	c.cond.Broadcast()
	c.mu.Unlock()
}

// end marks the stream drained after stream_ended and wakes readers.
func (c *StreamConn) end() {
	c.mu.Lock()
	c.stopReadTimer()
	c.ended = true
	c.cond.Broadcast()
	c.mu.Unlock()
}

// markClosed transitions to closed and wakes readers, reporting whether this call
// performed the transition. It does not notify sectool; callers hold no lock.
func (c *StreamConn) markClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	c.stopReadTimer()
	c.closed = true
	c.cond.Broadcast()
	return true
}

// stopReadTimer cancels a pending read-deadline timer; caller holds mu.
func (c *StreamConn) stopReadTimer() {
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
}

// Read drains delivered bytes, blocking until data arrives, the stream ends, the
// conn is closed, or the read deadline fires.
func (c *StreamConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if len(c.buf) > 0 {
			n := copy(p, c.buf)
			c.buf = c.buf[n:]
			return n, nil
		}
		if c.closed {
			return 0, io.ErrClosedPipe
		}
		if c.ended {
			return 0, io.EOF
		}
		if c.readPast {
			return 0, os.ErrDeadlineExceeded
		}
		c.cond.Wait()
	}
}

// Write sends bytes out the stream via stream_write, sharing the ordered write
// path with event-driven writes. A nil error means the bytes were accepted for
// delivery, not that they reached the socket.
func (c *StreamConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	closed := c.closed
	past := !c.writeAt.IsZero() && !time.Now().Before(c.writeAt)
	c.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	if past {
		return 0, os.ErrDeadlineExceeded
	}
	if err := c.conn.StreamWrite(c.streamID, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close closes the stream gracefully after queued writes. Use Conn.CloseStream with abort to drop them instead.
func (c *StreamConn) Close() error {
	if !c.markClosed() {
		return nil
	}
	return c.conn.CloseStream(c.streamID, "", false)
}

// LocalAddr reports a synthetic local address.
func (c *StreamConn) LocalAddr() net.Addr { return streamAddr("sidecar") }

// RemoteAddr reports the connecting peer's address from stream_open.
func (c *StreamConn) RemoteAddr() net.Addr { return streamAddr(c.open.PeerAddr) }

// SetDeadline sets both the read and write deadlines.
func (c *StreamConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

// SetReadDeadline sets the deadline for future Reads; a zero time clears it.
func (c *StreamConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readGen++
	gen := c.readGen
	c.readPast = false
	c.stopReadTimer()
	if t.IsZero() {
		return nil
	}
	if !t.After(time.Now()) {
		c.readPast = true
		c.cond.Broadcast()
		return nil
	}
	c.readTimer = time.AfterFunc(time.Until(t), func() {
		c.mu.Lock()
		if c.readGen == gen {
			c.readPast = true
			c.cond.Broadcast()
		}
		c.mu.Unlock()
	})
	return nil
}

// SetWriteDeadline sets the deadline for future Writes; a zero time clears it.
func (c *StreamConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeAt = t
	c.mu.Unlock()
	return nil
}

// streamAddr is the net.Addr for a stream endpoint.
type streamAddr string

func (streamAddr) Network() string  { return "sidecar-stream" }
func (a streamAddr) String() string { return string(a) }

// ErrRouterClosed is returned by Accept once the underlying conn has closed.
var ErrRouterClosed = errors.New("sidecar: stream router closed")

// streamAcceptQueue bounds streams opened but not yet Accepted.
const streamAcceptQueue = 64

// StreamRouter turns a claim's stream events into Accept-able StreamConns, so an
// adapter writes ordinary blocking net.Conn code instead of the stream callbacks.
// Embed it in a Handler and it supplies OnStreamOpen/OnStreamDeliver/OnStreamEnded;
// override the other callbacks (OnSidecarSend, OnInvokeTool, ...) as needed.
type StreamRouter struct {
	BaseHandler
	conn *Conn

	mu      sync.Mutex
	streams map[string]*StreamConn
	accept  chan *StreamConn
}

// NewStreamRouter returns a router that opens StreamConns over conn.
func NewStreamRouter(conn *Conn) *StreamRouter {
	r := &StreamRouter{
		conn:    conn,
		streams: map[string]*StreamConn{},
		accept:  make(chan *StreamConn, streamAcceptQueue),
	}
	go r.watchClose()
	return r
}

// watchClose wakes every open stream's blocked reader when the conn drops, since a
// dead transport delivers no stream_ended.
func (r *StreamRouter) watchClose() {
	<-r.conn.peer.Done()
	r.mu.Lock()
	for _, sc := range r.streams {
		sc.markClosed()
	}
	r.streams = map[string]*StreamConn{}
	r.mu.Unlock()
}

// Accept returns the next newly opened stream, blocking until one arrives, ctx is cancelled, or the conn closes.
func (r *StreamRouter) Accept(ctx context.Context) (*StreamConn, error) {
	select {
	case sc := <-r.accept:
		return sc, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-r.conn.peer.Done():
		return nil, ErrRouterClosed
	}
}

// DialUpstream dials an upstream through the conn and returns a StreamConn routed by this
// router: inbound bytes arrive via OnStreamDeliver and it is torn down by stream_ended or
// Close. Unlike an accepted stream it is not queued for Accept.
func (r *StreamRouter) DialUpstream(ctx context.Context, p wire.DialUpstreamParams) (*StreamConn, error) {
	id, err := r.conn.DialUpstream(ctx, p)
	if err != nil {
		return nil, err
	}
	sc := newStreamConn(r.conn, wire.StreamOpenParams{
		StreamID: id,
		Host:     p.Host,
		PeerAddr: net.JoinHostPort(p.Host, strconv.Itoa(p.Port)),
	})
	r.mu.Lock()
	r.streams[id] = sc
	r.mu.Unlock()
	return sc, nil
}

// OnStreamOpen registers the stream and queues it for Accept.
func (r *StreamRouter) OnStreamOpen(p wire.StreamOpenParams) ([]wire.StreamWrite, error) {
	sc := newStreamConn(r.conn, p)
	r.mu.Lock()
	r.streams[p.StreamID] = sc
	r.mu.Unlock()
	// block until Accept drains a slot or the conn closes
	// only this stream's dispatch goroutine waits, so other streams keep flowing
	select {
	case r.accept <- sc:
	case <-r.conn.peer.Done():
	}
	return nil, nil
}

// OnStreamDeliver hands inbound bytes to the stream's Read buffer.
func (r *StreamRouter) OnStreamDeliver(p wire.StreamWriteParams) ([]wire.StreamWrite, error) {
	if sc := r.lookup(p.StreamID); sc != nil {
		sc.deliver(p.Data)
	}
	return nil, nil
}

// OnStreamEnded marks the stream drained and drops it from the registry.
func (r *StreamRouter) OnStreamEnded(p wire.StreamEndedParams) {
	r.mu.Lock()
	sc := r.streams[p.StreamID]
	delete(r.streams, p.StreamID)
	r.mu.Unlock()
	if sc != nil {
		sc.end()
	}
}

func (r *StreamRouter) lookup(streamID string) *StreamConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.streams[streamID]
}

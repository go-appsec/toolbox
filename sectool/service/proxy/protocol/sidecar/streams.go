package sidecar

import (
	"context"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// streamReadBuf is the per-read chunk size delivered to the sidecar; raw
// transport bytes, not aligned to protocol frames.
const streamReadBuf = 32 * 1024

// streamWriteQueue bounds the writes queued for one stream; overflowing it closes
// the stream rather than dropping bytes out of a protocol's byte sequence.
const streamWriteQueue = 1024

// drainTimeout bounds a draining close, so a client that stopped reading cannot
// hold the stream open behind writes it will never take.
const drainTimeout = 30 * time.Second

// streamOp is one queued socket action: bytes to write, or a close.
type streamOp struct {
	data  []byte
	close bool
}

// stream is a registered socket and its ordered write queue. A single writer
// drains the queue so queued bytes reach the socket in enqueue order.
type stream struct {
	conn    net.Conn
	ops     chan streamOp
	drained chan struct{}
	done    chan struct{} // abort signal: stop the writer now, dropping queued ops
	stopped chan struct{} // closed by the writer when it exits
	once    sync.Once
}

func newStream(conn net.Conn) *stream {
	return &stream{
		conn:    conn,
		ops:     make(chan streamOp, streamWriteQueue),
		drained: make(chan struct{}, 1),
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

// enqueue queues an op without blocking, reporting false when the stream is released or its queue is full.
// Use from a shared goroutine, where blocking would stall unrelated streams.
func (s *stream) enqueue(op streamOp) bool {
	select {
	case s.ops <- op:
		return true
	case <-s.done:
		return false
	default:
		return false
	}
}

// awaitCapacity blocks while the write queue is full, returning once it drains or
// the stream is released. This is the backpressure toward whoever feeds the stream.
func (s *stream) awaitCapacity() {
	for len(s.ops) >= cap(s.ops) {
		select {
		case <-s.drained:
		case <-s.done:
			return
		}
	}
}

// release stops the writer; the socket owner still closes the socket.
func (s *stream) release() {
	s.once.Do(func() { close(s.done) })
}

// abort releases the stream and closes its socket, dropping queued writes.
func (s *stream) abort() {
	s.release()
	_ = s.conn.Close()
}

// closeAfterDrain enqueues a graceful close so the writer flushes the queued writes
// then closes the socket, bounded by drainTimeout so a client that stopped reading
// cannot hold the stream open. It does not wait for the writer.
func (s *stream) closeAfterDrain() {
	_ = s.conn.SetWriteDeadline(time.Now().Add(drainTimeout))
	if !s.enqueue(streamOp{close: true}) {
		s.abort() // queue full or already released, nothing left to drain into
	}
}

// write drains queued ops to the socket in enqueue order until a close op, a write
// failure, or an abort. A graceful close is an enqueued close op, so the writer
// flushes the bytes queued ahead of it; abort signals done and drops them.
func (s *stream) write(rec *Record, id string) {
	defer close(s.stopped)
	for {
		select {
		case op := <-s.ops:
			if !s.apply(rec, id, op) {
				return
			}
		case <-s.done:
			return
		}
	}
}

// apply performs one queued op, returning false when the writer should stop.
func (s *stream) apply(rec *Record, id string, op streamOp) bool {
	if op.close {
		_ = s.conn.Close()
		return false
	}
	if _, err := s.conn.Write(op.data); err != nil {
		// terminal for a byte stream; the owning pump reports stream_ended
		log.Printf("sidecar[%s]: stream write failed stream_id=%s: %v", rec.Name, id, err)
		_ = s.conn.Close()
		return false
	}
	select { // wake anyone waiting on capacity
	case s.drained <- struct{}{}:
	default:
	}
	return true
}

// streamSet tracks a sidecar's open byte streams so writes, proactive output, and teardown can reach the right socket.
type streamSet struct {
	next atomic.Uint64

	mu      sync.Mutex
	streams map[string]*stream
}

func newStreamSet() *streamSet {
	return &streamSet{streams: map[string]*stream{}}
}

// add registers conn as a new stream and starts its writer, returning the id.
func (ss *streamSet) add(rec *Record, conn net.Conn) string {
	id := "s" + strconv.FormatUint(ss.next.Add(1), 10)
	s := newStream(conn)
	ss.mu.Lock()
	ss.streams[id] = s
	ss.mu.Unlock()
	go s.write(rec, id)
	return id
}

func (ss *streamSet) remove(id string) {
	ss.mu.Lock()
	s := ss.streams[id]
	delete(ss.streams, id)
	ss.mu.Unlock()
	if s != nil {
		// flush queued writes and wait for the writer before the socket owner closes it
		s.closeAfterDrain()
		<-s.stopped
	}
}

func (ss *streamSet) get(id string) *stream {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.streams[id]
}

// awaitWriteCapacity blocks until every stream the sidecar just wrote to has queue
// space, so a slow client throttles the stream feeding it.
func (ss *streamSet) awaitWriteCapacity(streamIDs []string) {
	for _, id := range streamIDs {
		if s := ss.get(id); s != nil {
			s.awaitCapacity()
		}
	}
}

// serveClient runs one claimed client-facing connection as a stream. The caller owns closing the socket.
func (ss *streamSet) serveClient(ctx context.Context, rec *Record, c *protocol.EarlyClaimCtx) {
	id := ss.add(rec, c.ClientConn)
	defer ss.remove(id)
	// drop any per-exchange deadline the proxy left armed before the handoff
	_ = c.ClientConn.SetDeadline(time.Time{})

	host, path := openInfo(c)
	ss.runClient(ctx, rec, id, c.ClientReader, wire.StreamOpenParams{
		StreamID: id,
		Host:     host,
		Path:     path,
		PeerAddr: c.ClientConn.RemoteAddr().String(),
	})
}

// serveUpgrade runs a post-upgrade client connection as a stream, carrying the
// triggering request's flow_id and headers on stream_open.
func (ss *streamSet) serveUpgrade(ctx context.Context, rec *Record, conns protocol.UpgradeConns, reqFlowID string, reqHeaders []wire.Header, host, path string) {
	id := ss.add(rec, conns.ClientConn)
	defer ss.remove(id)
	// drop any per-exchange deadline the proxy left armed before the handoff
	_ = conns.ClientConn.SetDeadline(time.Time{})

	ss.runClient(ctx, rec, id, conns.ClientReader, wire.StreamOpenParams{
		StreamID:       id,
		Host:           host,
		Path:           path,
		PeerAddr:       conns.ClientConn.RemoteAddr().String(),
		RequestFlowID:  reqFlowID,
		RequestHeaders: reqHeaders,
	})
}

// runClient opens the stream and pumps inbound bytes. The caller registered the socket and owns closing it.
func (ss *streamSet) runClient(ctx context.Context, rec *Record, id string, r io.Reader, open wire.StreamOpenParams) {
	var res wire.StreamResult
	if err := rec.peer.Call(ctx, wire.MethodStreamOpen, open, &res); err != nil {
		return
	}
	// release the sidecar's per-stream state on any loop exit (RPC error or EOF)
	defer ss.notifyEnded(rec, id)
	// bytes were sent as stream_write; the reply only names the streams to pace
	ss.awaitWriteCapacity(res.WroteTo)
	ss.pump(ctx, rec, id, r)
}

// serveUpstream pumps a dialed upstream socket as a stream; the dial reply already
// announced it, so there is no stream_open. The caller registered the socket via
// add; this releases and closes it on exit.
func (ss *streamSet) serveUpstream(ctx context.Context, rec *Record, id string, conn net.Conn) {
	// the pump owns the dialed socket once registered
	defer func() { _ = conn.Close() }()
	defer ss.remove(id)
	defer ss.notifyEnded(rec, id)
	ss.pump(ctx, rec, id, conn)
}

// pump delivers inbound bytes from r as ordered stream_deliver events, pausing while a reply's target streams are backed up.
func (ss *streamSet) pump(ctx context.Context, rec *Record, id string, r io.Reader) {
	buf := make([]byte, streamReadBuf)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			var dres wire.StreamResult
			if derr := rec.peer.Call(ctx, wire.MethodStreamDeliver, wire.StreamWriteParams{
				StreamID: id,
				Data:     buf[:n],
			}, &dres); derr != nil {
				return
			}
			// bytes were sent as stream_write; the reply only names the streams to pace
			ss.awaitWriteCapacity(dres.WroteTo)
		}
		if err != nil {
			return
		}
	}
}

// notifyEnded tells the sidecar a stream closed so it can close the paired stream.
func (ss *streamSet) notifyEnded(rec *Record, id string) {
	_ = rec.peer.Notify(wire.MethodStreamEnded, wire.StreamEndedParams{StreamID: id, Reason: "closed"})
}

// closeStream closes the named stream's socket on the sidecar's request. It closes
// after the writes already queued, or immediately when abort drops them.
func (ss *streamSet) closeStream(id string, abort bool) {
	s := ss.get(id)
	if s == nil {
		return
	} else if abort {
		s.abort()
		return
	}
	// runs on the notification goroutine, so drain-close without waiting for the writer
	s.closeAfterDrain()
}

// streamWrite queues proactive bytes on an open stream. An unknown stream_id or a full
// queue returns a transport error; a full queue also aborts the stream, since dropping a
// write would desync the sidecar's state machine from the socket.
func (ss *streamSet) streamWrite(id string, data []byte) *wire.Error {
	s := ss.get(id)
	if s == nil {
		return wire.NewError(wire.CodeUnknownStream, "stream_write: unknown stream_id").
			WithData(&wire.ErrorData{StreamID: id})
	}
	if !s.enqueue(streamOp{data: data}) {
		s.abort()
		return wire.NewError(wire.CodeTransportInternal, "stream_write: queue full, stream closed").
			WithData(&wire.ErrorData{StreamID: id})
	}
	return nil
}

// closeAll closes every open stream, unblocking their read loops.
func (ss *streamSet) closeAll() {
	ss.mu.Lock()
	streams := bulk.MapValuesSlice(ss.streams)
	ss.mu.Unlock()
	for _, s := range streams {
		s.abort()
	}
}

// openInfo derives the stream_open host/path. An early_claim has no HTTP request,
// so host comes from the CONNECT target when TLS-terminated and path is empty.
func openInfo(c *protocol.EarlyClaimCtx) (host, path string) {
	if c.Target != nil {
		host = c.Target.Hostname
	}
	return host, ""
}

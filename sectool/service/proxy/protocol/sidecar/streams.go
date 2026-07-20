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

// streamSet tracks a sidecar's open byte streams so writes, proactive output, and
// teardown can reach the right socket.
type streamSet struct {
	next atomic.Uint64

	mu      sync.Mutex
	streams map[string]net.Conn
}

func newStreamSet() *streamSet {
	return &streamSet{streams: map[string]net.Conn{}}
}

func (ss *streamSet) add(conn net.Conn) string {
	id := "s" + strconv.FormatUint(ss.next.Add(1), 10)
	ss.mu.Lock()
	ss.streams[id] = conn
	ss.mu.Unlock()
	return id
}

func (ss *streamSet) remove(id string) {
	ss.mu.Lock()
	delete(ss.streams, id)
	ss.mu.Unlock()
}

func (ss *streamSet) conn(id string) net.Conn {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	return ss.streams[id]
}

// applyWrites writes each entry to its named stream's socket. An unknown
// stream_id is skipped; a failed write closes only that stream.
func (ss *streamSet) applyWrites(rec *Record, writes []wire.StreamWrite) {
	for _, w := range writes {
		c := ss.conn(w.StreamID)
		if c == nil {
			continue
		}
		if _, err := c.Write(w.Data); err != nil {
			// terminal for a byte stream; the owning pump reports stream_ended
			log.Printf("sidecar[%s]: stream write failed stream_id=%s: %v", rec.Name, w.StreamID, err)
			_ = c.Close()
		}
	}
}

// serveClient runs one claimed client-facing connection as a stream. The caller
// owns closing the socket.
func (ss *streamSet) serveClient(ctx context.Context, rec *Record, c *protocol.EarlyClaimCtx) {
	id := ss.add(c.ClientConn)
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
	id := ss.add(conns.ClientConn)
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

// runClient opens the stream and pumps inbound bytes. The caller registered the
// socket and owns closing it.
func (ss *streamSet) runClient(ctx context.Context, rec *Record, id string, r io.Reader, open wire.StreamOpenParams) {
	var res wire.StreamResult
	if err := rec.peer.Call(ctx, wire.MethodStreamOpen, open, &res); err != nil {
		return
	}
	// release the sidecar's per-stream state on any loop exit (RPC error or EOF)
	defer ss.notifyEnded(rec, id)
	ss.applyWrites(rec, res.Writes)
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

// pump delivers inbound bytes from r as ordered stream_deliver events, applying
// each reply's writes.
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
			ss.applyWrites(rec, dres.Writes)
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

// closeStream closes the named stream's socket on the sidecar's request.
func (ss *streamSet) closeStream(id string) {
	if c := ss.conn(id); c != nil {
		_ = c.Close()
	}
}

// streamWrite writes proactive bytes to an open stream. An unknown stream_id or a
// failed write is a transport error; a failed write also closes the stream.
func (ss *streamSet) streamWrite(id string, data []byte) *wire.Error {
	c := ss.conn(id)
	if c == nil {
		return wire.NewError(wire.CodeUnknownStream, "stream_write: unknown stream_id").
			WithData(&wire.ErrorData{StreamID: id})
	}
	if _, err := c.Write(data); err != nil {
		// terminal for a byte stream; the owning pump reports stream_ended
		_ = c.Close()
		return wire.NewError(wire.CodeTransportInternal, "stream_write: "+err.Error()).
			WithData(&wire.ErrorData{StreamID: id})
	}
	return nil
}

// closeAll closes every open stream, unblocking their read loops.
func (ss *streamSet) closeAll() {
	ss.mu.Lock()
	conns := bulk.MapValuesSlice(ss.streams)
	ss.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
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

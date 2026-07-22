package sidecar

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// countingConn records whether the stream owner closed the socket.
type countingConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *countingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// deadConn returns a registered socket whose peer is already gone, so any write
// to it fails.
func deadConn(t *testing.T) *countingConn {
	t.Helper()
	local, remote := net.Pipe()
	require.NoError(t, remote.Close())
	t.Cleanup(func() { _ = local.Close() })
	return &countingConn{Conn: local}
}

// streamPeers wires a Record to a client peer over net.Pipe against ss, matching how
// the session routes stream traffic in production. reply answers
// stream_open/stream_deliver with writes the sidecar sends as stream_write, and may
// use the sidecar peer it is passed to send proactive writes; the returned channel
// receives stream_ended stream ids.
func streamPeers(t *testing.T, ss *streamSet, reply func(sc *wire.Peer, method string, p wire.StreamWriteParams) []wire.StreamWrite) (*Record, chan string) {
	t.Helper()
	srv, cli := net.Pipe()
	rec := &Record{Name: "sc"}
	rec.peer = wire.NewPeer(srv, wire.HandlerFuncs{
		Notification: func(_ context.Context, method string, params json.RawMessage) {
			if method != wire.MethodStreamWrite {
				return
			}
			var p wire.StreamWriteParams
			if json.Unmarshal(params, &p) == nil {
				_ = ss.streamWrite(p.StreamID, p.Data)
			}
		},
	})
	go func() { _ = rec.peer.Run(t.Context()) }()
	t.Cleanup(func() { _ = rec.peer.Close() })

	ended := make(chan string, 8)
	p := wire.NewPeer(cli, nil)
	p.SetHandler(wire.HandlerFuncs{
		Request: func(_ context.Context, method string, params json.RawMessage) (any, *wire.Error) {
			var sp wire.StreamWriteParams
			_ = json.Unmarshal(params, &sp)
			// emulate the SDK: writes go out as stream_write, the reply names them
			writes := reply(p, method, sp)
			wroteTo := make([]string, 0, len(writes))
			for _, w := range writes {
				if err := p.Notify(wire.MethodStreamWrite, wire.StreamWriteParams(w)); err != nil {
					return nil, wire.NewError(wire.CodeTransportInternal, err.Error())
				}
				wroteTo = append(wroteTo, w.StreamID)
			}
			return wire.StreamResult{WroteTo: wroteTo}, nil
		},
		Notification: func(_ context.Context, method string, params json.RawMessage) {
			if method != wire.MethodStreamEnded {
				return
			}
			var ep wire.StreamEndedParams
			if json.Unmarshal(params, &ep) == nil {
				ended <- ep.StreamID
			}
		},
	})
	go func() { _ = p.Run(t.Context()) }()
	t.Cleanup(func() { _ = p.Close() })
	return rec, ended
}

func recvString(t *testing.T, ch chan string) string {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for value")
		return ""
	}
}

func recvBytes(t *testing.T, ch chan []byte) []byte {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for value")
		return nil
	}
}

func TestServeUpstream(t *testing.T) {
	t.Parallel()

	t.Run("eof_closes_conn", func(t *testing.T) {
		ss := newStreamSet()
		rec, ended := streamPeers(t, ss, func(*wire.Peer, string, wire.StreamWriteParams) []wire.StreamWrite { return nil })
		local, remote := net.Pipe()
		conn := &countingConn{Conn: local}

		id := ss.add(rec, conn)
		go ss.serveUpstream(t.Context(), rec, id, conn)

		require.NoError(t, remote.Close())
		assert.Equal(t, id, recvString(t, ended))
		// stream_ended is notified before the socket close and registry removal
		assert.Eventually(t, conn.closed.Load, time.Second, 5*time.Millisecond)
		assert.Eventually(t, func() bool { return ss.get(id) == nil }, time.Second, 5*time.Millisecond)
	})
}

func TestEventWrites(t *testing.T) {
	t.Parallel()

	t.Run("failed_target_keeps_source", func(t *testing.T) {
		var targetID string
		delivered := make(chan []byte, 4)
		ss := newStreamSet()
		rec, _ := streamPeers(t, ss, func(_ *wire.Peer, method string, p wire.StreamWriteParams) []wire.StreamWrite {
			if method != wire.MethodStreamDeliver {
				return nil
			}
			delivered <- p.Data
			return []wire.StreamWrite{{StreamID: targetID, Data: []byte("out")}}
		})

		target := deadConn(t)
		srcLocal, srcRemote := net.Pipe()
		t.Cleanup(func() { _ = srcRemote.Close() })
		src := &countingConn{Conn: srcLocal}

		targetID = ss.add(rec, target)
		srcID := ss.add(rec, src)
		go ss.pump(t.Context(), rec, srcID, src)

		_, err := srcRemote.Write([]byte("a"))
		require.NoError(t, err)
		assert.Equal(t, []byte("a"), recvBytes(t, delivered))
		// source survives the failed write to the dead target
		_, err = srcRemote.Write([]byte("b"))
		require.NoError(t, err)
		assert.Equal(t, []byte("b"), recvBytes(t, delivered))

		assert.Eventually(t, target.closed.Load, time.Second, 5*time.Millisecond)
		assert.False(t, src.closed.Load())
	})

	t.Run("unknown_stream_skipped", func(t *testing.T) {
		ss := newStreamSet()
		rec := &Record{Name: "sc"}
		conn := deadConn(t)
		id := ss.add(rec, conn)
		err := ss.streamWrite("missing", []byte("x"))
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeUnknownStream, err.Code)
		assert.False(t, conn.closed.Load())
		assert.NotNil(t, ss.get(id))
	})
}

func TestStreamWrite(t *testing.T) {
	t.Parallel()

	t.Run("unknown_stream", func(t *testing.T) {
		err := newStreamSet().streamWrite("missing", []byte("x"))
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeUnknownStream, err.Code)
	})

	t.Run("write_error_closes_stream", func(t *testing.T) {
		ss := newStreamSet()
		conn := deadConn(t)
		id := ss.add(&Record{Name: "sc"}, conn)

		require.Nil(t, ss.streamWrite(id, []byte("x")))
		assert.Eventually(t, conn.closed.Load, time.Second, 5*time.Millisecond)
	})

	t.Run("writes_keep_send_order", func(t *testing.T) {
		local, remote := net.Pipe()
		t.Cleanup(func() { _ = local.Close() })
		t.Cleanup(func() { _ = remote.Close() })

		ss := newStreamSet()
		rec := &Record{Name: "sc"}
		id := ss.add(rec, local)

		const writes = 200
		go func() {
			for i := range writes {
				_ = ss.streamWrite(id, []byte{byte(i)})
			}
		}()

		got := make([]byte, writes)
		require.NoError(t, remote.SetReadDeadline(time.Now().Add(5*time.Second)))
		_, err := io.ReadFull(remote, got)
		require.NoError(t, err)
		for i := range writes {
			require.Equal(t, byte(i), got[i])
		}
	})

	t.Run("queue_overflow_closes_stream", func(t *testing.T) {
		// net.Pipe is unbuffered and nothing reads, so the writer wedges on the first op
		local, remote := net.Pipe()
		t.Cleanup(func() { _ = remote.Close() })
		conn := &countingConn{Conn: local}

		ss := newStreamSet()
		rec := &Record{Name: "sc"}
		id := ss.add(rec, conn)

		var overflow *wire.Error
		for range streamWriteQueue + 2 {
			if err := ss.streamWrite(id, []byte("x")); err != nil {
				overflow = err
			}
		}
		require.NotNil(t, overflow)
		assert.Equal(t, wire.CodeTransportInternal, overflow.Code)
		assert.Eventually(t, conn.closed.Load, time.Second, 5*time.Millisecond)
	})
}

// TestStreamResultOrdering covers the mixed write paths: a sidecar that answers
// stream_deliver with writes while also sending proactive stream_write must see
// both reach the socket in the order it sent them.
func TestStreamResultOrdering(t *testing.T) {
	t.Parallel()

	const rounds = 50
	ss := newStreamSet()
	// the sidecar emits a proactive write, then answers the event with the next byte
	rec, _ := streamPeers(t, ss, func(sc *wire.Peer, method string, p wire.StreamWriteParams) []wire.StreamWrite {
		if method != wire.MethodStreamDeliver {
			return nil
		}
		assert.NoError(t, sc.Notify(wire.MethodStreamWrite, wire.StreamWriteParams{
			StreamID: p.StreamID,
			Data:     []byte{p.Data[0]},
		}))
		return []wire.StreamWrite{{StreamID: p.StreamID, Data: []byte{p.Data[0] + 1}}}
	})

	local, remote := net.Pipe()
	t.Cleanup(func() { _ = local.Close() })
	t.Cleanup(func() { _ = remote.Close() })
	id := ss.add(rec, local)

	src, srcRemote := net.Pipe()
	t.Cleanup(func() { _ = srcRemote.Close() })
	go ss.pump(t.Context(), rec, id, src)
	go func() {
		for i := range rounds {
			if _, err := srcRemote.Write([]byte{byte(i * 2)}); err != nil {
				return
			}
		}
	}()

	got := make([]byte, rounds*2)
	require.NoError(t, remote.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err := io.ReadFull(remote, got)
	require.NoError(t, err)
	for i := range rounds * 2 {
		require.Equal(t, byte(i), got[i], "byte %d out of order", i)
	}
}

func TestCloseStream(t *testing.T) {
	t.Parallel()

	t.Run("flushes_queued_writes", func(t *testing.T) {
		local, remote := net.Pipe()
		t.Cleanup(func() { _ = remote.Close() })
		conn := &countingConn{Conn: local}

		ss := newStreamSet()
		rec := &Record{Name: "sc"}
		id := ss.add(rec, conn)

		go func() {
			_ = ss.streamWrite(id, []byte("queued"))
			ss.closeStream(id, false)
		}()

		got := make([]byte, len("queued"))
		require.NoError(t, remote.SetReadDeadline(time.Now().Add(5*time.Second)))
		_, err := io.ReadFull(remote, got)
		require.NoError(t, err)
		assert.Equal(t, []byte("queued"), got)
		assert.Eventually(t, conn.closed.Load, time.Second, 5*time.Millisecond)
	})

	t.Run("remove_flushes_queued_writes", func(t *testing.T) {
		local, remote := net.Pipe()
		t.Cleanup(func() { _ = remote.Close() })
		conn := &countingConn{Conn: local}

		ss := newStreamSet()
		id := ss.add(&Record{Name: "sc"}, conn)
		require.Nil(t, ss.streamWrite(id, []byte("queued")))

		// a concurrent reader lets remove's drain flush before it returns
		got := make([]byte, len("queued"))
		read := make(chan error, 1)
		go func() { _, err := io.ReadFull(remote, got); read <- err }()

		ss.remove(id)
		require.NoError(t, <-read)
		assert.Equal(t, []byte("queued"), got)
		assert.True(t, conn.closed.Load())
		assert.Nil(t, ss.get(id))
	})

	t.Run("abort_drops_queued_writes", func(t *testing.T) {
		// net.Pipe is unbuffered and nothing reads, so the queued write is still pending
		local, remote := net.Pipe()
		t.Cleanup(func() { _ = remote.Close() })
		conn := &countingConn{Conn: local}

		ss := newStreamSet()
		rec := &Record{Name: "sc"}
		id := ss.add(rec, conn)

		require.Nil(t, ss.streamWrite(id, []byte("dropped")))
		ss.closeStream(id, true)
		assert.True(t, conn.closed.Load())

		// the queued write never reaches the socket
		_, err := remote.Read(make([]byte, 8))
		assert.Error(t, err)
	})

	t.Run("unknown_stream_noop", func(t *testing.T) {
		newStreamSet().closeStream("missing", false)
	})
}

func TestStreamAwaitCapacity(t *testing.T) {
	t.Parallel()

	local, remote := net.Pipe()
	t.Cleanup(func() { _ = local.Close() })
	t.Cleanup(func() { _ = remote.Close() })

	// no writer goroutine, so the queue only drains when this test says so
	s := newStream(local)
	for range cap(s.ops) {
		require.True(t, s.enqueue(streamOp{data: []byte("x")}))
	}

	blocked := make(chan struct{})
	go func() {
		defer close(blocked)
		s.awaitCapacity()
	}()
	select {
	case <-blocked:
		t.Fatal("awaitCapacity did not block on a full queue")
	case <-time.After(50 * time.Millisecond):
	}

	<-s.ops
	s.drained <- struct{}{}
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("awaitCapacity stayed blocked after the queue drained")
	}
}

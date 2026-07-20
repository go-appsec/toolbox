package sidecar

import (
	"context"
	"encoding/json"
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

// streamPeers wires a Record to a client peer over net.Pipe. reply answers
// stream_open/stream_deliver with writes to apply; the returned channel receives
// stream_ended stream ids.
func streamPeers(t *testing.T, reply func(method string, p wire.StreamWriteParams) []wire.StreamWrite) (*Record, chan string) {
	t.Helper()
	srv, cli := net.Pipe()
	rec := &Record{Name: "sc"}
	rec.peer = wire.NewPeer(srv, nil)
	go func() { _ = rec.peer.Run(t.Context()) }()
	t.Cleanup(func() { _ = rec.peer.Close() })

	ended := make(chan string, 8)
	p := wire.NewPeer(cli, nil)
	p.SetHandler(wire.HandlerFuncs{
		Request: func(_ context.Context, method string, params json.RawMessage) (any, *wire.Error) {
			var sp wire.StreamWriteParams
			_ = json.Unmarshal(params, &sp)
			return wire.StreamResult{Writes: reply(method, sp)}, nil
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
		rec, ended := streamPeers(t, func(string, wire.StreamWriteParams) []wire.StreamWrite { return nil })
		local, remote := net.Pipe()
		conn := &countingConn{Conn: local}

		ss := newStreamSet()
		id := ss.add(conn)
		go ss.serveUpstream(t.Context(), rec, id, conn)

		require.NoError(t, remote.Close())
		assert.Equal(t, id, recvString(t, ended))
		assert.True(t, conn.closed.Load())
		assert.Nil(t, ss.conn(id))
	})
}

func TestApplyWrites(t *testing.T) {
	t.Parallel()

	t.Run("failed_target_keeps_source", func(t *testing.T) {
		var targetID string
		delivered := make(chan []byte, 4)
		rec, _ := streamPeers(t, func(method string, p wire.StreamWriteParams) []wire.StreamWrite {
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

		ss := newStreamSet()
		targetID = ss.add(target)
		srcID := ss.add(src)
		go ss.pump(t.Context(), rec, srcID, src)

		_, err := srcRemote.Write([]byte("a"))
		require.NoError(t, err)
		assert.Equal(t, []byte("a"), recvBytes(t, delivered))
		// source survives the failed write to the dead target
		_, err = srcRemote.Write([]byte("b"))
		require.NoError(t, err)
		assert.Equal(t, []byte("b"), recvBytes(t, delivered))

		assert.True(t, target.closed.Load())
		assert.False(t, src.closed.Load())
	})

	t.Run("unknown_stream_skipped", func(t *testing.T) {
		ss := newStreamSet()
		conn := deadConn(t)
		id := ss.add(conn)
		ss.applyWrites(&Record{Name: "sc"}, []wire.StreamWrite{{StreamID: "missing", Data: []byte("x")}})
		assert.False(t, conn.closed.Load())
		assert.NotNil(t, ss.conn(id))
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
		id := ss.add(conn)

		err := ss.streamWrite(id, []byte("x"))
		require.NotNil(t, err)
		assert.Equal(t, wire.CodeTransportInternal, err.Code)
		require.NotNil(t, err.Data)
		assert.Equal(t, id, err.Data.StreamID)
		assert.True(t, conn.closed.Load())
	})
}

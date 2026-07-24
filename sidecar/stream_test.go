package sidecar

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sidecar/wire"
)

// streamServer is a fake sectool that registers, records the sidecar's stream
// notifications (stream_write, close_stream), and lets the test drive stream events.
type streamServer struct {
	mu     sync.Mutex
	writes map[string][]byte
	closed map[string]bool
	dialID string
	peer   chan *wire.Peer
}

func newStreamServer(t *testing.T) (*streamServer, *Conn, *StreamRouter) {
	t.Helper()
	s := &streamServer{writes: map[string][]byte{}, closed: map[string]bool{}, dialID: "up1", peer: make(chan *wire.Peer, 1)}
	addr, peerCh := fakeServer(t, s.onRequest, s.onNotify)
	conn, err := Dial(t.Context(), addr, Registration{Name: "streamer"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	router := NewStreamRouter(conn)
	conn.SetHandler(router)
	s.peer <- <-peerCh
	return s, conn, router
}

// srvPeer returns the accepted server-side peer, restoring it for reuse.
func (s *streamServer) srvPeer(t *testing.T) *wire.Peer {
	t.Helper()
	p := <-s.peer
	s.peer <- p
	return p
}

func (s *streamServer) onRequest(method string, params json.RawMessage) (any, *wire.Error) {
	if method == wire.MethodDialUpstream {
		return wire.DialUpstreamResult{StreamID: s.dialID}, nil
	}
	return registerOK(method, params)
}

func (s *streamServer) onNotify(_ context.Context, method string, params json.RawMessage) {
	switch method {
	case wire.MethodStreamWrite:
		var p wire.StreamWriteParams
		_ = json.Unmarshal(params, &p)
		s.mu.Lock()
		s.writes[p.StreamID] = append(s.writes[p.StreamID], p.Data...)
		s.mu.Unlock()
	case wire.MethodCloseStream:
		var p wire.StreamEndedParams
		_ = json.Unmarshal(params, &p)
		s.mu.Lock()
		s.closed[p.StreamID] = true
		s.mu.Unlock()
	}
}

func (s *streamServer) wroteTo(streamID string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writes[streamID]
}

func (s *streamServer) wasClosed(streamID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed[streamID]
}

func TestStreamRouter(t *testing.T) {
	t.Parallel()

	t.Run("accept_read_write_close", func(t *testing.T) {
		s, _, router := newStreamServer(t)
		srv := s.srvPeer(t)

		var res wire.StreamResult
		require.Nil(t, srv.Call(t.Context(), wire.MethodStreamOpen,
			wire.StreamOpenParams{StreamID: "s1", Host: "example.com", PeerAddr: "1.2.3.4:5"}, &res))

		sc, err := router.Accept(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "s1", sc.StreamID())
		assert.Equal(t, "example.com", sc.Open().Host)
		assert.Equal(t, "1.2.3.4:5", sc.RemoteAddr().String())

		require.Nil(t, srv.Call(t.Context(), wire.MethodStreamDeliver,
			wire.StreamWriteParams{StreamID: "s1", Data: []byte("hello")}, &res))

		got := make([]byte, 5)
		n, err := io.ReadFull(sc, got)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(got[:n]))

		_, err = sc.Write([]byte("world"))
		require.NoError(t, err)
		require.NoError(t, sc.Close())

		assert.Eventually(t, func() bool {
			return string(s.wroteTo("s1")) == "world" && s.wasClosed("s1")
		}, time.Second, 5*time.Millisecond)
	})

	t.Run("read_wakes_on_transport_drop", func(t *testing.T) {
		s, _, router := newStreamServer(t)
		srv := s.srvPeer(t)

		var res wire.StreamResult
		require.Nil(t, srv.Call(t.Context(), wire.MethodStreamOpen, wire.StreamOpenParams{StreamID: "s4"}, &res))
		sc, err := router.Accept(t.Context())
		require.NoError(t, err)

		errc := make(chan error, 1)
		go func() {
			_, err := sc.Read(make([]byte, 4))
			errc <- err
		}()

		// drop the transport with no stream_ended; a blocked Read must still wake
		require.NoError(t, srv.Close())
		select {
		case err := <-errc:
			require.ErrorIs(t, err, io.ErrClosedPipe)
		case <-time.After(2 * time.Second):
			t.Fatal("Read did not wake on transport drop")
		}
	})

	t.Run("ended_reads_eof", func(t *testing.T) {
		s, _, router := newStreamServer(t)
		srv := s.srvPeer(t)

		var res wire.StreamResult
		require.Nil(t, srv.Call(t.Context(), wire.MethodStreamOpen, wire.StreamOpenParams{StreamID: "s2"}, &res))
		sc, err := router.Accept(t.Context())
		require.NoError(t, err)

		require.Nil(t, srv.Call(t.Context(), wire.MethodStreamDeliver,
			wire.StreamWriteParams{StreamID: "s2", Data: []byte("abcde")}, &res))
		require.NoError(t, srv.Notify(wire.MethodStreamEnded, wire.StreamEndedParams{StreamID: "s2"}))

		// partial read leaves a remainder, then the rest, then EOF
		buf := make([]byte, 3)
		n, err := sc.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "abc", string(buf[:n]))

		rest, err := io.ReadAll(sc)
		require.NoError(t, err)
		assert.Equal(t, "de", string(rest))
	})
}

func TestStreamRouterDialUpstream(t *testing.T) {
	t.Parallel()

	t.Run("registers_and_routes_deliver", func(t *testing.T) {
		s, _, router := newStreamServer(t)
		srv := s.srvPeer(t)

		sc, err := router.DialUpstream(t.Context(), wire.DialUpstreamParams{Host: "up.example.com", Port: 443})
		require.NoError(t, err)
		assert.Equal(t, s.dialID, sc.StreamID())
		assert.Equal(t, "up.example.com:443", sc.RemoteAddr().String())
		// dialed stream is routed but not queued for Accept
		assert.Empty(t, router.accept)

		var res wire.StreamResult
		require.Nil(t, srv.Call(t.Context(), wire.MethodStreamDeliver,
			wire.StreamWriteParams{StreamID: s.dialID, Data: []byte("pong")}, &res))

		got := make([]byte, 4)
		n, err := io.ReadFull(sc, got)
		require.NoError(t, err)
		assert.Equal(t, "pong", string(got[:n]))
	})

	t.Run("stream_ended_cleans_up", func(t *testing.T) {
		s, _, router := newStreamServer(t)
		srv := s.srvPeer(t)

		sc, err := router.DialUpstream(t.Context(), wire.DialUpstreamParams{Host: "up", Port: 1})
		require.NoError(t, err)

		require.NoError(t, srv.Notify(wire.MethodStreamEnded, wire.StreamEndedParams{StreamID: s.dialID}))
		assert.Eventually(t, func() bool { return router.lookup(s.dialID) == nil }, time.Second, 5*time.Millisecond)
		_, err = sc.Read(make([]byte, 1))
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("close_notifies_sectool", func(t *testing.T) {
		s, _, router := newStreamServer(t)
		_ = s.srvPeer(t)

		sc, err := router.DialUpstream(t.Context(), wire.DialUpstreamParams{Host: "up", Port: 1})
		require.NoError(t, err)
		require.NoError(t, sc.Close())
		assert.Eventually(t, func() bool { return s.wasClosed(s.dialID) }, time.Second, 5*time.Millisecond)
	})
}

func TestStreamConnReadDeadline(t *testing.T) {
	t.Parallel()

	s, _, router := newStreamServer(t)
	srv := s.srvPeer(t)

	var res wire.StreamResult
	require.Nil(t, srv.Call(t.Context(), wire.MethodStreamOpen, wire.StreamOpenParams{StreamID: "s3"}, &res))
	sc, err := router.Accept(t.Context())
	require.NoError(t, err)

	require.NoError(t, sc.SetReadDeadline(time.Now().Add(-time.Second)))
	n, err := sc.Read(make([]byte, 4))
	assert.Zero(t, n)
	assert.ErrorIs(t, err, os.ErrDeadlineExceeded)
}

package wire

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newPeerPair wires two peers over net.Pipe and starts both reader loops.
func newPeerPair(t *testing.T, ha, hb Handler) (*Peer, *Peer) {
	t.Helper()
	ca, cb := net.Pipe()
	pa := NewPeer(ca, ha)
	pb := NewPeer(cb, hb)
	ctx := t.Context()
	go func() { _ = pa.Run(ctx) }()
	go func() { _ = pb.Run(ctx) }()
	t.Cleanup(func() {
		_ = pa.Close()
		_ = pb.Close()
	})
	return pa, pb
}

func TestPeerCall(t *testing.T) {
	t.Parallel()

	t.Run("request_response", func(t *testing.T) {
		server := HandlerFuncs{
			Request: func(_ context.Context, method string, params json.RawMessage) (any, *Error) {
				assert.Equal(t, "echo", method)
				return map[string]string{"got": string(params)}, nil
			},
		}
		client, _ := newPeerPair(t, HandlerFuncs{}, server)

		var out struct{ Got string }
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		t.Cleanup(cancel)
		require.Nil(t, client.Call(ctx, "echo", map[string]int{"n": 1}, &out))
		assert.Equal(t, `{"n":1}`, out.Got)
	})

	t.Run("error_response", func(t *testing.T) {
		server := HandlerFuncs{
			Request: func(context.Context, string, json.RawMessage) (any, *Error) {
				return nil, NewError(CodeRegistrationRejected, "nope").
					WithData(&ErrorData{Adapter: "x"})
			},
		}
		client, _ := newPeerPair(t, HandlerFuncs{}, server)

		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		t.Cleanup(cancel)
		err := client.Call(ctx, "boom", nil, nil)
		require.NotNil(t, err)
		assert.Equal(t, CodeRegistrationRejected, err.Code)
		require.NotNil(t, err.Data)
		assert.Equal(t, "x", err.Data.Adapter)
	})

	t.Run("notification_no_reply", func(t *testing.T) {
		got := make(chan string, 1)
		server := HandlerFuncs{
			Notification: func(_ context.Context, method string, _ json.RawMessage) {
				got <- method
			},
		}
		client, _ := newPeerPair(t, HandlerFuncs{}, server)

		require.NoError(t, client.Notify("event", nil))
		select {
		case m := <-got:
			assert.Equal(t, "event", m)
		case <-time.After(2 * time.Second):
			t.Fatal("notification not received")
		}
	})
}

// TestPeerNestedRequest verifies deadlock freedom: while peer A handles a
// request from B, A issues its own request back to B; both must complete
// without the reader loops blocking.
func TestPeerNestedRequest(t *testing.T) {
	t.Parallel()

	var bPeer *Peer
	// B's handler, when asked "outer", calls back to A for "inner" over its own peer.
	bHandler := HandlerFuncs{
		Request: func(ctx context.Context, method string, _ json.RawMessage) (any, *Error) {
			if method == "outer" {
				var inner struct{ V int }
				if err := bPeer.Call(ctx, "inner", nil, &inner); err != nil {
					return nil, err
				}
				return map[string]int{"doubled": inner.V * 2}, nil
			}
			return nil, NewError(-32601, "unknown")
		},
	}
	aHandler := HandlerFuncs{
		Request: func(context.Context, string, json.RawMessage) (any, *Error) {
			return map[string]int{"v": 21}, nil
		},
	}

	ca, cb := net.Pipe()
	aPeer := NewPeer(ca, aHandler)
	bPeer = NewPeer(cb, bHandler)
	runCtx := t.Context()
	go func() { _ = aPeer.Run(runCtx) }()
	go func() { _ = bPeer.Run(runCtx) }()
	t.Cleanup(func() { _ = aPeer.Close(); _ = bPeer.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	t.Cleanup(cancel)
	var out struct{ Doubled int }
	require.Nil(t, aPeer.Call(ctx, "outer", nil, &out))
	assert.Equal(t, 42, out.Doubled)
}

func TestPeerConcurrentCalls(t *testing.T) {
	t.Parallel()

	server := HandlerFuncs{
		Request: func(_ context.Context, _ string, params json.RawMessage) (any, *Error) {
			var in struct {
				N int `json:"n"`
			}
			_ = json.Unmarshal(params, &in)
			return map[string]int{"n": in.N}, nil
		},
	}
	client, _ := newPeerPair(t, HandlerFuncs{}, server)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			var out struct {
				N int `json:"n"`
			}
			assert.Nil(t, client.Call(ctx, "id", map[string]int{"n": n}, &out))
			assert.Equal(t, n, out.N)
		}(i)
	}
	wg.Wait()
}

func TestPeerCloseWakesCallers(t *testing.T) {
	t.Parallel()

	// server never replies; Close must unblock the call, received signals in-flight
	received := make(chan struct{})
	block := make(chan struct{})
	server := HandlerFuncs{
		Request: func(context.Context, string, json.RawMessage) (any, *Error) {
			close(received)
			<-block
			return nil, nil
		},
	}
	client, _ := newPeerPair(t, HandlerFuncs{}, server)
	t.Cleanup(func() { close(block) })

	errCh := make(chan *Error, 1)
	go func() { errCh <- client.Call(t.Context(), "hang", nil, nil) }()

	<-received // request reached the server; the Call is now awaiting a reply
	_ = client.Close()

	err := <-errCh
	require.NotNil(t, err)
	assert.Equal(t, CodeTransportInternal, err.Code)
}

func TestPeerNotificationOrder(t *testing.T) {
	t.Parallel()

	// stays under laneQueue so every Notify completes while the first handler waits
	const count = 100
	got := make(chan int, count)
	sent, release := make(chan struct{}), make(chan struct{})
	var first sync.Once
	handler := HandlerFuncs{
		Notification: func(_ context.Context, _ string, params json.RawMessage) {
			// hold the first handler until all are sent, so concurrent dispatch would overtake it
			first.Do(func() { <-release })
			var seq int
			assert.NoError(t, json.Unmarshal(params, &seq))
			got <- seq
		},
	}

	pa, _ := newPeerPair(t, nil, handler)
	go func() {
		defer close(sent)
		for i := range count {
			assert.NoError(t, pa.Notify("seq", i))
		}
	}()
	<-sent
	close(release)

	for i := range count {
		select {
		case seq := <-got:
			require.Equal(t, i, seq)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for notification")
		}
	}
}

// TestPeerRequestsConcurrent verifies requests do not block behind each other, so a
// handler awaiting a nested Call cannot wedge the reader.
func TestPeerRequestsConcurrent(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	entered := make(chan string, 2)
	handler := HandlerFuncs{
		Request: func(_ context.Context, method string, _ json.RawMessage) (any, *Error) {
			entered <- method
			if method == "slow" {
				<-release
			}
			return struct{}{}, nil
		},
	}
	client, _ := newPeerPair(t, HandlerFuncs{}, handler)

	go func() { _ = client.Call(t.Context(), "slow", nil, nil) }()
	require.Equal(t, "slow", <-entered)

	// a second request runs while the first is held
	done := make(chan struct{})
	go func() {
		defer close(done)
		assert.Nil(t, client.Call(t.Context(), "fast", nil, nil))
	}()
	require.Equal(t, "fast", <-entered)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("second request blocked behind the first")
	}
	close(release)
}

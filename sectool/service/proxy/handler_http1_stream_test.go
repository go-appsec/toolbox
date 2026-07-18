package proxy

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

// syncBuf is a concurrency-safe byte sink for reading a streamed response.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// chunkedTrickleUpstream accepts one connection, sends a chunked response head
// and the first chunk, then waits on gate before sending the second chunk and
// terminator. Returns the listener address.
func chunkedTrickleUpstream(t *testing.T, gate <-chan struct{}) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		br := bufio.NewReader(conn)
		for { // drain the request head
			line, rerr := br.ReadString('\n')
			if rerr != nil || line == "\r\n" {
				break
			}
		}

		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
		writeChunk(conn, "data: one\n\n")
		<-gate
		writeChunk(conn, "data: two\n\n")
		_, _ = io.WriteString(conn, "0\r\n\r\n")
	}()

	return ln.Addr().String()
}

func writeChunk(w io.Writer, payload string) {
	_, _ = io.WriteString(w, fmt.Sprintf("%x\r\n%s\r\n", len(payload), payload))
}

// replaceBodyRuleApplier mutates response bodies (per unit) by replacing find with replace.
type replaceBodyRuleApplier struct {
	find, replace []byte
}

func (replaceBodyRuleApplier) ApplyRequestRules(r *types.RawHTTP1Request) *types.RawHTTP1Request {
	return r
}
func (replaceBodyRuleApplier) ApplyResponseRules(r *types.RawHTTP1Response) *types.RawHTTP1Response {
	return r
}
func (replaceBodyRuleApplier) ApplyRequestBodyOnlyRules(b []byte, _ types.Headers) ([]byte, error) {
	return b, nil
}
func (a replaceBodyRuleApplier) ApplyResponseBodyOnlyRules(b []byte, _ types.Headers) []byte {
	return bytes.ReplaceAll(b, a.find, a.replace)
}
func (replaceBodyRuleApplier) ApplyRequestHeaderOnlyRules(h types.Headers) types.Headers  { return h }
func (replaceBodyRuleApplier) ApplyResponseHeaderOnlyRules(h types.Headers) types.Headers { return h }
func (replaceBodyRuleApplier) ApplyWSRules(p []byte, _ string) []byte                     { return p }
func (replaceBodyRuleApplier) HasBodyRules(isRequest bool) bool                           { return !isRequest }

func TestHTTP1StreamingResponseWithRules(t *testing.T) {
	t.Parallel()

	gate := make(chan struct{})
	close(gate) // send both chunks immediately
	upstreamAddr := chunkedTrickleUpstream(t, gate)

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{}, false)
	require.NoError(t, err)
	proxy.SetRuleApplier(replaceBodyRuleApplier{find: []byte("one"), replace: []byte("ONE")})
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })
	require.NoError(t, proxy.WaitReady(t.Context()))

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", proxy.Addr())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	req := "GET http://" + upstreamAddr + "/events HTTP/1.1\r\nHost: " + upstreamAddr + "\r\n\r\n"
	_, err = conn.Write([]byte(req))
	require.NoError(t, err)

	received := &syncBuf{}
	go func() { _, _ = io.Copy(received, conn) }()

	// Per-unit rule mutates the streamed body on the wire
	require.Eventually(t, func() bool {
		return strings.Contains(received.String(), "data: ONE") && strings.Contains(received.String(), "data: two")
	}, 2*time.Second, 10*time.Millisecond)

	// History stores the mutated body
	require.Eventually(t, func() bool {
		flows := proxy.History().Page(1, "")
		if len(flows) != 1 || flows[0].Response == nil || flows[0].CompletedAt.IsZero() {
			return false
		}
		return strings.Contains(string(flows[0].Response.Body), "ONE")
	}, 2*time.Second, 10*time.Millisecond)
}

func TestHTTP1StreamingResponse(t *testing.T) {
	t.Parallel()

	gate := make(chan struct{})
	upstreamAddr := chunkedTrickleUpstream(t, gate)

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{}, false)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })
	require.NoError(t, proxy.WaitReady(t.Context()))

	var d net.Dialer
	conn, err := d.DialContext(t.Context(), "tcp", proxy.Addr())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	req := "GET http://" + upstreamAddr + "/events HTTP/1.1\r\nHost: " + upstreamAddr + "\r\n\r\n"
	_, err = conn.Write([]byte(req))
	require.NoError(t, err)

	received := &syncBuf{}
	go func() { _, _ = io.Copy(received, conn) }()

	// First chunk reaches the client before the upstream sends the second
	require.Eventually(t, func() bool {
		return strings.Contains(received.String(), "data: one")
	}, 2*time.Second, 10*time.Millisecond)
	assert.NotContains(t, received.String(), "data: two")

	// History shows the flow in progress with the partial body
	var flowID string
	require.Eventually(t, func() bool {
		flows := proxy.History().Page(1, "")
		if len(flows) != 1 || flows[0].Response == nil {
			return false
		}
		flowID = flows[0].FlowID
		return flows[0].CompletedAt.IsZero() && strings.Contains(string(flows[0].Response.Body), "one")
	}, 2*time.Second, 10*time.Millisecond)

	// Release the second chunk
	close(gate)

	require.Eventually(t, func() bool {
		return strings.Contains(received.String(), "data: two")
	}, 2*time.Second, 10*time.Millisecond)

	// History now shows the completed flow with the full body
	require.Eventually(t, func() bool {
		flow, ok := proxy.History().Get(flowID)
		if !ok || flow.Response == nil {
			return false
		}
		body := string(flow.Response.Body)
		return !flow.CompletedAt.IsZero() && strings.Contains(body, "one") && strings.Contains(body, "two")
	}, 2*time.Second, 10*time.Millisecond)
}

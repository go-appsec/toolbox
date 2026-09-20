package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sectool/service/testutil"
)

func TestStreamTracker(t *testing.T) {
	t.Parallel()

	t.Run("get_nonexistent", func(t *testing.T) {
		tracker := newStreamTracker()
		_, exists := tracker.get(1)
		assert.False(t, exists)
	})

	t.Run("get_or_create", func(t *testing.T) {
		tracker := newStreamTracker()
		now := time.Now()

		s1 := tracker.getOrCreate(5)
		assert.NotNil(t, s1)
		assert.Equal(t, uint32(5), s1.id)
		// getOrCreate initializes state and both timestamps
		assert.Equal(t, streamOpen, s1.state)
		assert.WithinDuration(t, now, s1.startTime, time.Second)
		assert.WithinDuration(t, now, s1.lastActivity, time.Second)

		s2 := tracker.getOrCreate(5)
		assert.Equal(t, s1, s2)
	})

	t.Run("get_existing", func(t *testing.T) {
		tracker := newStreamTracker()
		stream := tracker.getOrCreate(1)

		stream2, exists := tracker.get(1)
		assert.True(t, exists)
		assert.Equal(t, stream, stream2)
	})

	t.Run("all_streams", func(t *testing.T) {
		tracker := newStreamTracker()
		tracker.getOrCreate(1)
		tracker.getOrCreate(3)

		all := tracker.all()
		assert.Len(t, all, 2)
	})

	t.Run("remove", func(t *testing.T) {
		tracker := newStreamTracker()
		tracker.getOrCreate(1)
		tracker.getOrCreate(3)

		tracker.remove(1)
		_, exists := tracker.get(1)
		assert.False(t, exists)

		_, exists = tracker.get(3)
		assert.True(t, exists)
	})
}

// h2MockRuleApplier is a mock implementation for testing
type h2MockRuleApplier struct {
	hasReqBodyRules  bool
	hasRespBodyRules bool
	reqHeaderMod     func([]types.Header) []types.Header
	respHeaderMod    func([]types.Header) []types.Header
	reqBodyMod       func([]byte) []byte
	respBodyMod      func([]byte) []byte
}

func (m *h2MockRuleApplier) ApplyRequestRules(req *types.RawHTTP1Request) *types.RawHTTP1Request {
	if m.reqHeaderMod != nil {
		req.Headers = m.reqHeaderMod(req.Headers)
	}
	if m.reqBodyMod != nil {
		req.Body = m.reqBodyMod(req.Body)
	}
	return req
}

func (m *h2MockRuleApplier) ApplyResponseRules(resp *types.RawHTTP1Response) *types.RawHTTP1Response {
	if m.respHeaderMod != nil {
		resp.Headers = m.respHeaderMod(resp.Headers)
	}
	if m.respBodyMod != nil {
		resp.Body = m.respBodyMod(resp.Body)
	}
	return resp
}

func (m *h2MockRuleApplier) ApplyWSRules(payload []byte, direction string) []byte {
	return payload
}

func (m *h2MockRuleApplier) HasBodyRules(isRequest bool) bool {
	if isRequest {
		return m.hasReqBodyRules
	}
	return m.hasRespBodyRules
}

func (m *h2MockRuleApplier) ApplyRequestBodyOnlyRules(body []byte, headers types.Headers) ([]byte, error) {
	if m.reqBodyMod != nil {
		return m.reqBodyMod(body), nil
	}
	return body, nil
}

func (m *h2MockRuleApplier) ApplyResponseBodyOnlyRules(body []byte, headers types.Headers) []byte {
	if m.respBodyMod != nil {
		return m.respBodyMod(body)
	}
	return body
}

func (m *h2MockRuleApplier) ApplyRequestHeaderOnlyRules(headers types.Headers) types.Headers {
	if m.reqHeaderMod != nil {
		return m.reqHeaderMod(headers)
	}
	return headers
}

func (m *h2MockRuleApplier) ApplyResponseHeaderOnlyRules(headers types.Headers) types.Headers {
	if m.respHeaderMod != nil {
		return m.respHeaderMod(headers)
	}
	return headers
}

func TestApplyBodyRules(t *testing.T) {
	t.Parallel()

	t.Run("request_with_headers", func(t *testing.T) {
		handler := newHTTP2Handler(newHistoryStore(store.NewMemStorage()), 1024, TimeoutConfig{})
		applier := &h2MockRuleApplier{
			reqBodyMod: func(body []byte) []byte {
				return append(body, []byte("-modified")...)
			},
		}
		handler.SetRuleApplier(applier)

		stream := &h2Stream{
			id:         1,
			method:     "POST",
			path:       "/test",
			reqHeaders: []types.Header{{Name: "content-type", Value: "text/plain"}},
		}
		stream.reqBodyFull.WriteString("hello")

		p := &h2Proxy{handler: handler}

		result, err := p.applyBodyRules(stream, stream.reqBodyFull.Bytes(), true)
		require.NoError(t, err)
		assert.Equal(t, "hello-modified", string(result))
	})

	t.Run("response_uses_body_only", func(t *testing.T) {
		handler := newHTTP2Handler(newHistoryStore(store.NewMemStorage()), 1024, TimeoutConfig{})

		var bodyOnlyCalled, fullMethodCalled bool
		applier := &h2MockRuleApplier{
			respBodyMod: func(body []byte) []byte {
				bodyOnlyCalled = true
				return append(body, []byte("-modified")...)
			},
			respHeaderMod: func(headers []types.Header) []types.Header {
				fullMethodCalled = true
				return headers
			},
		}
		handler.SetRuleApplier(applier)

		stream := &h2Stream{
			id:          1,
			statusCode:  200,
			respHeaders: []types.Header{{Name: "content-type", Value: "text/plain"}},
		}
		stream.respBodyFull.WriteString("test body")

		p := &h2Proxy{handler: handler}

		result, err := p.applyBodyRules(stream, stream.respBodyFull.Bytes(), false)
		require.NoError(t, err)

		assert.Equal(t, "test body-modified", string(result))
		assert.True(t, bodyOnlyCalled)
		assert.False(t, fullMethodCalled)
	})
}

func TestCopyToHistoryBuffer(t *testing.T) {
	t.Parallel()

	handler := newHTTP2Handler(newHistoryStore(store.NewMemStorage()), 10, TimeoutConfig{})
	stream := &h2Stream{id: 1}
	p := &h2Proxy{handler: handler}

	p.copyToHistoryBufferLocked(stream, []byte("hello"), true)
	p.copyToHistoryBufferLocked(stream, []byte("worldextra"), true)

	assert.Equal(t, 10, stream.reqBody.Len())
	assert.Equal(t, "helloworld", stream.reqBody.String())
}

func TestCopyToFullBuffer(t *testing.T) {
	t.Parallel()

	t.Run("no_overflow", func(t *testing.T) {
		handler := newHTTP2Handler(newHistoryStore(store.NewMemStorage()), 1024, TimeoutConfig{})
		stream := &h2Stream{id: 1}
		p := &h2Proxy{handler: handler}

		overflow := p.copyToFullBufferLocked(stream, []byte("hello"), true)
		assert.False(t, overflow)
		assert.False(t, stream.reqBodyOverflow)
		assert.Equal(t, "hello", stream.reqBodyFull.String())
	})

	t.Run("overflow", func(t *testing.T) {
		handler := newHTTP2Handler(newHistoryStore(store.NewMemStorage()), 1024, TimeoutConfig{})
		stream := &h2Stream{id: 1}
		stream.reqBodyOverflow = true
		p := &h2Proxy{handler: handler}

		overflow := p.copyToFullBufferLocked(stream, []byte("more data"), true)
		assert.True(t, overflow)
	})
}

func TestUpdateHistoryWithModifiedBody(t *testing.T) {
	t.Parallel()

	handler := newHTTP2Handler(newHistoryStore(store.NewMemStorage()), 5, TimeoutConfig{})
	stream := &h2Stream{id: 1}
	stream.reqBody.WriteString("original")
	p := &h2Proxy{handler: handler}

	p.updateHistoryWithModifiedBodyLocked(stream, []byte("new body content"), true)

	assert.Equal(t, 5, stream.reqBody.Len())
	assert.Equal(t, "new b", stream.reqBody.String())
}

func TestStoreStreamInHistory(t *testing.T) {
	t.Parallel()

	newStream := func() *h2Stream {
		s := &h2Stream{
			id:          1,
			state:       streamClosed,
			method:      "GET",
			scheme:      "https",
			authority:   "test.example.com",
			path:        "/api/v1",
			statusCode:  200,
			startTime:   time.Now().Add(-100 * time.Millisecond),
			reqHeaders:  []types.Header{{Name: "user-agent", Value: "test"}},
			respHeaders: []types.Header{{Name: "content-type", Value: "application/json"}},
		}
		s.reqBody.WriteString("request body")
		s.respBody.WriteString(`{"ok": true}`)
		return s
	}
	newProxy := func() (*h2Proxy, *HistoryStore) {
		history := newHistoryStore(store.NewMemStorage())
		return &h2Proxy{handler: newHTTP2Handler(history, 1024, TimeoutConfig{}), streams: newStreamTracker()}, history
	}

	t.Run("whole_store_clean", func(t *testing.T) {
		p, history := newProxy()
		p.storeStreamInHistory(newStream(), "")

		require.Equal(t, 1, history.Count())
		entry := firstEntry(t, history)
		assert.Equal(t, "http/2", entry.ProtocolTag)
		assert.Equal(t, "1", entry.GetRequestHeader(types.HeaderStreamID))
		assert.Equal(t, "GET", entry.GetMethod())
		assert.Equal(t, "test.example.com", entry.GetHost())
		assert.Equal(t, "/api/v1", entry.GetPath())
		assert.Equal(t, "request body", string(entry.Request.Body))
		assert.Equal(t, `{"ok": true}`, string(entry.Response.Body))
		assert.False(t, entry.CompletedAt.IsZero())
		assert.Nil(t, entry.Annotations)
	})

	t.Run("truncated_reason", func(t *testing.T) {
		p, history := newProxy()
		p.storeStreamInHistory(newStream(), reasonUpstreamError)

		entry := firstEntry(t, history)
		assert.Equal(t, true, entry.Annotations[annStreamTruncated])
		assert.Equal(t, reasonUpstreamError, entry.Annotations[annStreamReason])
	})

	t.Run("body_truncated_on_clean_close", func(t *testing.T) {
		p, history := newProxy()
		stream := newStream()
		stream.respBodyHistTruncated = true
		p.storeStreamInHistory(stream, "")

		entry := firstEntry(t, history)
		assert.Equal(t, true, entry.Annotations[annBodyTruncated])
		_, truncated := entry.Annotations[annStreamTruncated]
		assert.False(t, truncated)
	})

	t.Run("skip_request_only", func(t *testing.T) {
		p, history := newProxy()
		stream := newStream()
		stream.statusCode = 0
		p.storeStreamInHistory(stream, reasonConnClosed)

		assert.Equal(t, 0, history.Count())
	})

	t.Run("idempotent_head_then_finalize", func(t *testing.T) {
		p, history := newProxy()
		stream := newStream()
		stream.state = streamOpen
		p.storeH2StreamHead(stream)
		require.NotEmpty(t, stream.flowID)
		flowID := stream.flowID

		p.storeStreamInHistory(stream, reasonConnClosed)
		p.storeStreamInHistory(stream, reasonConnClosed) // repeat teardown path

		assert.Equal(t, 1, history.Count())
		flow, ok := history.Get(flowID)
		require.True(t, ok)
		assert.False(t, flow.CompletedAt.IsZero())
		assert.Equal(t, reasonConnClosed, flow.Annotations[annStreamReason])
	})
}

func TestHTTP2ProxyEndToEnd(t *testing.T) {
	t.Parallel()

	testServer := newHTTP2TestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Protocol", r.Proto)
		w.Header().Set("X-Test-Header", "h2-success")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("Hello from HTTP/2 server"))
	})
	t.Cleanup(testServer.Close)

	proxy, client := newTestHTTP2Proxy(t)

	req, err := http.NewRequestWithContext(t.Context(), "GET", testServer.URL+"/test", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "h2-success", resp.Header.Get("X-Test-Header"))
	assert.Equal(t, "Hello from HTTP/2 server", string(body))

	assert.Equal(t, 2, resp.ProtoMajor)

	testutil.WaitForCount(t, func() int { return proxy.History().Count() }, 1)

	entry := firstEntry(t, proxy.History())
	assert.Equal(t, "http/2", entry.ProtocolTag)
	require.NotNil(t, entry.Request)
	assert.Equal(t, "GET", entry.GetMethod())
	assert.Contains(t, entry.GetPath(), "/test")
	require.NotNil(t, entry.Response)
	assert.Equal(t, 200, entry.GetStatusCode())
	assert.Contains(t, string(entry.Response.Body), "Hello from HTTP/2 server")
}

// h2MockInterceptor serves a canned response for requests matching path.
type h2MockInterceptor struct {
	path string
	resp *InterceptedResponse
}

func (m *h2MockInterceptor) InterceptRequest(_, path, _ string) *InterceptedResponse {
	if path == m.path {
		return m.resp
	}
	return nil
}

func TestHTTP2ProxyInterceptWithRequestBody(t *testing.T) {
	t.Parallel()

	var upstreamConns atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("live-ok"))
	}))
	server.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			upstreamConns.Add(1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	proxy, client := newTestHTTP2Proxy(t)

	const cannedBody = "intercepted-response"
	proxy.SetResponseInterceptor(&h2MockInterceptor{
		path: "/canned",
		resp: &InterceptedResponse{
			StatusCode: 200,
			Headers:    types.Headers{{Name: "content-type", Value: "text/plain"}},
			Body:       []byte(cannedBody),
		},
	})

	// Body large enough that DATA frames hit the proxy before the canned response is processed by the client
	reqBody := strings.Repeat("A", 128*1024)
	postReq, err := http.NewRequestWithContext(t.Context(), "POST", server.URL+"/canned", strings.NewReader(reqBody))
	require.NoError(t, err)
	postResp, err := client.Do(postReq)
	require.NoError(t, err)
	postData, err := io.ReadAll(postResp.Body)
	require.NoError(t, err)
	require.NoError(t, postResp.Body.Close())
	assert.Equal(t, 200, postResp.StatusCode)
	assert.Equal(t, cannedBody, string(postData))
	assert.Equal(t, 2, postResp.ProtoMajor)

	// Second request on the same h2 connection must still reach the upstream
	liveReq, err := http.NewRequestWithContext(t.Context(), "GET", server.URL+"/live", nil)
	require.NoError(t, err)
	liveResp, err := client.Do(liveReq)
	require.NoError(t, err)
	liveData, err := io.ReadAll(liveResp.Body)
	require.NoError(t, err)
	require.NoError(t, liveResp.Body.Close())
	assert.Equal(t, "live-ok", string(liveData))

	// One upstream connection served both: it survived rather than a GOAWAY
	assert.Equal(t, int64(1), upstreamConns.Load())
}

func TestHTTP2ProxyHeaderRules(t *testing.T) {
	t.Parallel()

	var receivedHeader string
	testServer := newHTTP2TestServer(t, func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Injected")
		w.WriteHeader(200)
	})
	t.Cleanup(testServer.Close)

	proxy, client := newTestHTTP2Proxy(t)

	applier := &h2MockRuleApplier{
		reqHeaderMod: func(headers []types.Header) []types.Header {
			return append(headers, types.Header{Name: "x-injected", Value: "rule-applied"})
		},
	}
	proxy.SetRuleApplier(applier)

	req, err := http.NewRequestWithContext(t.Context(), "GET", testServer.URL+"/test", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, "rule-applied", receivedHeader)

	assert.Equal(t, 2, resp.ProtoMajor)
}

func TestHTTP2ProxyBidirectionalLargeBody(t *testing.T) {
	t.Parallel()

	// Echo the upload back incrementally so large bodies flow in both directions at
	// once - the scenario that deadlocked the old inline-write path and silently
	// truncated on flow-control timeout.
	testServer := newHTTP2TestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		flusher, _ := w.(http.Flusher)
		chunk := make([]byte, 32*1024)
		for {
			n, readErr := r.Body.Read(chunk)
			if n > 0 {
				_, _ = w.Write(chunk[:n])
				if flusher != nil {
					flusher.Flush()
				}
			}
			if readErr != nil {
				break
			}
		}
	})
	t.Cleanup(testServer.Close)

	_, client := newTestHTTP2Proxy(t)

	const size = 4 * 1024 * 1024
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}

	// Bound runtime so a regression that reintroduces the stall fails fast
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, "POST", testServer.URL+"/echo", bytes.NewReader(payload))
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	got, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	// Full delivery both ways - no silent truncation
	assert.Len(t, got, size)
	assert.Equal(t, sha256.Sum256(payload), sha256.Sum256(got))
}

func TestPumpDataFrame(t *testing.T) {
	t.Parallel()

	newProxy := func(t *testing.T) (*h2Proxy, *h2Conn) {
		t.Helper()
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		c, _ := net.Pipe()
		t.Cleanup(func() { _ = c.Close() })
		return &h2Proxy{ctx: ctx, cancel: cancel, streams: newStreamTracker()}, newH2Conn(c)
	}

	t.Run("emits_data_frame", func(t *testing.T) {
		p, dst := newProxy(t)
		p.pumpDataFrame(&bytes.Buffer{}, dst, nil,
			h2WorkItem{kind: wiData, streamID: 1, data: []byte("hello"), endStream: true})
		assert.Len(t, dst.writeCh, 1)
	})

	t.Run("aborted_stream_skipped", func(t *testing.T) {
		p, dst := newProxy(t)
		dst.markStreamAborted(1)
		p.pumpDataFrame(&bytes.Buffer{}, dst, nil,
			h2WorkItem{kind: wiData, streamID: 1, data: []byte("hello"), endStream: true})
		assert.Empty(t, dst.writeCh)
	})

	t.Run("aborted_stream_replenishes", func(t *testing.T) {
		p, dst := newProxy(t)
		src, _ := net.Pipe()
		t.Cleanup(func() { _ = src.Close() })
		srcConn := newH2Conn(src)
		srcConn.recvWindowConn = 1000 // drained below the update threshold

		dst.markStreamAborted(1)
		p.pumpDataFrame(&bytes.Buffer{}, dst, srcConn,
			h2WorkItem{kind: wiData, streamID: 1, data: []byte("hello"), endStream: true, replenish: true})

		assert.Empty(t, dst.writeCh)
		assert.Len(t, srcConn.writeCh, 1) // connection WINDOW_UPDATE
		assert.Equal(t, int32(localInitialWindow), srcConn.recvWindowConn)
	})
}

func TestWriteFramesFlushOnCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	srv, cli := net.Pipe()
	t.Cleanup(func() { _ = srv.Close(); _ = cli.Close() })

	p := &h2Proxy{
		ctx:     ctx,
		cancel:  cancel,
		handler: newHTTP2Handler(newHistoryStore(store.NewMemStorage()), 1024, TimeoutConfig{}),
	}
	h := newH2Conn(srv)

	// queue frames, then cancel so writeFrames drains via flushRemaining
	frames := [][]byte{[]byte("frame-one"), []byte("frame-two"), []byte("frame-three")}
	for _, f := range frames {
		require.True(t, h.enqueueWrite(ctx, f))
	}
	want := bytes.Join(frames, nil)
	cancel()

	p.wg.Add(1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.writeFrames(h, srv)
	}()

	got := make([]byte, len(want))
	_, err := io.ReadFull(cli, got)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	<-done
}

func newHTTP2TestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(handler)

	server.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}
	server.StartTLS()

	return server
}

// newTestHTTP2Proxy starts a proxy and returns it with an HTTP client that trusts the
// proxy CA and prefers HTTP/2. Cleaned up on test end.
func newTestHTTP2Proxy(t *testing.T) (*ProxyServer, *http.Client) {
	t.Helper()

	proxy, err := NewProxyServer(t.Context(), 0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), store.NewMemStorage(), TimeoutConfig{}, false)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })
	require.NoError(t, proxy.WaitReady(t.Context()))

	caPool := x509.NewCertPool()
	caPool.AddCert(proxy.CertManager().CACert())
	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr())),
		TLSClientConfig:   &tls.Config{RootCAs: caPool, InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	}}
	return proxy, client
}

func TestHTTP2Streaming(t *testing.T) {
	t.Parallel()

	t.Run("in_progress_then_complete", func(t *testing.T) {
		gate := make(chan struct{})
		upstream := newHTTP2TestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			flusher := w.(http.Flusher)
			_, _ = w.Write([]byte("data: one\n\n"))
			flusher.Flush()
			<-gate
			_, _ = w.Write([]byte("data: two\n\n"))
			flusher.Flush()
		})
		t.Cleanup(upstream.Close)

		proxy, client := newTestHTTP2Proxy(t)

		req, err := http.NewRequestWithContext(t.Context(), "GET", upstream.URL+"/events", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		require.Equal(t, 2, resp.ProtoMajor)

		received := &syncBuf{}
		go func() { _, _ = io.Copy(received, resp.Body) }()

		// First event reaches the client before the second is released
		require.Eventually(t, func() bool {
			return strings.Contains(received.String(), "data: one")
		}, 3*time.Second, 10*time.Millisecond)
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
		}, 3*time.Second, 10*time.Millisecond)

		close(gate)

		require.Eventually(t, func() bool {
			return strings.Contains(received.String(), "data: two")
		}, 3*time.Second, 10*time.Millisecond)

		require.Eventually(t, func() bool {
			flow, ok := proxy.History().Get(flowID)
			if !ok || flow.Response == nil {
				return false
			}
			body := string(flow.Response.Body)
			return !flow.CompletedAt.IsZero() && strings.Contains(body, "one") && strings.Contains(body, "two")
		}, 3*time.Second, 10*time.Millisecond)
	})

	t.Run("client_cancel_finalizes", func(t *testing.T) {
		upstream := newHTTP2TestServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			flusher := w.(http.Flusher)
			_, _ = w.Write([]byte("data: one\n\n"))
			flusher.Flush()
			<-r.Context().Done() // hold the stream open until the client goes away
		})
		t.Cleanup(upstream.Close)

		proxy, client := newTestHTTP2Proxy(t)

		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		req, err := http.NewRequestWithContext(ctx, "GET", upstream.URL+"/events", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.Equal(t, 2, resp.ProtoMajor)

		head := make([]byte, len("data: one\n\n"))
		_, err = io.ReadFull(resp.Body, head)
		require.NoError(t, err)
		assert.Contains(t, string(head), "data: one")

		// Flow is head-stored and in progress while the server holds the stream open
		var flowID string
		require.Eventually(t, func() bool {
			flows := proxy.History().Page(1, "")
			if len(flows) != 1 || flows[0].Response == nil {
				return false
			}
			flowID = flows[0].FlowID
			return flows[0].CompletedAt.IsZero()
		}, 3*time.Second, 10*time.Millisecond)

		// Cancel mid-stream: abnormal teardown must finalize and mark the flow truncated
		cancel()
		_ = resp.Body.Close()

		require.Eventually(t, func() bool {
			flow, ok := proxy.History().Get(flowID)
			if !ok || flow.CompletedAt.IsZero() {
				return false
			}
			return flow.Annotations[annStreamTruncated] == true
		}, 5*time.Second, 20*time.Millisecond)
	})
}

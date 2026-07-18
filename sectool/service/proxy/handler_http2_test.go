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

		s1 := tracker.getOrCreate(5)
		assert.NotNil(t, s1)
		assert.Equal(t, uint32(5), s1.id)

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

	t.Run("remove_nonexistent", func(t *testing.T) {
		tracker := newStreamTracker()
		tracker.remove(999) // should not panic
		assert.Empty(t, tracker.all())
	})
}

func TestH2StreamInitialState(t *testing.T) {
	t.Parallel()

	tracker := newStreamTracker()
	stream := tracker.getOrCreate(1)
	now := time.Now()

	assert.Equal(t, streamOpen, stream.state)
	assert.WithinDuration(t, now, stream.startTime, time.Second)
	assert.WithinDuration(t, now, stream.lastActivity, time.Second)
	assert.Equal(t, int32(initialWindowSize), stream.window)
	assert.False(t, stream.reqBodyComplete)
	assert.False(t, stream.respBodyComplete)
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

func TestH2ConnConsumeRecvWindow(t *testing.T) {
	t.Parallel()

	t.Run("successful_consume", func(t *testing.T) {
		h := &h2Conn{
			initialWindowSize: 65535,
			recvWindowConn:    65535,
			recvWindowStream:  make(map[uint32]int32),
		}

		err := h.consumeRecvWindow(1, 1000)
		require.NoError(t, err)
		assert.Equal(t, int32(65535-1000), h.recvWindowConn)
		assert.Equal(t, int32(65535-1000), h.recvWindowStream[1])

		err = h.consumeRecvWindow(1, 2000)
		require.NoError(t, err)
		assert.Equal(t, int32(65535-3000), h.recvWindowConn)
	})

	t.Run("connection_level_violation", func(t *testing.T) {
		h := &h2Conn{
			initialWindowSize: 65535,
			recvWindowConn:    1000,
			recvWindowStream:  make(map[uint32]int32),
		}

		err := h.consumeRecvWindow(1, 2000)
		require.Error(t, err)

		var fcErr *flowControlError
		require.ErrorAs(t, err, &fcErr)
		assert.Equal(t, uint32(0), fcErr.StreamID)

		assert.Equal(t, int32(1000), h.recvWindowConn)
	})

	t.Run("stream_level_violation", func(t *testing.T) {
		h := &h2Conn{
			initialWindowSize: 65535,
			recvWindowConn:    65535,
			recvWindowStream:  map[uint32]int32{1: 500},
		}

		err := h.consumeRecvWindow(1, 1000)
		require.Error(t, err)

		var fcErr *flowControlError
		require.ErrorAs(t, err, &fcErr)
		assert.Equal(t, uint32(1), fcErr.StreamID)

		assert.Equal(t, int32(65535), h.recvWindowConn)
		assert.Equal(t, int32(500), h.recvWindowStream[1])
	})
}

func TestH2ConnNeedsWindowUpdate(t *testing.T) {
	t.Parallel()

	h := &h2Conn{
		initialWindowSize: 65535,
		recvWindowConn:    65535,
		recvWindowStream:  make(map[uint32]int32),
	}

	connUp, streamUp := h.needsWindowUpdate(1)
	assert.Equal(t, uint32(0), connUp)
	assert.Equal(t, uint32(0), streamUp)

	require.NoError(t, h.consumeRecvWindow(1, 40000))

	connUp, streamUp = h.needsWindowUpdate(1)
	assert.Positive(t, connUp)
	assert.Positive(t, streamUp)

	assert.Equal(t, int32(65535), h.recvWindowConn)
	assert.Equal(t, int32(65535), h.recvWindowStream[1])
}

func TestH2ConnRemoveStreamWindow(t *testing.T) {
	t.Parallel()

	h := &h2Conn{
		initialWindowSize: 65535,
		recvWindowConn:    65535,
		recvWindowStream:  make(map[uint32]int32),
	}

	require.NoError(t, h.consumeRecvWindow(1, 1000))
	require.NoError(t, h.consumeRecvWindow(3, 500))
	assert.Len(t, h.recvWindowStream, 2)

	h.removeStreamWindow(1)
	assert.Len(t, h.recvWindowStream, 1)
	_, ok := h.recvWindowStream[1]
	assert.False(t, ok)
	_, ok = h.recvWindowStream[3]
	assert.True(t, ok)
}

func TestH2ConnClose(t *testing.T) {
	t.Parallel()

	h := &h2Conn{
		closeCh: make(chan struct{}),
	}

	h.close()
	select {
	case <-h.closeCh:
	default:
		t.Fatal("closeCh should be closed")
	}

	h.close() // should not panic
}

func TestH2ConnEnqueueWrite(t *testing.T) {
	t.Parallel()

	t.Run("closed_connection", func(t *testing.T) {
		h := &h2Conn{
			writeCh: make(chan []byte),
			closeCh: make(chan struct{}),
		}

		h.close()

		ok := h.enqueueWrite(t.Context(), []byte("test"))
		assert.False(t, ok)
	})

	t.Run("successful_enqueue", func(t *testing.T) {
		h := &h2Conn{
			writeCh: make(chan []byte, 1),
			closeCh: make(chan struct{}),
		}

		ok := h.enqueueWrite(t.Context(), []byte("test"))
		assert.True(t, ok)

		data := <-h.writeCh
		assert.Equal(t, []byte("test"), data)
	})
}

func TestH2ConnFlowCtrlWait(t *testing.T) {
	t.Parallel()

	t.Run("signaled_on_window_update", func(t *testing.T) {
		h := &h2Conn{
			initialWindowSize: 65535,
			sendWindowConn:    0,
			sendWindowStream:  make(map[uint32]int32),
			flowCtrlCh:        make(chan struct{}),
		}

		waitCh := h.flowCtrlWait()

		select {
		case <-waitCh:
			t.Fatal("channel should not be closed yet")
		default:
		}

		h.updateSendWindow(0, 1000)

		select {
		case <-waitCh:
		default:
			t.Fatal("channel should be closed after updateSendWindow")
		}

		waitCh2 := h.flowCtrlWait()
		select {
		case <-waitCh2:
			t.Fatal("new channel should not be closed")
		default:
		}
	})

	t.Run("signaled_on_settings_increase", func(t *testing.T) {
		h := &h2Conn{
			initialWindowSize: 65535,
			sendWindowConn:    65535,
			sendWindowStream:  make(map[uint32]int32),
			flowCtrlCh:        make(chan struct{}),
		}

		h.initStreamSendWindow(1)

		waitCh := h.flowCtrlWait()

		h.updateSendWindowFromSettings(131070)

		select {
		case <-waitCh:
		default:
			t.Fatal("channel should be closed after settings increase")
		}
	})

	t.Run("not_signaled_on_decrease", func(t *testing.T) {
		h := &h2Conn{
			initialWindowSize: 65535,
			sendWindowConn:    65535,
			sendWindowStream:  make(map[uint32]int32),
			flowCtrlCh:        make(chan struct{}),
		}

		h.initStreamSendWindow(1)

		waitCh := h.flowCtrlWait()

		h.updateSendWindowFromSettings(32768)

		select {
		case <-waitCh:
			t.Fatal("channel should not be closed on settings decrease")
		default:
		}
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

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{}, false)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(proxy.CertManager().CACert())

	transport := &http.Transport{
		Proxy: http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr())),
		TLSClientConfig: &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: transport}

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

func (m *h2MockInterceptor) InterceptRequest(_ string, _ int, path string, _ string) *InterceptedResponse {
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

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{}, false)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	const cannedBody = "intercepted-response"
	proxy.SetResponseInterceptor(&h2MockInterceptor{
		path: "/canned",
		resp: &InterceptedResponse{
			StatusCode: 200,
			Headers:    types.Headers{{Name: "content-type", Value: "text/plain"}},
			Body:       []byte(cannedBody),
		},
	})

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(proxy.CertManager().CACert())
	transport := &http.Transport{
		Proxy:             http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr())),
		TLSClientConfig:   &tls.Config{RootCAs: caCertPool, InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: transport}

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

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{}, false)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	applier := &h2MockRuleApplier{
		reqHeaderMod: func(headers []types.Header) []types.Header {
			return append(headers, types.Header{Name: "x-injected", Value: "rule-applied"})
		},
	}
	proxy.SetRuleApplier(applier)

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(proxy.CertManager().CACert())

	transport := &http.Transport{
		Proxy: http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr())),
		TLSClientConfig: &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: transport}

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

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{}, false)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(proxy.CertManager().CACert())
	transport := &http.Transport{
		Proxy: http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr())),
		TLSClientConfig: &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: transport}

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
}

func TestFlushRemaining(t *testing.T) {
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

func TestH2StreamTimestamps(t *testing.T) {
	t.Parallel()

	tracker := newStreamTracker()

	now := time.Now()
	stream := tracker.getOrCreate(1)

	assert.WithinDuration(t, now, stream.startTime, 100*time.Millisecond)
	assert.WithinDuration(t, now, stream.lastActivity, 100*time.Millisecond)

	// Update last activity slightly in the future
	stream.mu.Lock()
	stream.lastActivity = stream.startTime.Add(10 * time.Millisecond)
	stream.mu.Unlock()

	assert.True(t, stream.lastActivity.After(stream.startTime))
}

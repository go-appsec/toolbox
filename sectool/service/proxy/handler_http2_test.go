package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/llm-security-toolbox/sectool/service/store"
	"github.com/go-appsec/llm-security-toolbox/sectool/service/testutil"
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
	reqHeaderMod     func([]Header) []Header
	respHeaderMod    func([]Header) []Header
	reqBodyMod       func([]byte) []byte
	respBodyMod      func([]byte) []byte
}

func (m *h2MockRuleApplier) ApplyRequestRules(req *RawHTTP1Request) *RawHTTP1Request {
	if m.reqHeaderMod != nil {
		req.Headers = m.reqHeaderMod(req.Headers)
	}
	if m.reqBodyMod != nil {
		req.Body = m.reqBodyMod(req.Body)
	}
	return req
}

func (m *h2MockRuleApplier) ApplyResponseRules(resp *RawHTTP1Response) *RawHTTP1Response {
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

func (m *h2MockRuleApplier) ApplyRequestBodyOnlyRules(body []byte, headers Headers) ([]byte, error) {
	if m.reqBodyMod != nil {
		return m.reqBodyMod(body), nil
	}
	return body, nil
}

func (m *h2MockRuleApplier) ApplyResponseBodyOnlyRules(body []byte, headers Headers) []byte {
	if m.respBodyMod != nil {
		return m.respBodyMod(body)
	}
	return body
}

func TestApplyBodyRules(t *testing.T) {
	t.Parallel()

	t.Run("request_with_headers", func(t *testing.T) {
		handler := newHTTP2Handler(newHistoryStore(store.NewMemStorage()), 1024)
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
			reqHeaders: []Header{{Name: "content-type", Value: "text/plain"}},
		}
		stream.reqBodyFull.WriteString("hello")

		p := &h2Proxy{handler: handler}

		result, err := p.applyBodyRules(stream, stream.reqBodyFull.Bytes(), true)
		require.NoError(t, err)
		assert.Equal(t, "hello-modified", string(result))
	})

	t.Run("response_uses_body_only", func(t *testing.T) {
		handler := newHTTP2Handler(newHistoryStore(store.NewMemStorage()), 1024)

		var bodyOnlyCalled, fullMethodCalled bool
		applier := &h2MockRuleApplier{
			respBodyMod: func(body []byte) []byte {
				bodyOnlyCalled = true
				return append(body, []byte("-modified")...)
			},
			respHeaderMod: func(headers []Header) []Header {
				fullMethodCalled = true
				return headers
			},
		}
		handler.SetRuleApplier(applier)

		stream := &h2Stream{
			id:          1,
			statusCode:  200,
			respHeaders: []Header{{Name: "content-type", Value: "text/plain"}},
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
	handler := newHTTP2Handler(newHistoryStore(store.NewMemStorage()), 10)
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
		handler := newHTTP2Handler(newHistoryStore(store.NewMemStorage()), 1024)
		stream := &h2Stream{id: 1}
		p := &h2Proxy{handler: handler}

		overflow := p.copyToFullBufferLocked(stream, []byte("hello"), true)
		assert.False(t, overflow)
		assert.False(t, stream.reqBodyOverflow)
		assert.Equal(t, "hello", stream.reqBodyFull.String())
	})

	t.Run("overflow", func(t *testing.T) {
		handler := newHTTP2Handler(newHistoryStore(store.NewMemStorage()), 1024)
		stream := &h2Stream{id: 1}
		stream.reqBodyOverflow = true
		p := &h2Proxy{handler: handler}

		overflow := p.copyToFullBufferLocked(stream, []byte("more data"), true)
		assert.True(t, overflow)
	})
}

func TestUpdateHistoryWithModifiedBody(t *testing.T) {
	t.Parallel()

	handler := newHTTP2Handler(newHistoryStore(store.NewMemStorage()), 5)
	stream := &h2Stream{id: 1}
	stream.reqBody.WriteString("original")
	p := &h2Proxy{handler: handler}

	p.updateHistoryWithModifiedBodyLocked(stream, []byte("new body content"), true)

	assert.Equal(t, 5, stream.reqBody.Len())
	assert.Equal(t, "new b", stream.reqBody.String())
}

func TestStoreStreamInHistory(t *testing.T) {
	t.Parallel()

	history := newHistoryStore(store.NewMemStorage())
	handler := newHTTP2Handler(history, 1024)
	stream := &h2Stream{
		id:          1,
		state:       streamClosed,
		method:      "GET",
		scheme:      "https",
		authority:   "test.example.com",
		path:        "/api/v1",
		statusCode:  200,
		startTime:   time.Now().Add(-100 * time.Millisecond),
		reqHeaders:  []Header{{Name: "user-agent", Value: "test"}},
		respHeaders: []Header{{Name: "content-type", Value: "application/json"}},
	}
	stream.reqBody.WriteString("request body")
	stream.respBody.WriteString(`{"ok": true}`)
	p := &h2Proxy{
		handler: handler,
		streams: newStreamTracker(),
	}

	p.storeStreamInHistory(stream)

	assert.Equal(t, 1, history.Count())

	entry, ok := history.Get(0)
	require.True(t, ok)
	assert.Equal(t, "h2", entry.Protocol)
	assert.Equal(t, uint32(1), entry.H2StreamID)
	require.NotNil(t, entry.H2Request)
	assert.Equal(t, "GET", entry.H2Request.Method)
	assert.Equal(t, "https", entry.H2Request.Scheme)
	assert.Equal(t, "test.example.com", entry.H2Request.Authority)
	assert.Equal(t, "/api/v1", entry.H2Request.Path)
	assert.Equal(t, "request body", string(entry.H2Request.Body))
	require.NotNil(t, entry.H2Response)
	assert.Equal(t, 200, entry.H2Response.StatusCode)
	assert.Equal(t, `{"ok": true}`, string(entry.H2Response.Body))
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

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage())
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

	entry, ok := proxy.History().Get(0)
	require.True(t, ok)
	assert.Equal(t, "h2", entry.Protocol)
	require.NotNil(t, entry.H2Request)
	assert.Equal(t, "GET", entry.H2Request.Method)
	assert.Contains(t, entry.H2Request.Path, "/test")
	require.NotNil(t, entry.H2Response)
	assert.Equal(t, 200, entry.H2Response.StatusCode)
	assert.Contains(t, string(entry.H2Response.Body), "Hello from HTTP/2 server")
}

func TestHTTP2ProxyHeaderRules(t *testing.T) {
	t.Parallel()

	var receivedHeader string
	testServer := newHTTP2TestServer(t, func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Injected")
		w.WriteHeader(200)
	})
	t.Cleanup(testServer.Close)

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage())
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	applier := &h2MockRuleApplier{
		reqHeaderMod: func(headers []Header) []Header {
			return append(headers, Header{Name: "x-injected", Value: "rule-applied"})
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
	_ = resp.Body.Close()

	assert.Equal(t, "rule-applied", receivedHeader)

	assert.Equal(t, 2, resp.ProtoMajor)
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

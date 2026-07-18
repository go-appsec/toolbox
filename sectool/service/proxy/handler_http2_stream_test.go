package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/store"
)

func TestHTTP2StreamingResponse(t *testing.T) {
	t.Parallel()

	gate := make(chan struct{})
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte("data: one\n\n"))
		flusher.Flush()
		<-gate
		_, _ = w.Write([]byte("data: two\n\n"))
		flusher.Flush()
	}))
	upstream.TLS = &tls.Config{NextProtos: []string{"h2"}}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{}, false)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })
	require.NoError(t, proxy.WaitReady(t.Context()))

	caPool := x509.NewCertPool()
	caPool.AddCert(proxy.CertManager().CACert())
	transport := &http.Transport{
		Proxy: http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr())),
		TLSClientConfig: &tls.Config{
			RootCAs:            caPool,
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: transport}

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
}

func TestHTTP2StreamingClientCancelFinalizes(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte("data: one\n\n"))
		flusher.Flush()
		<-r.Context().Done() // hold the stream open until the client goes away
	}))
	upstream.TLS = &tls.Config{NextProtos: []string{"h2"}}
	upstream.StartTLS()
	t.Cleanup(upstream.Close)

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{}, false)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })
	require.NoError(t, proxy.WaitReady(t.Context()))

	caPool := x509.NewCertPool()
	caPool.AddCert(proxy.CertManager().CACert())
	transport := &http.Transport{
		Proxy: http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr())),
		TLSClientConfig: &tls.Config{
			RootCAs:            caPool,
			InsecureSkipVerify: true,
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: transport}

	ctx, cancel := context.WithCancel(context.Background())
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
}

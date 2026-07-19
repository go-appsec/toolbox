package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/store"
	"github.com/go-appsec/toolbox/sectool/service/testutil"
)

func TestParseConnectRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{
			name:     "standard_with_port",
			input:    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantHost: "example.com",
			wantPort: 443,
		},
		{
			name:     "no_port_defaults_443",
			input:    "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantHost: "example.com",
			wantPort: 443,
		},
		{
			name:     "with_extra_headers",
			input:    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic abc\r\n\r\n",
			wantHost: "example.com",
			wantPort: 443,
		},
		{
			name:    "invalid_not_connect",
			input:   "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantErr: true,
		},
		{
			name:    "empty_line",
			input:   "\r\n",
			wantErr: true,
		},
		{
			name:    "invalid_port_non_numeric",
			input:   "CONNECT example.com:abc HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantErr: true,
		},
		{
			name:     "port_zero",
			input:    "CONNECT example.com:0 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantHost: "example.com",
			wantPort: 0,
		},
		{
			name:     "empty_hostname_with_port",
			input:    "CONNECT :443 HTTP/1.1\r\nHost: :443\r\n\r\n",
			wantHost: "",
			wantPort: 443,
		},
		{
			name:     "ipv6_with_brackets",
			input:    "CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n",
			wantHost: "::1",
			wantPort: 443,
		},
		{
			name:     "ipv6_full_with_brackets",
			input:    "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\n",
			wantHost: "2001:db8::1",
			wantPort: 8443,
		},
		{
			name:     "high_port",
			input:    "CONNECT example.com:65535 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantHost: "example.com",
			wantPort: 65535,
		},
		{
			name:     "port_out_of_range",
			input:    "CONNECT example.com:70000 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			wantHost: "example.com",
			wantPort: 70000, // permissive parsing for security testing
		},
		{
			name:     "ipv4_with_port",
			input:    "CONNECT 192.168.1.1:443 HTTP/1.1\r\nHost: 192.168.1.1:443\r\n\r\n",
			wantHost: "192.168.1.1",
			wantPort: 443,
		},
		{
			name:     "subdomain_with_hyphens",
			input:    "CONNECT my-sub-domain.example.com:443 HTTP/1.1\r\nHost: my-sub-domain.example.com\r\n\r\n",
			wantHost: "my-sub-domain.example.com",
			wantPort: 443,
		},
		{
			name:     "missing_http_version",
			input:    "CONNECT example.com:443\r\nHost: example.com\r\n\r\n",
			wantHost: "example.com",
			wantPort: 443, // permissive parsing - HTTP version not required
		},
		{
			name:     "single_label_domain",
			input:    "CONNECT localhost:8443 HTTP/1.1\r\nHost: localhost:8443\r\n\r\n",
			wantHost: "localhost",
			wantPort: 8443,
		},
		{
			name:     "domain_with_underscore",
			input:    "CONNECT my_server.local:443 HTTP/1.1\r\nHost: my_server.local\r\n\r\n",
			wantHost: "my_server.local",
			wantPort: 443,
		},
		{
			name:     "long_domain",
			input:    "CONNECT very.long.subdomain.chain.example.com:443 HTTP/1.1\r\nHost: very.long.subdomain.chain.example.com\r\n\r\n",
			wantHost: "very.long.subdomain.chain.example.com",
			wantPort: 443,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &connectHandler{}
			reader := bufio.NewReader(strings.NewReader(tc.input))

			target, err := h.parseConnectRequest(reader)

			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, target)
			assert.Equal(t, tc.wantHost, target.Hostname)
			assert.Equal(t, tc.wantPort, target.Port)
			assert.True(t, target.UsesHTTPS)
		})
	}
}

func TestHandle(t *testing.T) {
	t.Parallel()

	t.Run("connection_established", func(t *testing.T) {
		t.Parallel()

		proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{}, false)
		require.NoError(t, err)
		go func() { _ = proxy.Serve() }()
		t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

		var d net.Dialer
		conn, err := d.DialContext(t.Context(), "tcp", proxy.Addr())
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		_, err = conn.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		require.NoError(t, err)

		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		line, err := reader.ReadString('\n')
		require.NoError(t, err)

		assert.Contains(t, line, "200 Connection Established")
	})

	t.Run("https_end_to_end", func(t *testing.T) {
		t.Parallel()

		testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Test-Response", "success")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("Hello from HTTPS server"))
		}))
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
		assert.Equal(t, "success", resp.Header.Get("X-Test-Response"))
		assert.Equal(t, "Hello from HTTPS server", string(body))

		// Streamed response: wait for the body to finish accumulating, not just the head
		require.Eventually(t, func() bool {
			flows := proxy.History().Page(1, "")
			return len(flows) == 1 && flows[0].Response != nil && !flows[0].CompletedAt.IsZero()
		}, 10*time.Second, time.Millisecond)

		entry := firstEntry(t, proxy.History())
		assert.Equal(t, "http/1.1", entry.ProtocolTag)
		assert.Equal(t, "GET", entry.Request.Method)
		assert.Equal(t, 200, entry.Response.StatusCode)
		assert.Contains(t, string(entry.Response.Body), "Hello from HTTPS server")
		assert.Equal(t, "https", entry.Scheme)
		wantPort, _ := strconv.Atoi(mustParseURL(t, testServer.URL).Port())
		assert.Equal(t, wantPort, entry.Port)
	})

	t.Run("headers_preserved", func(t *testing.T) {
		t.Parallel()

		var receivedHeaders http.Header
		testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			w.WriteHeader(200)
		}))
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
		}
		client := &http.Client{Transport: transport}

		req, err := http.NewRequestWithContext(t.Context(), "GET", testServer.URL+"/test", nil)
		require.NoError(t, err)
		req.Header.Set("X-Custom-Header", "test-value")
		req.Header.Set("Authorization", "Bearer token123")

		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()

		assert.Equal(t, "test-value", receivedHeaders.Get("X-Custom-Header"))
		assert.Equal(t, "Bearer token123", receivedHeaders.Get("Authorization"))
	})

	t.Run("pipelined_clienthello", func(t *testing.T) {
		t.Parallel()

		testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("pipelined ok"))
		}))
		t.Cleanup(testServer.Close)

		proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{}, false)
		require.NoError(t, err)
		go func() { _ = proxy.Serve() }()
		t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

		target := mustParseURL(t, testServer.URL).Host

		var d net.Dialer
		raw, err := d.DialContext(t.Context(), "tcp", proxy.Addr())
		require.NoError(t, err)
		t.Cleanup(func() { _ = raw.Close() })
		// Deadline guards against a regression hanging the handshake
		require.NoError(t, raw.SetDeadline(time.Now().Add(10*time.Second)))

		pc := &pipelineConn{
			Conn:       raw,
			br:         bufio.NewReader(raw),
			connectReq: []byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"),
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AddCert(proxy.CertManager().CACert())
		tlsConn := tls.Client(pc, &tls.Config{RootCAs: caCertPool, InsecureSkipVerify: true})
		require.NoError(t, tlsConn.HandshakeContext(t.Context()))

		_, err = tlsConn.Write([]byte("GET /test HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n"))
		require.NoError(t, err)

		respData, err := io.ReadAll(tlsConn)
		require.NoError(t, err)
		assert.Contains(t, string(respData), "pipelined ok")

		testutil.WaitForCount(t, func() int { return proxy.History().Count() }, 1)
		entry := firstEntry(t, proxy.History())
		assert.Equal(t, "GET", entry.Request.Method)
		assert.Equal(t, "https", entry.Scheme)
	})
}

func TestHandleClientProtoReconciliation(t *testing.T) {
	t.Parallel()

	testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("proto=" + r.Proto))
	}))
	testServer.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	testServer.StartTLS()
	t.Cleanup(testServer.Close)

	proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{}, false)
	require.NoError(t, err)
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(proxy.CertManager().CACert())
	target := mustParseURL(t, testServer.URL).Host

	// seed the caps cache to h2 with an ALPN-offering client
	h2Client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(mustParseURL(t, "http://"+proxy.Addr())),
		TLSClientConfig:   &tls.Config{RootCAs: caCertPool, InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	}}
	req, err := http.NewRequestWithContext(t.Context(), "GET", testServer.URL+"/seed", nil)
	require.NoError(t, err)
	resp, err := h2Client.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, "HTTP/2.0", resp.Proto)
	require.Contains(t, string(body), "proto=HTTP/2.0")

	// no-ALPN client to the same host must be reconciled to HTTP/1.1, not misrouted to h2
	var d net.Dialer
	raw, err := d.DialContext(t.Context(), "tcp", proxy.Addr())
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	require.NoError(t, raw.SetDeadline(time.Now().Add(10*time.Second)))

	_, err = raw.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
	require.NoError(t, err)
	br := bufio.NewReader(raw)
	statusLine, err := br.ReadString('\n')
	require.NoError(t, err)
	require.Contains(t, statusLine, "200 Connection Established")
	for { // drain remaining CONNECT response headers
		line, err := br.ReadString('\n')
		require.NoError(t, err)
		if strings.TrimSpace(line) == "" {
			break
		}
	}

	// nil NextProtos means the client offers no ALPN
	tlsConn := tls.Client(&readerConn{Conn: raw, r: br}, &tls.Config{RootCAs: caCertPool, InsecureSkipVerify: true})
	require.NoError(t, tlsConn.HandshakeContext(t.Context()))
	require.Empty(t, tlsConn.ConnectionState().NegotiatedProtocol)

	_, err = tlsConn.Write([]byte("GET /noalpn HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err)
	noAlpnResp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	require.NoError(t, err)
	noAlpnBody, err := io.ReadAll(noAlpnResp.Body)
	require.NoError(t, err)
	_ = noAlpnResp.Body.Close()

	assert.Equal(t, 200, noAlpnResp.StatusCode)
	assert.Contains(t, string(noAlpnBody), "proto=HTTP/1.1")
}

func TestProbeOrConnect(t *testing.T) {
	t.Parallel()

	// dualProtoProxy serves h2 and http/1.1 upstream through a fresh proxy, returning the
	// upstream host:port, a CA pool trusting the proxy, and the proxy itself
	dualProtoProxy := func(t *testing.T) (string, *x509.CertPool, *ProxyServer) {
		t.Helper()

		testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("proto=" + r.Proto))
		}))
		testServer.TLS = &tls.Config{NextProtos: []string{alpnH2, alpnHTTP1}}
		testServer.StartTLS()
		t.Cleanup(testServer.Close)

		proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{}, false)
		require.NoError(t, err)
		go func() { _ = proxy.Serve() }()
		t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

		caCertPool := x509.NewCertPool()
		caCertPool.AddCert(proxy.CertManager().CACert())
		return mustParseURL(t, testServer.URL).Host, caCertPool, proxy
	}

	// alpnClient builds a proxied client offering exactly the given ALPN protocols
	alpnClient := func(proxy *ProxyServer, pool *x509.CertPool, alpn ...string) *http.Client {
		return &http.Client{Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxy.Addr()}),
			TLSClientConfig: &tls.Config{
				RootCAs:            pool,
				InsecureSkipVerify: true,
				NextProtos:         alpn,
			},
			ForceAttemptHTTP2: slices.Contains(alpn, alpnH2),
		}}
	}

	fetch := func(t *testing.T, client *http.Client, target string) string {
		t.Helper()

		req, err := http.NewRequestWithContext(t.Context(), "GET", "https://"+target+"/probe", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return string(body)
	}

	t.Run("h2_then_h1_only_client", func(t *testing.T) {
		t.Parallel()

		target, pool, proxy := dualProtoProxy(t)

		require.Equal(t, "proto=HTTP/2.0", fetch(t, alpnClient(proxy, pool, alpnH2, alpnHTTP1), target))
		assert.Equal(t, "proto=HTTP/1.1", fetch(t, alpnClient(proxy, pool, alpnHTTP1), target))
	})

	t.Run("h1_then_h2_only_client", func(t *testing.T) {
		t.Parallel()

		target, pool, proxy := dualProtoProxy(t)

		require.Equal(t, "proto=HTTP/1.1", fetch(t, alpnClient(proxy, pool, alpnHTTP1), target))
		assert.Equal(t, "proto=HTTP/2.0", fetch(t, alpnClient(proxy, pool, alpnH2), target))
	})

	t.Run("stale_entry_refreshed", func(t *testing.T) {
		t.Parallel()

		target, pool, proxy := dualProtoProxy(t)
		h := proxy.connectHandler

		h.capsMu.Lock()
		h.serverCaps[target] = serverCap{proto: alpnHTTP1, seen: time.Now().Add(-2 * serverCapTTL)}
		h.capsMu.Unlock()
		_, ok := h.cachedProto(target)
		require.False(t, ok)

		// expired entry ignored, so the h2 client probes fresh and refreshes the cache
		assert.Equal(t, "proto=HTTP/2.0", fetch(t, alpnClient(proxy, pool, alpnH2), target))
		cached, ok := h.cachedProto(target)
		require.True(t, ok)
		assert.Equal(t, alpnH2, cached)
	})

	t.Run("no_alpn_client_not_cached", func(t *testing.T) {
		t.Parallel()

		target, pool, proxy := dualProtoProxy(t)
		h := proxy.connectHandler

		host, _, err := net.SplitHostPort(target)
		require.NoError(t, err)
		conn, proto, err := h.probeOrConnect(t.Context(), target, host, nil)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		assert.Equal(t, alpnHTTP1, proto)

		_, ok := h.cachedProto(target)
		assert.False(t, ok)

		// h2 traffic is still able to negotiate h2
		assert.Equal(t, "proto=HTTP/2.0", fetch(t, alpnClient(proxy, pool, alpnH2), target))
	})
}

func TestAlpnForClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		clientALPN []string
		upstream   string
		want       []string
	}{
		{
			name:       "client_offers_upstream",
			clientALPN: []string{alpnH2, alpnHTTP1},
			upstream:   alpnH2,
			want:       []string{alpnH2},
		},
		{
			name:       "client_lacks_upstream",
			clientALPN: []string{alpnHTTP1},
			upstream:   alpnH2,
		},
		{
			name:     "empty_client_list",
			upstream: alpnH2,
		},
		{
			name:       "empty_upstream",
			clientALPN: []string{alpnHTTP1},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, alpnForClient(tc.clientALPN, tc.upstream))
		})
	}
}

func TestUpstreamMirrorSpec(t *testing.T) {
	t.Parallel()

	t.Run("mirrors_upstream_sans", func(t *testing.T) {
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{multiSANServerCert(t)},
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = conn.(*tls.Conn).HandshakeContext(t.Context())
		}()

		d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}}
		conn, err := d.DialContext(t.Context(), "tcp", ln.Addr().String())
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		spec := upstreamMirrorSpec(conn)
		require.NotNil(t, spec)
		assert.Contains(t, spec.DNSNames, "a.example.com")
		assert.Contains(t, spec.DNSNames, "b.example.com")
		assert.Equal(t, "cn.example.com", spec.CommonName)
		require.Len(t, spec.URIs, 1)
		assert.Equal(t, "spiffe://example.com/svc", spec.URIs[0].String())
	})

	t.Run("non_tls_conn_yields_nil", func(t *testing.T) {
		c1, c2 := net.Pipe()
		t.Cleanup(func() { _ = c1.Close() })
		t.Cleanup(func() { _ = c2.Close() })
		assert.Nil(t, upstreamMirrorSpec(c1))
	})
}

// multiSANServerCert builds a self-signed leaf carrying several SAN types and a CN.
func multiSANServerCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cn.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"a.example.com", "b.example.com"},
		URIs:         []*url.URL{mustParseURL(t, "spiffe://example.com/svc")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()

	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return u
}

// pipelineConn forces the CONNECT request to share its first segment with the client's first
// write (the TLS ClientHello) and strips the proxy's CONNECT 200 response from the read stream,
// simulating a client that pipelines without waiting for the 200.
type pipelineConn struct {
	net.Conn
	br          *bufio.Reader
	connectReq  []byte
	sentConnect bool
	strippedOK  bool
}

func (c *pipelineConn) Write(p []byte) (int, error) {
	if !c.sentConnect {
		c.sentConnect = true
		if _, err := c.Conn.Write(append(slices.Clone(c.connectReq), p...)); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *pipelineConn) Read(p []byte) (int, error) {
	if !c.strippedOK {
		for {
			line, err := c.br.ReadString('\n')
			if err != nil {
				return 0, err
			}
			if strings.TrimSpace(line) == "" {
				break
			}
		}
		c.strippedOK = true
	}
	return c.br.Read(p)
}

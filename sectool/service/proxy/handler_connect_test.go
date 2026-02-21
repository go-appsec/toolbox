package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

		proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{})
		require.NoError(t, err)
		go func() { _ = proxy.Serve() }()
		t.Cleanup(func() { _ = proxy.Shutdown(context.Background()) })

		conn, err := net.Dial("tcp", proxy.Addr())
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

		proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{})
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

		testutil.WaitForCount(t, func() int { return proxy.History().Count() }, 1)

		entry, ok := proxy.History().Get(0)
		require.True(t, ok)
		assert.Equal(t, "http/1.1", entry.Protocol)
		assert.Equal(t, "GET", entry.Request.Method)
		assert.Equal(t, 200, entry.Response.StatusCode)
		assert.Contains(t, string(entry.Response.Body), "Hello from HTTPS server")
	})

	t.Run("headers_preserved", func(t *testing.T) {
		t.Parallel()

		var receivedHeaders http.Header
		testServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			w.WriteHeader(200)
		}))
		t.Cleanup(testServer.Close)

		proxy, err := NewProxyServer(0, t.TempDir(), 10*1024*1024, store.NewMemStorage(), TimeoutConfig{})
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
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()

	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return u
}

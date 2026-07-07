package sidecar

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

func TestFlowDest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		flow   *types.Flow
		host   string
		port   int
		scheme string
	}{
		{
			name: "host_header_with_port",
			flow: &types.Flow{Scheme: "https", Port: 8443, Request: &types.Message{
				Headers: types.Headers{{Name: "Host", Value: "echo.test:8443"}},
			}},
			host: "echo.test", port: 8443, scheme: "https",
		},
		{
			name: "host_header_no_port",
			flow: &types.Flow{Scheme: "http", Port: 80, Request: &types.Message{
				Headers: types.Headers{{Name: "Host", Value: "example.com"}},
			}},
			host: "example.com", port: 80, scheme: "http",
		},
		{
			name: "no_request_side",
			flow: &types.Flow{Scheme: "https", Port: 443},
			host: "", port: 443, scheme: "https",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, port, scheme := flowDest(tc.flow)
			assert.Equal(t, tc.host, host)
			assert.Equal(t, tc.port, port)
			assert.Equal(t, tc.scheme, scheme)
		})
	}
}

func TestResolveDest(t *testing.T) {
	t.Parallel()

	flows := newFakeFlows()
	parentID := flows.Store(&types.Flow{Scheme: "https", Port: 8443, Request: &types.Message{
		Headers: types.Headers{{Name: "Host", Value: "echo.test:8443"}},
	}})
	noDestID := flows.Store(&types.Flow{}) // no request host, port 0
	s := &session{m: managerWithFlows(flows)}
	rec := &Record{Name: "demo"}

	tests := []struct {
		name       string
		p          wire.DialUpstreamParams
		wantHost   string
		wantPort   int
		wantScheme string
		wantCode   int // 0 means no error
	}{
		{
			name:     "explicit_host_port",
			p:        wire.DialUpstreamParams{Host: "h", Port: 80},
			wantHost: "h", wantPort: 80,
		},
		{
			name:     "explicit_with_tls",
			p:        wire.DialUpstreamParams{Host: "h", Port: 443, TLS: &wire.DialUpstreamTLS{Enabled: true}},
			wantHost: "h", wantPort: 443, wantScheme: types.SchemeHTTPS,
		},
		{
			name:     "defaults_from_parent",
			p:        wire.DialUpstreamParams{ParentFlowID: parentID},
			wantHost: "echo.test", wantPort: 8443, wantScheme: "https",
		},
		{
			name:     "params_host_parent_port",
			p:        wire.DialUpstreamParams{Host: "override.test", ParentFlowID: parentID},
			wantHost: "override.test", wantPort: 8443, wantScheme: "https",
		},
		{
			name:     "missing_dest_no_parent",
			p:        wire.DialUpstreamParams{Host: "h"}, // port 0, no parent
			wantCode: wire.CodeDialFailed,
		},
		{
			name:     "unknown_parent",
			p:        wire.DialUpstreamParams{ParentFlowID: "nope"},
			wantCode: wire.CodeDialFailed,
		},
		{
			name:     "parent_without_dest",
			p:        wire.DialUpstreamParams{ParentFlowID: noDestID},
			wantCode: wire.CodeDialFailed,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			host, port, scheme, rpcErr := s.resolveDest(rec, &tc.p)
			if tc.wantCode != 0 {
				require.NotNil(t, rpcErr)
				assert.Equal(t, tc.wantCode, rpcErr.Code)
				return
			}
			require.Nil(t, rpcErr)
			assert.Equal(t, tc.wantHost, host)
			assert.Equal(t, tc.wantPort, port)
			assert.Equal(t, tc.wantScheme, scheme)
		})
	}
}

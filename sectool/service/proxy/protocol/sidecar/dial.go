package sidecar

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"time"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
)

// defaultDialTimeout bounds a dial_upstream attempt when Config sets none.
const defaultDialTimeout = 20 * time.Second

// handleDialUpstream opens an upstream TCP connection on the sidecar's behalf,
// subject to scope policy, and bridges it as a new stream.
func (s *session) handleDialUpstream(ctx context.Context, p *wire.DialUpstreamParams) (any, *wire.Error) {
	rec := s.record()
	if rec == nil {
		return nil, wire.NewError(wire.CodeNotRegistered, "dial_upstream: register first")
	}

	host, port, scheme, rpcErr := s.resolveDest(rec, p)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if s.m.cfg.ScopeCheck != nil {
		if ok, reason := s.m.cfg.ScopeCheck(host); !ok {
			return nil, wire.NewError(wire.CodeDialScopeRejected, "dial_upstream: "+reason).
				WithData(&wire.ErrorData{Adapter: rec.Name})
		}
	}

	conn, rpcErr := s.dial(ctx, rec, host, port, p.TLS)
	if rpcErr != nil {
		return nil, rpcErr
	}

	id := rec.bridge.streams.add(conn)
	go rec.bridge.streams.serveUpstream(ctx, rec, id, conn)

	s.recordDial(rec, p.ParentFlowID, host, port, scheme)
	return wire.DialUpstreamResult{StreamID: id}, nil
}

// resolveDest resolves the upstream destination, defaulting host/port/scheme from
// the parent flow's recorded connection when the params omit them.
func (s *session) resolveDest(rec *Record, p *wire.DialUpstreamParams) (host string, port int, scheme string, rpcErr *wire.Error) {
	host, port = p.Host, p.Port
	if p.TLS != nil && p.TLS.Enabled {
		scheme = types.SchemeHTTPS
	}
	if host != "" && port != 0 {
		return host, port, scheme, nil
	} else if p.ParentFlowID == "" {
		return "", 0, "", wire.NewError(wire.CodeDialFailed, "dial_upstream: host/port required without parent_flow_id").
			WithData(&wire.ErrorData{Adapter: rec.Name})
	}
	flow, ok := s.m.flows.Get(p.ParentFlowID)
	if !ok {
		return "", 0, "", wire.NewError(wire.CodeDialFailed, "dial_upstream: unknown parent_flow_id").
			WithData(&wire.ErrorData{Adapter: rec.Name, FlowID: p.ParentFlowID})
	}
	dh, dp, ds := flowDest(flow)
	if host == "" {
		host = dh
	}
	if port == 0 {
		port = dp
	}
	if scheme == "" {
		scheme = ds
	}
	if host == "" || port == 0 {
		return "", 0, "", wire.NewError(wire.CodeDialFailed, "dial_upstream: parent_flow_id has no destination").
			WithData(&wire.ErrorData{Adapter: rec.Name, FlowID: p.ParentFlowID})
	}
	return host, port, scheme, nil
}

// flowDest derives the upstream destination (host, port, scheme) from a flow.
func flowDest(flow *types.Flow) (host string, port int, scheme string) {
	scheme, port = flow.Scheme, flow.Port
	if flow.Request != nil {
		h := flow.Request.Headers.Get("Host")
		if hh, _, err := net.SplitHostPort(h); err == nil {
			host = hh
		} else {
			host = h
		}
	}
	return host, port, scheme
}

// dial opens the upstream socket, terminating TLS toward it when requested.
func (s *session) dial(ctx context.Context, rec *Record, host string, port int, t *wire.DialUpstreamTLS) (net.Conn, *wire.Error) {
	timeout := s.m.cfg.DialTimeout
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	if t != nil && t.Enabled {
		sni := t.SNI
		if sni == "" {
			sni = host
		}
		d := tls.Dialer{
			NetDialer: &net.Dialer{Timeout: timeout},
			Config: &tls.Config{
				ServerName:         sni,
				NextProtos:         t.ALPN,
				InsecureSkipVerify: t.SkipVerify,
			},
		}
		conn, err := d.DialContext(dctx, "tcp", addr)
		if err != nil {
			return nil, wire.NewError(wire.CodeDialTLSFailed, "dial_upstream: tls: "+err.Error()).
				WithData(&wire.ErrorData{Adapter: rec.Name})
		}
		return conn, nil
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, wire.NewError(wire.CodeDialFailed, "dial_upstream: "+err.Error()).
			WithData(&wire.ErrorData{Adapter: rec.Name})
	}
	return conn, nil
}

// recordDial stores an audit flow for the dial, linked to parent_flow_id. Stored
// unconditionally (no capture filter) so audit is never dropped.
func (s *session) recordDial(rec *Record, parentFlowID, host string, port int, scheme string) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	s.m.flows.Store(&types.Flow{
		Adapter:      rec.Name,
		ProtocolTag:  "dial_upstream",
		Direction:    "bidirectional",
		ParentFlowID: parentFlowID,
		Scheme:       scheme,
		Port:         port,
		Request: &types.Message{
			Method:  "DIAL",
			Path:    addr,
			Version: "HTTP/1.1",
			Headers: types.Headers{{Name: "Host", Value: addr}},
		},
		StartedAt:         s.m.now(),
		SidecarInstanceID: rec.InstanceID,
	})
}

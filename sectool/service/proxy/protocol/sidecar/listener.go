package sidecar

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

// Listener accepts sidecar connections on the local socket and hands each to the
// Manager. Its lifecycle is owned by the native proxy backend.
type Listener struct {
	mgr    *Manager
	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed atomic.Bool
}

// NewListener binds the local socket: a Unix domain socket on unix, loopback TCP
// on Windows. Call Serve to start accepting.
func NewListener(cfg Config, mgr *Manager) (*Listener, error) {
	ln, err := listen(cfg.Socket)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Listener{mgr: mgr, ln: ln, ctx: ctx, cancel: cancel}, nil
}

// Addr returns the bound socket address.
func (l *Listener) Addr() string { return l.ln.Addr().String() }

// Serve accepts connections until Close. Returns nil on clean shutdown.
func (l *Listener) Serve() error {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			if l.closed.Load() {
				return nil
			}
			select {
			case <-l.ctx.Done():
				return nil
			default:
			}
			return err
		}
		log.Printf("sidecar: connection accepted from %s", conn.RemoteAddr())
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.mgr.HandleConn(l.ctx, conn)
		}()
	}
}

// Close stops accepting, shuts the registered sidecars down, and releases the
// socket.
func (l *Listener) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	l.cancel()
	err := l.ln.Close()
	l.mgr.Shutdown(context.Background())
	l.wg.Wait()
	return err
}

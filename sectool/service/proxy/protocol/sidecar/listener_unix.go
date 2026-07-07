//go:build unix

package sidecar

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// listen binds a Unix domain socket with dir 0700 and socket 0600, removing any
// stale socket first.
func listen(socket string) (net.Listener, error) {
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sidecar: create socket dir: %w", err)
	}
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("sidecar: remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("sidecar: listen unix %s: %w", socket, err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("sidecar: chmod socket: %w", err)
	}
	return ln, nil
}

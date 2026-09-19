//go:build windows

package sidecar

import (
	"context"
	"fmt"
	"net"
)

// listen binds a loopback TCP socket. socket is a host:port address.
func listen(ctx context.Context, socket string) (net.Listener, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", socket)
	if err != nil {
		return nil, fmt.Errorf("sidecar: listen tcp %s: %w", socket, err)
	}
	return ln, nil
}

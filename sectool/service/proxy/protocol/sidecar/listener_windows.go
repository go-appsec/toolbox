//go:build windows

package sidecar

import (
	"fmt"
	"net"
)

// listen binds a loopback TCP socket. socket is a host:port address.
func listen(socket string) (net.Listener, error) {
	ln, err := net.Listen("tcp", socket)
	if err != nil {
		return nil, fmt.Errorf("sidecar: listen tcp %s: %w", socket, err)
	}
	return ln, nil
}

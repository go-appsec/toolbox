//go:build unix

package sidecar

import "net"

// networkFor returns the dial network for addr.
func networkFor(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil && host != "" {
		return "tcp"
	}
	return "unix"
}

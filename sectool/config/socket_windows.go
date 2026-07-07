//go:build windows

package config

import "strconv"

// DefaultSidecarSocket returns the default sidecar IPC address: a loopback TCP
// address on Windows, which lacks reliable Unix domain socket support.
func DefaultSidecarSocket() string {
	return "127.0.0.1:" + strconv.Itoa(DefaultSidecarPort)
}

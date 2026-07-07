//go:build windows

package sidecar

// networkFor always selects loopback TCP on Windows, which lacks reliable Unix
// domain socket support.
func networkFor(addr string) string {
	return "tcp"
}

package addr

import (
	"net"
	"strconv"
	"strings"
)

// Parse extracts host and port from an authority like "example.com",
// "example.com:8443", or "[::1]:8080". scheme selects the default port when the
// authority carries none ("https" -> 443, else 80). The returned host is lowercased.
func Parse(authority, scheme string) (string, int) {
	defaultPort := 80
	if scheme == "https" {
		defaultPort = 443
	}

	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		return strings.ToLower(authority), defaultPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return strings.ToLower(host), defaultPort
	}
	return strings.ToLower(host), port
}

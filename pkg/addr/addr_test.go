package addr

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		authority string
		scheme    string
		wantHost  string
		wantPort  int
	}{
		{"no_port_https", "example.com", "https", "example.com", 443},
		{"no_port_http", "example.com", "http", "example.com", 80},
		{"explicit_port", "example.com:8443", "https", "example.com", 8443},
		{"lowercases_host", "Example.COM:80", "https", "example.com", 80},
		{"ipv6_with_port", "[::1]:8080", "https", "::1", 8080},
		{"non_numeric_port", "example.com:abc", "https", "example.com", 443},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port := Parse(tt.authority, tt.scheme)
			assert.Equal(t, tt.wantHost, host)
			assert.Equal(t, tt.wantPort, port)
		})
	}
}

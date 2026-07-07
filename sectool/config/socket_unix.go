//go:build unix

package config

import (
	"os"
	"path/filepath"
)

// DefaultSidecarSocket returns the default sidecar IPC address: a Unix domain
// socket at ~/.sectool/sidecar.sock.
func DefaultSidecarSocket() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".sectool", "sidecar.sock")
	}
	return filepath.Join(home, ".sectool", "sidecar.sock")
}

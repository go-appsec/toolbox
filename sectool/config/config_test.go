package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadSaveRoundTrip(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")

	original := &Config{
		Version: Version,
		MCPPort: 8080,
	}

	err := original.Save(path)
	require.NoError(t, err)

	_, err = os.Stat(path)
	require.NoError(t, err)

	loaded, err := loadConfig(path)
	require.NoError(t, err)

	assert.Equal(t, original.Version, loaded.Version)
	assert.Equal(t, original.MCPPort, loaded.MCPPort)
}

func TestLoadNotExist(t *testing.T) {
	t.Parallel()

	_, err := loadConfig("/nonexistent/path/config.json")
	assert.True(t, os.IsNotExist(err))
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")

	// Write minimal config (missing optional fields)
	const minimalJSON = `{"version": "0.1.0"}`
	err := os.WriteFile(path, []byte(minimalJSON), 0644)
	require.NoError(t, err)

	cfg, err := loadConfig(path)
	require.NoError(t, err)
	assert.Equal(t, DefaultMCPPort, cfg.MCPPort)
}

func TestLoadInvalidJSON(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")

	err := os.WriteFile(path, []byte("not json"), 0644)
	require.NoError(t, err)

	_, err = loadConfig(path)
	assert.Error(t, err)
}

func TestLoadOrCreatePath(t *testing.T) {
	t.Parallel()

	t.Run("creates_new_file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")

		cfg, err := LoadOrCreatePath(path)
		require.NoError(t, err)
		assert.Equal(t, Version, cfg.Version)
		assert.Equal(t, DefaultMCPPort, cfg.MCPPort)

		// File should exist on disk
		_, err = os.Stat(path)
		require.NoError(t, err)
	})

	t.Run("same_version_no_rewrite", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")

		// Write config with current version but custom port
		original := &Config{Version: Version, MCPPort: 7777}
		require.NoError(t, original.Save(path))
		info1, err := os.Stat(path)
		require.NoError(t, err)

		cfg, err := LoadOrCreatePath(path)
		require.NoError(t, err)
		assert.Equal(t, 7777, cfg.MCPPort)

		// File should not have been rewritten (same mod time)
		info2, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, info1.ModTime(), info2.ModTime())
	})

	t.Run("different_version_updates_file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")

		// Write config with an old version, missing some fields
		oldJSON := `{"version": "0.0.1", "mcp_port": 7777}`
		require.NoError(t, os.WriteFile(path, []byte(oldJSON), 0600))

		cfg, err := LoadOrCreatePath(path)
		require.NoError(t, err)
		assert.Equal(t, Version, cfg.Version)
		assert.Equal(t, 7777, cfg.MCPPort) // user value preserved

		// Re-read the file to verify it was persisted with defaults
		reloaded, err := loadConfig(path)
		require.NoError(t, err)
		assert.Equal(t, Version, reloaded.Version)
		assert.Equal(t, 7777, reloaded.MCPPort)
		assert.Equal(t, DefaultProxyPort, reloaded.ProxyPort) // default filled in
		assert.NotNil(t, reloaded.IncludeSubdomains)
		assert.NotNil(t, reloaded.Crawler.ExtractForms)
	})

	t.Run("empty_version_updates_file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")

		// Config with no version field at all
		require.NoError(t, os.WriteFile(path, []byte(`{"mcp_port": 9999}`), 0600))

		cfg, err := LoadOrCreatePath(path)
		require.NoError(t, err)
		assert.Equal(t, Version, cfg.Version)
		assert.Equal(t, 9999, cfg.MCPPort)

		// Verify persisted
		reloaded, err := loadConfig(path)
		require.NoError(t, err)
		assert.Equal(t, Version, reloaded.Version)
	})

	t.Run("error_on_invalid_json", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")

		require.NoError(t, os.WriteFile(path, []byte("invalid"), 0644))

		_, err := LoadOrCreatePath(path)
		assert.Error(t, err)
	})
}

func TestLoadInteractshServerURL(t *testing.T) {
	t.Parallel()

	t.Run("present", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")

		cfgJSON := `{"interactsh_server_url": "oast.internal.com"}`
		require.NoError(t, os.WriteFile(path, []byte(cfgJSON), 0644))

		cfg, err := loadConfig(path)
		require.NoError(t, err)
		assert.Equal(t, "oast.internal.com", cfg.InteractshServerURL)
	})

	t.Run("absent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")

		cfgJSON := `{"mcp_port": 9119}`
		require.NoError(t, os.WriteFile(path, []byte(cfgJSON), 0644))

		cfg, err := loadConfig(path)
		require.NoError(t, err)
		assert.Empty(t, cfg.InteractshServerURL)
	})
}

func TestLoadExcludeExtensionsDefault(t *testing.T) {
	t.Parallel()

	t.Run("nil_gets_default", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")

		// Config without exclude_extensions key
		require.NoError(t, os.WriteFile(path, []byte(`{"mcp_port": 9119}`), 0644))

		cfg, err := loadConfig(path)
		require.NoError(t, err)
		require.NotNil(t, cfg.Proxy.ExcludeExtensions)
		assert.Equal(t, DefaultExcludeExtensions, *cfg.Proxy.ExcludeExtensions)
	})

	t.Run("empty_string_preserved", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")

		// Explicit empty string disables the filter
		cfgJSON := `{"proxy": {"exclude_extensions": ""}}`
		require.NoError(t, os.WriteFile(path, []byte(cfgJSON), 0644))

		cfg, err := loadConfig(path)
		require.NoError(t, err)
		require.NotNil(t, cfg.Proxy.ExcludeExtensions)
		assert.Empty(t, *cfg.Proxy.ExcludeExtensions)
	})

	t.Run("custom_value_preserved", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")

		cfgJSON := `{"proxy": {"exclude_extensions": "woff|woff2"}}`
		require.NoError(t, os.WriteFile(path, []byte(cfgJSON), 0644))

		cfg, err := loadConfig(path)
		require.NoError(t, err)
		require.NotNil(t, cfg.Proxy.ExcludeExtensions)
		assert.Equal(t, "woff|woff2", *cfg.Proxy.ExcludeExtensions)
	})

	t.Run("default_config_has_value", func(t *testing.T) {
		cfg := DefaultConfig()
		require.NotNil(t, cfg.Proxy.ExcludeExtensions)
		assert.Equal(t, DefaultExcludeExtensions, *cfg.Proxy.ExcludeExtensions)
	})
}

func TestIsDomainAllowed(t *testing.T) {
	t.Parallel()

	boolPtr := func(v bool) *bool { return &v }

	cases := []struct {
		name       string
		cfg        *Config
		hostname   string
		wantOK     bool
		wantReason string
	}{
		{
			name:     "no_config_allows_all",
			cfg:      &Config{IncludeSubdomains: boolPtr(true)},
			hostname: "anything.example.com",
			wantOK:   true,
		},
		{
			name: "exclude_takes_precedence",
			cfg: &Config{
				IncludeSubdomains: boolPtr(true),
				AllowedDomains:    []string{"example.com"},
				ExcludeDomains:    []string{"example.com"},
			},
			hostname:   "example.com",
			wantOK:     false,
			wantReason: "exclude_domains",
		},
		{
			name: "exclude_matches_subdomains",
			cfg: &Config{
				IncludeSubdomains: boolPtr(true),
				ExcludeDomains:    []string{"evil.com"},
			},
			hostname:   "sub.evil.com",
			wantOK:     false,
			wantReason: "exclude_domains",
		},
		{
			name: "allowed_exact_match",
			cfg: &Config{
				IncludeSubdomains: boolPtr(false),
				AllowedDomains:    []string{"example.com"},
			},
			hostname: "example.com",
			wantOK:   true,
		},
		{
			name: "allowed_subdomain_match",
			cfg: &Config{
				IncludeSubdomains: boolPtr(true),
				AllowedDomains:    []string{"example.com"},
			},
			hostname: "api.example.com",
			wantOK:   true,
		},
		{
			name: "allowed_no_subdomains",
			cfg: &Config{
				IncludeSubdomains: boolPtr(false),
				AllowedDomains:    []string{"example.com"},
			},
			hostname:   "api.example.com",
			wantOK:     false,
			wantReason: "not in allowed_domains",
		},
		{
			name: "not_in_allowed",
			cfg: &Config{
				IncludeSubdomains: boolPtr(true),
				AllowedDomains:    []string{"example.com"},
			},
			hostname:   "other.com",
			wantOK:     false,
			wantReason: "not in allowed_domains",
		},
		{
			name: "hostname_with_port",
			cfg: &Config{
				IncludeSubdomains: boolPtr(true),
				AllowedDomains:    []string{"example.com"},
			},
			hostname: "example.com:8443",
			wantOK:   true,
		},
		{
			name: "case_insensitive",
			cfg: &Config{
				IncludeSubdomains: boolPtr(true),
				AllowedDomains:    []string{"Example.COM"},
			},
			hostname: "API.example.com",
			wantOK:   true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := tc.cfg.IsDomainAllowed(tc.hostname)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantReason != "" {
				assert.Contains(t, reason, tc.wantReason)
			}
		})
	}
}

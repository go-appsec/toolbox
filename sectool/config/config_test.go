package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadSaveRoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	original := &Config{
		Version:        "0.0.1",
		InitializedAt:  time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		LastInitMode:   "explore",
		BurpMCPURL:     "http://localhost:9999/sse",
		PreserveGuides: true,
	}

	err := original.Save(path)
	require.NoError(t, err)

	_, err = os.Stat(path)
	require.NoError(t, err)

	loaded, err := Load(path)
	require.NoError(t, err)

	assert.Equal(t, original.Version, loaded.Version)
	assert.Equal(t, original.InitializedAt.UTC(), loaded.InitializedAt.UTC())
	assert.Equal(t, original.LastInitMode, loaded.LastInitMode)
	assert.Equal(t, original.BurpMCPURL, loaded.BurpMCPURL)
	assert.Equal(t, original.PreserveGuides, loaded.PreserveGuides)
}

func TestLoadNotExist(t *testing.T) {
	t.Parallel()

	_, err := Load("/nonexistent/path/config.json")
	assert.True(t, os.IsNotExist(err))
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// Write minimal config (missing optional fields)
	minimalJSON := `{"version": "0.0.1", "initialized_at": "2025-01-15T10:30:00Z"}`
	err := os.WriteFile(path, []byte(minimalJSON), 0644)
	require.NoError(t, err)

	cfg, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, DefaultBurpMCPURL, cfg.BurpMCPURL)
}

func TestLoadInvalidJSON(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	err := os.WriteFile(path, []byte("not json"), 0644)
	require.NoError(t, err)

	_, err = Load(path)
	assert.Error(t, err)
}

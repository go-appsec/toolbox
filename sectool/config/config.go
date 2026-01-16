package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

const (
	Version           = "0.0.1"
	DefaultBurpMCPURL = "http://127.0.0.1:9876/sse"
)

// RevNum is the git revision count, injected at build time via ldflags.
// Falls back to "dev" when not set (e.g., go run without ldflags).
var RevNum = "dev"

// UserAgent returns the standard user agent string for sectool requests.
func UserAgent() string {
	return "Mozilla/5.0 (compatible; go-harden/llm-security-toolbox sectool-v" + Version + "-" + RevNum + ")"
}

type Config struct {
	Version        string        `json:"version"`
	InitializedAt  time.Time     `json:"initialized_at"`
	LastInitMode   string        `json:"last_init_mode,omitempty"`
	BurpMCPURL     string        `json:"burp_mcp_url"`
	PreserveGuides bool          `json:"preserve_guides,omitempty"`
	Crawler        CrawlerConfig `json:"crawler,omitempty"`
}

type CrawlerConfig struct {
	MaxResponseBodyBytes int      `json:"max_response_body_bytes,omitempty"`
	IncludeSubdomains    *bool    `json:"include_subdomains,omitempty"`
	DisallowedPaths      []string `json:"disallowed_paths,omitempty"`
	DelayMS              int      `json:"delay_ms,omitempty"`
	Parallelism          int      `json:"parallelism,omitempty"`
	MaxDepth             int      `json:"max_depth,omitempty"`
	MaxRequests          int      `json:"max_requests,omitempty"`
	ExtractForms         *bool    `json:"extract_forms,omitempty"`
	SubmitForms          *bool    `json:"submit_forms,omitempty"`
}

// DefaultConfig returns a new Config with default values.
func DefaultConfig() *Config {
	t := true
	f := false
	return &Config{
		Version:       Version,
		InitializedAt: time.Now().UTC(),
		BurpMCPURL:    DefaultBurpMCPURL,
		Crawler: CrawlerConfig{
			MaxResponseBodyBytes: 1048576, // 1MB
			IncludeSubdomains:    &t,
			DisallowedPaths: []string{
				"*logout*",
				"*signout*",
				"*sign-out*",
				"*delete*",
				"*remove*",
			},
			DelayMS:      200,
			Parallelism:  2,
			MaxDepth:     10,
			MaxRequests:  1000,
			ExtractForms: &t,
			SubmitForms:  &f,
		},
	}
}

// Load reads and parses config from the given path.
// If the file doesn't exist, returns os.ErrNotExist.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// set required fields if cleared
	if cfg.Version == "" {
		cfg.Version = Version
	}
	if cfg.InitializedAt.IsZero() {
		cfg.InitializedAt = time.Now()
	}
	if cfg.BurpMCPURL == "" {
		cfg.BurpMCPURL = DefaultBurpMCPURL
	}

	return &cfg, nil
}

func LoadOrDefaultConfig(path string) (*Config, error) {
	cfg, err := Load(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return cfg, nil
}

// Save writes the config to the given path atomically.
func (c *Config) Save(path string) error {
	if c == nil {
		return errors.New("config is nil")
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

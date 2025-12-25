package initialize

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jentfoo/llm-security-toolbox/sectool/config"
	"github.com/jentfoo/llm-security-toolbox/sectool/service"
)

//go:embed templates/AGENT-explore.md
var exploreGuide string

//go:embed templates/AGENT-test-report.md
var testReportGuide string

const (
	exploreFileName    = "AGENT-explore.md"
	testReportFileName = "AGENT-test-report.md"
)

func run(mode string, reset bool) error {
	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	paths := service.NewServicePaths(workDir)

	// Handle --reset: stop service and clear .sectool/
	if reset {
		if err := performReset(paths); err != nil {
			return err
		}
	}

	// Create directory structure
	if err := os.MkdirAll(paths.SectoolDir, 0755); err != nil {
		return fmt.Errorf("failed to create .sectool directory: %w", err)
	}

	cfg, err := loadOrCreateConfig(paths.ConfigPath)
	if err != nil {
		return err
	}

	// Determine template and output path
	var template, filename string
	switch mode {
	case "explore":
		template = exploreGuide
		filename = exploreFileName
	case "test-report":
		template = testReportGuide
		filename = testReportFileName
	default:
		return fmt.Errorf("unknown init mode: %s", mode)
	}

	outputPath := filepath.Join(paths.SectoolDir, filename)

	// Write template unless preserve_guides is set and file exists
	written, err := writeGuideIfNeeded(outputPath, template, cfg.PreserveGuides)
	if err != nil {
		return err
	}

	if written {
		cfg.LastInitMode = mode
		cfg.InitializedAt = time.Now().UTC()
		if err := cfg.Save(paths.ConfigPath); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}
	}

	printSuccess(outputPath, written)

	return nil
}

func performReset(paths service.ServicePaths) error {
	// Try to stop the service if running
	client := service.NewClient(paths.WorkDir)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if client.CheckHealth(ctx) == nil {
		_, _ = client.Stop(ctx)
	}

	if err := os.RemoveAll(paths.SectoolDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove .sectool directory: %w", err)
	}

	return nil
}

func loadOrCreateConfig(path string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err == nil {
		return cfg, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Create new config with defaults
	return config.DefaultConfig(config.Version), nil
}

// writeGuideIfNeeded writes the template to the output path.
// If preserveGuides is true and the file exists, it skips writing.
// Returns true if the file was written, false if skipped.
func writeGuideIfNeeded(outputPath, template string, preserveGuides bool) (bool, error) {
	if preserveGuides {
		if _, err := os.Stat(outputPath); err == nil {
			return false, nil // File exists and preserve_guides is set
		}
	}

	if err := os.WriteFile(outputPath, []byte(template), 0644); err != nil {
		return false, fmt.Errorf("failed to write guide: %w", err)
	}

	return true, nil
}

func printSuccess(outputPath string, written bool) {
	if written {
		fmt.Printf("Initialized %s\n", outputPath)
	}

	fmt.Println("Start an agent with this system prompt:")
	fmt.Println()
	fmt.Printf("  claude --system-prompt-file %s\n", outputPath)
	fmt.Printf("  codex (add to AGENTS.md or use -c experimental_instructions_file=%s)\n", outputPath)
	fmt.Println("  crush (reference in .crush.json configuration)")
}

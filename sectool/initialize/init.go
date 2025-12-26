package initialize

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
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
	if err := os.MkdirAll(paths.SectoolDir, 0700); err != nil {
		return fmt.Errorf("failed to create .sectool directory: %w", err)
	}

	cfg, err := loadOrCreateConfig(paths.ConfigPath)
	if err != nil {
		return err
	}

	// Determine template and output path
	var tmplStr, filename string
	switch mode {
	case "explore":
		tmplStr = exploreGuide
		filename = exploreFileName
	case "test-report":
		tmplStr = testReportGuide
		filename = testReportFileName
	default:
		return fmt.Errorf("unknown init mode: %s", mode)
	}

	outputPath := filepath.Join(paths.SectoolDir, filename)

	// Render template with sectool command
	data := templateData{SectoolCmd: getSectoolCommand()}
	content, err := renderTemplate(tmplStr, data)
	if err != nil {
		return err
	}

	// Write template unless preserve_guides is set and file exists
	written, err := writeGuideIfNeeded(outputPath, content, cfg.PreserveGuides)
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

// writeGuideIfNeeded writes the content to the output path.
// If preserveGuides is true and the file exists, it skips writing.
// Returns true if the file was written, false if skipped.
func writeGuideIfNeeded(outputPath, content string, preserveGuides bool) (bool, error) {
	if preserveGuides {
		if _, err := os.Stat(outputPath); err == nil {
			return false, nil // File exists and preserve_guides is set
		}
	}

	if err := os.WriteFile(outputPath, []byte(content), 0644); err != nil {
		return false, fmt.Errorf("failed to write guide: %w", err)
	}

	return true, nil
}

func printSuccess(outputPath string, written bool) {
	// Convert to relative path for cleaner output
	relPath := outputPath
	if wd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(wd, outputPath); err == nil {
			relPath = rel
		}
	}

	if written {
		fmt.Printf("Initialized %s\n", relPath)
	}

	fmt.Println("Start Burp Suite with MCP then run your agent with this system prompt:")
	fmt.Println()
	fmt.Printf("  claude --system-prompt-file %s\n", relPath)
	fmt.Printf("  codex (add to AGENTS.md or use -c experimental_instructions_file=%s)\n", relPath)
	fmt.Println("  crush (reference in .crush.json configuration)")
	fmt.Println()
	fmt.Println("Follow agent action logs with: 'tail -F .sectool/service/log.txt'")
}

// templateData holds values for template rendering
type templateData struct {
	SectoolCmd string
}

// getSectoolCommand returns the command to use for sectool in templates.
// Prefers "sectool" if it's in PATH and matches the running executable.
func getSectoolCommand() string {
	currentExe, err := os.Executable()
	if err != nil {
		return "sectool"
	}
	currentExe, _ = filepath.EvalSymlinks(currentExe)

	// Check if sectool is in PATH
	pathExe, err := exec.LookPath("sectool")
	if err != nil {
		// Not in PATH, return relative or absolute path
		return relativeOrAbsPath(currentExe)
	}

	pathExe, _ = filepath.EvalSymlinks(pathExe)

	// If we're running the PATH version, use simple "sectool"
	if pathExe == currentExe {
		return "sectool"
	}

	// Running a different binary than PATH, use local path
	return relativeOrAbsPath(currentExe)
}

// relativeOrAbsPath returns a relative path from cwd if possible, otherwise absolute
func relativeOrAbsPath(exePath string) string {
	wd, err := os.Getwd()
	if err != nil {
		return exePath
	}

	rel, err := filepath.Rel(wd, exePath)
	if err != nil {
		return exePath
	}

	// Only use relative if it doesn't escape the working directory
	if strings.HasPrefix(rel, "..") {
		return exePath
	}

	// Ensure it starts with ./ for clarity
	if !strings.HasPrefix(rel, ".") {
		return "./" + rel
	}
	return rel
}

// renderTemplate applies templateData to a template string
func renderTemplate(tmplStr string, data templateData) (string, error) {
	tmpl, err := template.New("guide").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

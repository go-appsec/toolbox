package proxy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jentfoo/llm-security-toolbox/sectool/service"
)

func export(timeout time.Duration, flowID, out string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w (check %s)", err, client.LogPath())
	}

	resp, err := client.ProxyExport(ctx, &service.ProxyExportRequest{
		FlowID: flowID,
		OutDir: out,
	})
	if err != nil {
		return fmt.Errorf("proxy export failed: %w", err)
	}

	// Convert to relative path for cleaner output
	bundlePath := resp.BundlePath
	if rel, err := filepath.Rel(workDir, resp.BundlePath); err == nil {
		bundlePath = rel
	}

	// Output result
	fmt.Printf("Exported flow `%s` to bundle `%s`\n\n", flowID, resp.BundleID)
	fmt.Printf("Bundle path: `%s`\n\n", bundlePath)
	fmt.Println("Files created:")
	fmt.Println("- `request.http` - HTTP headers with body placeholder")
	fmt.Println("- `body` - Request body (edit for modifications)")
	fmt.Println("- `request.meta.json` - Metadata")
	fmt.Println("\nTo replay: `sectool replay send --bundle " + bundlePath + "`")

	return nil
}

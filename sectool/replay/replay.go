package replay

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/jentfoo/llm-security-toolbox/sectool/service"
)

func send(timeout time.Duration, flow, bundle, file, body, target string, headers, removeHeaders []string,
	path, query string, setQuery, removeQuery []string,
	setJSON, removeJSON []string,
	followRedirects bool, requestTimeout time.Duration, force bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Validate stdin usage early
	if file == "-" && body == "-" {
		return errors.New("cannot read both file and body from stdin")
	}

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	// Handle stdin by writing to temp files
	requestsDir := filepath.Join(workDir, ".sectool", "requests")
	if file == "-" || body == "-" {
		if err := os.MkdirAll(requestsDir, 0700); err != nil {
			return fmt.Errorf("failed to create requests directory: %w", err)
		}
	}

	if file == "-" {
		content, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
		tmpPath := filepath.Join(requestsDir, fmt.Sprintf("temp-%d.req", time.Now().Unix()))
		if err := os.WriteFile(tmpPath, content, 0600); err != nil {
			return fmt.Errorf("failed to write temp file: %w", err)
		}
		defer func() { _ = os.Remove(tmpPath) }()
		file = tmpPath
	}

	if body == "-" {
		content, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read body from stdin: %w", err)
		}
		tmpPath := filepath.Join(requestsDir, fmt.Sprintf("temp-%d.body", time.Now().Unix()))
		if err := os.WriteFile(tmpPath, content, 0600); err != nil {
			return fmt.Errorf("failed to write temp body file: %w", err)
		}
		defer func() { _ = os.Remove(tmpPath) }()
		body = tmpPath
	}

	client := service.NewClient(workDir, service.WithTimeout(timeout))
	if err := client.EnsureService(ctx); err != nil {
		return fmt.Errorf("failed to start service: %w (check %s)", err, client.LogPath())
	}

	req := &service.ReplaySendRequest{
		FlowID:          flow,
		BundlePath:      bundle,
		FilePath:        file,
		BodyPath:        body,
		Target:          target,
		AddHeaders:      headers,
		RemoveHeaders:   removeHeaders,
		Path:            path,
		Query:           query,
		SetQuery:        setQuery,
		RemoveQuery:     removeQuery,
		SetJSON:         setJSON,
		RemoveJSON:      removeJSON,
		FollowRedirects: followRedirects,
		Force:           force,
	}
	if requestTimeout > 0 {
		req.Timeout = requestTimeout.String()
	}

	resp, err := client.ReplaySend(ctx, req)
	if err != nil {
		if bundle != "" {
			fmt.Fprintln(os.Stderr, "\nTip: Consider using `sectool replay send --flow <flow_id>` with modification flags as a simpler alternative to editing bundle files directly.")
		}
		return fmt.Errorf("replay send failed: %w", err)
	}

	// Output result as markdown
	fmt.Printf("## Replay Result\n\n")
	fmt.Printf("Replay ID: `%s`\n", resp.ReplayID)
	fmt.Printf("Duration: %s\n\n", resp.Duration)

	fmt.Printf("### Response\n\n")
	fmt.Printf("Status: %d %s\n", resp.Status, resp.StatusLine)
	fmt.Printf("Size: %d bytes\n\n", resp.RespSize)

	if resp.RespHeaders != "" {
		fmt.Printf("Headers:\n```\n%s```\n\n", resp.RespHeaders)
	}

	if resp.RespPreview != "" {
		fmt.Printf("Body Preview:\n```\n%s\n```\n", resp.RespPreview)
	}

	return nil
}

func get(timeout time.Duration, replayID string) error {
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

	resp, err := client.ReplayGet(ctx, &service.ReplayGetRequest{
		ReplayID: replayID,
	})
	if err != nil {
		return fmt.Errorf("replay get failed: %w", err)
	}

	// Output result as markdown
	fmt.Printf("## Replay Details\n\n")
	fmt.Printf("Replay ID: `%s`\n", resp.ReplayID)
	fmt.Printf("Duration: %s\n", resp.Duration)
	fmt.Printf("Status: %d %s\n", resp.Status, resp.StatusLine)
	fmt.Printf("Size: %d bytes\n\n", resp.RespSize)

	if resp.RespHeaders != "" {
		fmt.Printf("Headers:\n```\n%s```\n\n", resp.RespHeaders)
	}

	if resp.RespBody != "" {
		body, err := base64.StdEncoding.DecodeString(resp.RespBody)
		if err != nil {
			fmt.Printf("Body: (failed to decode: %v)\n", err)
		} else {
			fmt.Printf("Body:\n```\n%s\n```\n", string(body))
		}
	}

	return nil
}

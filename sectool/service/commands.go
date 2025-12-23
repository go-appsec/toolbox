package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

func status(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := NewClient(workDir, WithTimeout(timeout))
	st, err := client.Status(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status: %w", err)
	}

	fmt.Println("## Service Status")
	fmt.Println()

	if st.Running {
		fmt.Println("**Status**: Running")
		if st.PID > 0 {
			fmt.Printf("**PID**: %d\n", st.PID)
		}
		if st.Health != nil {
			fmt.Printf("**Version**: %s\n", st.Health.Version)
			fmt.Printf("**Started At**: %s\n", st.Health.StartedAt)
			fmt.Printf("**Burp Connected**: %v\n", st.Health.BurpConnected)
			if st.Health.BurpMCPURL != "" {
				fmt.Printf("**Burp MCP URL**: %s\n", st.Health.BurpMCPURL)
			}
			if len(st.Health.Metrics) > 0 {
				fmt.Println()
				fmt.Println("### Metrics")
				for key, value := range st.Health.Metrics {
					fmt.Printf("- %s: %s\n", key, value)
				}
			}
		}
	} else {
		fmt.Println("**Status**: Not running")
	}

	fmt.Println()
	fmt.Printf("**Socket Path**: `%s`\n", st.SocketPath)

	return nil
}

func stop(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := NewClient(workDir, WithTimeout(timeout))
	if client.CheckHealth(ctx) != nil {
		fmt.Println("Service is not running.")
		return nil
	}

	resp, err := client.Stop(ctx)
	if err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}

	fmt.Printf("Service stop requested: %s\n", resp.Message)

	fmt.Print("Waiting for shutdown...")
	for i := 0; i < 500; i++ { // 5 seconds max
		time.Sleep(10 * time.Millisecond)
		if client.CheckHealth(ctx) != nil {
			fmt.Println(" done.")
			fmt.Println("Service stopped successfully.")
			return nil
		}
		fmt.Print(".")
	}

	fmt.Println(" timeout.")
	return errors.New("service did not stop within timeout")
}

func logs(timeout time.Duration, follow bool, lines int) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	client := NewClient(workDir, WithTimeout(timeout))
	if _, err := os.Stat(client.paths.LogFile); os.IsNotExist(err) {
		fmt.Println("No service logs found.")
		fmt.Printf("Log file would be at: %s\n", client.paths.LogFile)
		return nil
	}

	if follow {
		return followLogs(ctx, client.paths.LogFile)
	}

	return tailLogs(client.paths.LogFile, lines)
}

// tailLogs shows the last N lines of the log file.
func tailLogs(logPath string, lines int) error {
	file, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer func() { _ = file.Close() }()

	// Use a ring buffer to keep only the last N lines
	ringBuf := make([]string, lines)
	var ringIdx, totalLines int
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ringBuf[ringIdx] = scanner.Text()
		ringIdx = (ringIdx + 1) % lines
		totalLines++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read log file: %w", err)
	}

	outputCount := totalLines
	if outputCount > lines {
		outputCount = lines
	}

	fmt.Printf("## Service Logs (last %d lines)\n\n", outputCount)
	fmt.Println("```")

	if totalLines <= lines {
		for i := 0; i < totalLines; i++ {
			fmt.Println(ringBuf[i])
		}
	} else {
		// Buffer wrapped: ringIdx is oldest, ringIdx-1 is newest
		for i := 0; i < lines; i++ {
			idx := (ringIdx + i) % lines
			fmt.Println(ringBuf[idx])
		}
	}

	fmt.Println("```")

	return nil
}

// followLogs tails the log file continuously until context is cancelled.
func followLogs(ctx context.Context, logPath string) error {
	file, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer func() { _ = file.Close() }()

	_, err = file.Seek(0, io.SeekEnd) // Seek to end
	if err != nil {
		return fmt.Errorf("failed to seek to end of log file: %w", err)
	}

	fmt.Println("Following service logs (Ctrl+C to stop)...")
	fmt.Println()

	reader := bufio.NewReader(file)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// No new data, wait a bit
				time.Sleep(100 * time.Millisecond)
				continue
			}
			return fmt.Errorf("failed to read log file: %w", err)
		}
		fmt.Print(line)
	}
}

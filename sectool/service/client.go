package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	startupTimeout        = 10 * time.Second
	startupPollInterval   = 10 * time.Millisecond
	defaultRequestTimeout = 30 * time.Second
)

// Client connects to the sectool service over a Unix socket.
type Client struct {
	paths      ServicePaths
	httpClient *http.Client
	timeout    time.Duration
}

type ClientOption func(*Client)

func WithTimeout(d time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = d
	}
}

func NewClient(workDir string, opts ...ClientOption) *Client {
	c := &Client{
		paths:   NewServicePaths(workDir),
		timeout: defaultRequestTimeout,
	}
	for _, opt := range opts {
		opt(c)
	}

	c.httpClient = &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", c.paths.SocketPath)
			},
		},
		Timeout: c.timeout,
	}

	return c
}

// EnsureService ensures the service is running, starting it if necessary.
func (c *Client) EnsureService(ctx context.Context) error {
	if c.CheckHealth(ctx) == nil {
		return nil
	}
	return c.startService(ctx)
}

// CheckHealth returns an error if the service is not running or unhealthy.
func (c *Client) CheckHealth(ctx context.Context) error {
	_, err := c.Health(ctx)
	return err
}

// Health returns the service health response.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/health", nil)
	if err != nil {
		return nil, err
	}

	var health HealthResponse
	if err := json.Unmarshal(resp.Data, &health); err != nil {
		return nil, fmt.Errorf("failed to parse health response: %w", err)
	}

	return &health, nil
}

// Stop requests the service to shut down gracefully.
func (c *Client) Stop(ctx context.Context) (*StopResponse, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, "/srv/stop", nil)
	if err != nil {
		return nil, err
	}

	var stopResp StopResponse
	if err := json.Unmarshal(resp.Data, &stopResp); err != nil {
		return nil, fmt.Errorf("failed to parse stop response: %w", err)
	}

	return &stopResp, nil
}

// Status returns the current service status without starting the service.
func (c *Client) Status(ctx context.Context) (*ServiceStatus, error) {
	status := &ServiceStatus{
		SocketPath: c.paths.SocketPath,
	}

	health, err := c.Health(ctx)
	if err == nil {
		status.Running = true
		status.Health = health
		if pid, exists := c.checkPIDFile(); exists {
			status.PID = pid
		}
	} else {
		status.Running = false
	}

	return status, nil
}

// startService starts the service daemon. Concurrent start attempts are safe
// due to the server's flock-based mutual exclusion.
func (c *Client) startService(ctx context.Context) error {
	if err := os.MkdirAll(c.paths.ServiceDir, 0755); err != nil {
		return fmt.Errorf("failed to create service directory: %w", err)
	}
	c.cleanupStaleSocket()
	if err := c.spawnServiceProcess(); err != nil {
		return fmt.Errorf("failed to spawn service process: %w", err)
	}
	return c.waitForHealthy(ctx)
}

// cleanupStaleSocket removes the socket file if it exists but is not connectable.
func (c *Client) cleanupStaleSocket() {
	if _, err := os.Stat(c.paths.SocketPath); err == nil {
		conn, err := net.DialTimeout("unix", c.paths.SocketPath, 100*time.Millisecond)
		if err != nil {
			_ = os.Remove(c.paths.SocketPath)
		} else {
			_ = conn.Close()
		}
	}
}

// checkPIDFile reads and returns the PID from the PID file if it exists.
func (c *Client) checkPIDFile() (pid int, exists bool) {
	data, err := os.ReadFile(c.paths.PIDPath)
	if err != nil {
		return 0, false
	}

	pid, err = strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, false
	}

	return pid, true
}

// spawnServiceProcess starts the service as a detached background process.
func (c *Client) spawnServiceProcess() error {
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	logFile, err := os.OpenFile(c.paths.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	cmd := exec.Command(executable, "--service", "--workdir", c.paths.WorkDir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("failed to start service: %w", err)
	}
	_ = logFile.Close() // Child retains its own file descriptor

	return nil
}

// waitForHealthy polls until the service becomes healthy or times out.
func (c *Client) waitForHealthy(ctx context.Context) error {
	deadline := time.Now().Add(startupTimeout)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if c.CheckHealth(ctx) == nil {
			return nil
		}

		time.Sleep(startupPollInterval)
	}

	return fmt.Errorf("service did not become healthy within %v", startupTimeout)
}

func (c *Client) doRequest(ctx context.Context, method, path string, body io.Reader) (*APIResponse, error) {
	url := "http://sectool" + path // Host is ignored for Unix sockets

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	} else if !apiResp.OK {
		if apiResp.Error != nil {
			return nil, apiResp.Error
		}
		return nil, errors.New("request failed with unknown error")
	}

	return &apiResp, nil
}

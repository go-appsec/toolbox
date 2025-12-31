package service

import (
	"bytes"
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
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("redirect not allowed")
		},
	}

	return c
}

// LogPath returns the relative path to the service log file for display.
func (c *Client) LogPath() string {
	return c.paths.RelPath(c.paths.LogFile)
}

// EnsureService ensures the service is running, starting it if necessary.
func (c *Client) EnsureService(ctx context.Context) error {
	// Validate socket path security if directory exists (before connecting)
	if _, err := os.Stat(c.paths.ServiceDir); err == nil {
		if err := ValidateSocketPathSecurity(c.paths.SocketPath); err != nil {
			return fmt.Errorf("socket security validation failed: %w", err)
		}
	}

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
	if err := os.MkdirAll(c.paths.ServiceDir, 0700); err != nil {
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

	logFile, err := os.OpenFile(c.paths.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
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

	return fmt.Errorf("service did not become healthy within %v (check %s)", startupTimeout, c.LogPath())
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

// doJSONRequest sends a POST request with a JSON body and parses the response into result.
func (c *Client) doJSONRequest(ctx context.Context, path string, reqBody interface{}, result interface{}) error {
	var body io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("failed to marshal request: %w", err)
		}
		body = bytes.NewReader(data)
	}

	resp, err := c.doRequest(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}

	if result != nil && len(resp.Data) > 0 {
		if err := json.Unmarshal(resp.Data, result); err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}
	}

	return nil
}

// =============================================================================
// Proxy API
// =============================================================================

// ProxyList lists proxy history entries.
func (c *Client) ProxyList(ctx context.Context, req *ProxyListRequest) (*ProxyListResponse, error) {
	var resp ProxyListResponse
	if err := c.doJSONRequest(ctx, "/proxy/list", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ProxyExport exports a flow to disk for editing.
func (c *Client) ProxyExport(ctx context.Context, req *ProxyExportRequest) (*ProxyExportResponse, error) {
	var resp ProxyExportResponse
	if err := c.doJSONRequest(ctx, "/proxy/export", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// =============================================================================
// Replay API
// =============================================================================

// ReplaySend sends a request through the repeater.
func (c *Client) ReplaySend(ctx context.Context, req *ReplaySendRequest) (*ReplaySendResponse, error) {
	var resp ReplaySendResponse
	if err := c.doJSONRequest(ctx, "/replay/send", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ReplayGet retrieves details for a previous replay.
func (c *Client) ReplayGet(ctx context.Context, req *ReplayGetRequest) (*ReplayGetResponse, error) {
	var resp ReplayGetResponse
	if err := c.doJSONRequest(ctx, "/replay/get", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// =============================================================================
// OAST API
// =============================================================================

// OastCreate creates a new OAST session.
func (c *Client) OastCreate(ctx context.Context, req *OastCreateRequest) (*OastCreateResponse, error) {
	var resp OastCreateResponse
	if err := c.doJSONRequest(ctx, "/oast/create", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OastPoll polls for OAST interaction events.
func (c *Client) OastPoll(ctx context.Context, req *OastPollRequest) (*OastPollResponse, error) {
	var resp OastPollResponse
	if err := c.doJSONRequest(ctx, "/oast/poll", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OastGet retrieves full details for a specific OAST event.
func (c *Client) OastGet(ctx context.Context, req *OastGetRequest) (*OastGetResponse, error) {
	var resp OastGetResponse
	if err := c.doJSONRequest(ctx, "/oast/get", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OastList lists active OAST sessions.
func (c *Client) OastList(ctx context.Context, req *OastListRequest) (*OastListResponse, error) {
	var resp OastListResponse
	if err := c.doJSONRequest(ctx, "/oast/list", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// OastDelete deletes an OAST session.
func (c *Client) OastDelete(ctx context.Context, req *OastDeleteRequest) (*OastDeleteResponse, error) {
	var resp OastDeleteResponse
	if err := c.doJSONRequest(ctx, "/oast/delete", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// =============================================================================
// Rule API
// =============================================================================

// RuleList lists match/replace rules.
func (c *Client) RuleList(ctx context.Context, req *RuleListRequest) (*RuleListResponse, error) {
	var resp RuleListResponse
	if err := c.doJSONRequest(ctx, "/proxy/rule/list", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RuleAdd creates a new match/replace rule.
func (c *Client) RuleAdd(ctx context.Context, req *RuleAddRequest) (*RuleEntry, error) {
	var resp RuleEntry
	if err := c.doJSONRequest(ctx, "/proxy/rule/add", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RuleUpdate modifies an existing match/replace rule.
func (c *Client) RuleUpdate(ctx context.Context, req *RuleUpdateRequest) (*RuleEntry, error) {
	var resp RuleEntry
	if err := c.doJSONRequest(ctx, "/proxy/rule/update", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RuleDelete removes a match/replace rule.
func (c *Client) RuleDelete(ctx context.Context, req *RuleDeleteRequest) (*RuleDeleteResponse, error) {
	var resp RuleDeleteResponse
	if err := c.doJSONRequest(ctx, "/proxy/rule/delete", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

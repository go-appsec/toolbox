package service

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

// ServicePaths holds all the filesystem paths used by the service.
// Consolidates path computation for both Client and Server.
type ServicePaths struct {
	WorkDir     string // Base working directory
	ServiceDir  string // .sectool/service/
	SocketPath  string // .sectool/service/socket
	PIDPath     string // .sectool/service/pid (also used for flock)
	LogFile     string // .sectool/service/logs.txt
	RequestsDir string // .sectool/requests/
}

func NewServicePaths(workDir string) ServicePaths {
	serviceDir := filepath.Join(workDir, ".sectool", "service")
	return ServicePaths{
		WorkDir:     workDir,
		ServiceDir:  serviceDir,
		SocketPath:  filepath.Join(serviceDir, "socket"),
		PIDPath:     filepath.Join(serviceDir, "pid"),
		LogFile:     filepath.Join(serviceDir, "logs.txt"),
		RequestsDir: filepath.Join(workDir, ".sectool", "requests"),
	}
}

// APIResponse is the standard envelope for all API responses.
type APIResponse struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error *APIError       `json:"error,omitempty"`
}

// APIError represents a structured error response.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

func (e *APIError) Error() string {
	if e.Hint != "" {
		return fmt.Sprintf("%s: %s (hint: %s)", e.Code, e.Message, e.Hint)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Common error codes
const (
	ErrCodeServiceUnavailable = "SERVICE_UNAVAILABLE"
	ErrCodeBurpUnreachable    = "BURP_UNREACHABLE"
	ErrCodeInvalidRequest     = "INVALID_REQUEST"
	ErrCodeNotFound           = "NOT_FOUND"
	ErrCodeInternal           = "INTERNAL_ERROR"
	ErrCodeTimeout            = "TIMEOUT"
	ErrCodeValidation         = "VALIDATION_ERROR"
)

func NewAPIError(code, message, hint string) *APIError {
	return &APIError{
		Code:    code,
		Message: message,
		Hint:    hint,
	}
}

// HealthResponse is returned by GET /health.
type HealthResponse struct {
	Version       string            `json:"version"`
	StartedAt     string            `json:"started_at"`
	BurpConnected bool              `json:"burp_connected"`
	BurpMCPURL    string            `json:"burp_mcp_url,omitempty"`
	Metrics       map[string]string `json:"metrics,omitempty"`
}

// HealthMetricProvider is a function that returns a metric value for a given key.
// Providers are registered with the server and called during health checks.
type HealthMetricProvider func() string

// ServiceStatus represents the service status for CLI display.
type ServiceStatus struct {
	Running    bool            `json:"running"`
	PID        int             `json:"pid,omitempty"`
	Health     *HealthResponse `json:"health,omitempty"`
	SocketPath string          `json:"socket_path"`
}

// StopResponse is returned by POST /srv/stop.
type StopResponse struct {
	Message string `json:"message"`
}

func SuccessResponse(data interface{}) (*APIResponse, error) {
	var rawData json.RawMessage
	if data != nil {
		b, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		rawData = b
	}
	return &APIResponse{
		OK:   true,
		Data: rawData,
	}, nil
}

func ErrorResponse(code, message, hint string) *APIResponse {
	return &APIResponse{
		OK:    false,
		Error: NewAPIError(code, message, hint),
	}
}

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// ServicePaths holds all the filesystem paths used by the service.
// Consolidates path computation for both Client and Server.
type ServicePaths struct {
	WorkDir     string // Base working directory
	SectoolDir  string // .sectool/
	ConfigPath  string // .sectool/config.json
	ServiceDir  string // .sectool/service/
	SocketPath  string // .sectool/service/socket
	PIDPath     string // .sectool/service/pid (also used for flock)
	LogFile     string // .sectool/service/log.txt
	RequestsDir string // .sectool/requests/
}

func NewServicePaths(workDir string) ServicePaths {
	sectoolDir := filepath.Join(workDir, ".sectool")
	serviceDir := filepath.Join(sectoolDir, "service")
	return ServicePaths{
		WorkDir:     workDir,
		SectoolDir:  sectoolDir,
		ConfigPath:  filepath.Join(sectoolDir, "config.json"),
		ServiceDir:  serviceDir,
		SocketPath:  filepath.Join(serviceDir, "socket"),
		PIDPath:     filepath.Join(serviceDir, "pid"),
		LogFile:     filepath.Join(serviceDir, "log.txt"),
		RequestsDir: filepath.Join(sectoolDir, "requests"),
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

const (
	ErrCodeBackendError   = "BACKEND_ERROR"
	ErrCodeInvalidRequest = "INVALID_REQUEST"
	ErrCodeNotFound       = "NOT_FOUND"
	ErrCodeInternal       = "INTERNAL_ERROR"
	ErrCodeTimeout        = "TIMEOUT"
	ErrCodeValidation     = "VALIDATION_ERROR"
)

// IsTimeoutError returns true if the error is a timeout (context deadline exceeded,
// network timeout, etc). Used to distinguish timeout errors from other backend errors.
func IsTimeoutError(err error) bool {
	if err == nil {
		return false
	} else if errors.Is(err, context.DeadlineExceeded) {
		return true
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}

func NewAPIError(code, message, hint string) *APIError {
	return &APIError{
		Code:    code,
		Message: message,
		Hint:    hint,
	}
}

// HealthResponse is returned by GET /health.
type HealthResponse struct {
	Version   string            `json:"version"`
	StartedAt string            `json:"started_at"`
	Metrics   map[string]string `json:"metrics,omitempty"`
}

// HealthMetricProvider is a function that returns a metric value for a given key.
// Providers are registered with the server and called during health checks.
type HealthMetricProvider func() string

// ServiceStatus represents the service status for CLI display.
type ServiceStatus struct {
	Running    bool
	PID        int
	Health     *HealthResponse
	SocketPath string
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

// =============================================================================
// Proxy Types
// =============================================================================

// ProxyListRequest is the request for POST /proxy/list.
type ProxyListRequest struct {
	Host         string `json:"host,omitempty"`
	Path         string `json:"path,omitempty"`
	Method       string `json:"method,omitempty"`
	Status       string `json:"status,omitempty"`
	Contains     string `json:"contains,omitempty"`
	ContainsBody string `json:"contains_body,omitempty"`
	Since        string `json:"since,omitempty"`
	ExcludeHost  string `json:"exclude_host,omitempty"`
	ExcludePath  string `json:"exclude_path,omitempty"`
	Limit        int    `json:"limit,omitempty"`
}

// HasFilters returns true if any filter is set.
func (r *ProxyListRequest) HasFilters() bool {
	return r.Host != "" || r.Path != "" || r.Method != "" || r.Status != "" ||
		r.Contains != "" || r.ContainsBody != "" || r.Since != "" ||
		r.ExcludeHost != "" || r.ExcludePath != "" || r.Limit > 0
}

// ProxyListResponse is the response for POST /proxy/list.
// When no filters are applied, Aggregates is populated.
// When filters are applied, Flows is populated.
type ProxyListResponse struct {
	Aggregates []AggregateEntry `json:"aggregates,omitempty"`
	Flows      []FlowSummary    `json:"flows,omitempty"`
}

// AggregateEntry represents a grouped count of traffic by (host, path, method, status).
type AggregateEntry struct {
	Host   string `json:"host"`
	Path   string `json:"path"`
	Method string `json:"method"`
	Status int    `json:"status"`
	Count  int    `json:"count"`
}

// FlowSummary represents a single proxy history entry in list view.
type FlowSummary struct {
	FlowID         string `json:"flow_id"`
	Method         string `json:"method"`
	Scheme         string `json:"scheme"`
	Host           string `json:"host"`
	Port           int    `json:"port,omitempty"`
	Path           string `json:"path"`
	Status         int    `json:"status"`
	ResponseLength int    `json:"response_length"`
}

// ProxyExportRequest is the request for POST /proxy/export.
type ProxyExportRequest struct {
	FlowID string `json:"flow_id"`
	OutDir string `json:"out_dir,omitempty"`
}

// ProxyExportResponse is the response for POST /proxy/export.
type ProxyExportResponse struct {
	BundleID   string `json:"bundle_id"`
	BundlePath string `json:"bundle_path"`
}

// =============================================================================
// Common Response Types
// =============================================================================

// ResponseDetails contains HTTP response summary fields.
// Embedded in responses that include response data.
type ResponseDetails struct {
	Status      int    `json:"status"`
	StatusLine  string `json:"status_line"`
	RespHeaders string `json:"response_headers"`
	RespPreview string `json:"response_preview,omitempty"`
	RespSize    int    `json:"response_size"`
}

// =============================================================================
// Replay Types
// =============================================================================

// ReplaySendRequest is the request for POST /replay/send.
// Exactly one of FlowID, BundlePath, or FilePath must be set.
type ReplaySendRequest struct {
	FlowID          string   `json:"flow_id,omitempty"`
	BundlePath      string   `json:"bundle_path,omitempty"`
	FilePath        string   `json:"file_path,omitempty"`
	BodyPath        string   `json:"body_path,omitempty"`
	Target          string   `json:"target,omitempty"`
	AddHeaders      []string `json:"add_headers,omitempty"`
	RemoveHeaders   []string `json:"remove_headers,omitempty"`
	Path            string   `json:"path,omitempty"`
	Query           string   `json:"query,omitempty"`
	SetQuery        []string `json:"set_query,omitempty"`
	RemoveQuery     []string `json:"remove_query,omitempty"`
	FollowRedirects bool     `json:"follow_redirects,omitempty"`
	Timeout         string   `json:"timeout,omitempty"`
	Force           bool     `json:"force,omitempty"`
}

// ReplaySendResponse is the response for POST /replay/send.
type ReplaySendResponse struct {
	ReplayID string `json:"replay_id"`
	Duration string `json:"duration"`
	ResponseDetails
}

// ReplayGetRequest is the request for POST /replay/get.
type ReplayGetRequest struct {
	ReplayID string `json:"replay_id"`
}

// ReplayGetResponse is the response for POST /replay/get.
// Unlike ReplaySendResponse which returns a preview, this returns the full response.
type ReplayGetResponse struct {
	ReplayID    string `json:"replay_id"`
	Duration    string `json:"duration"`
	Status      int    `json:"status"`
	StatusLine  string `json:"status_line"`
	RespHeaders string `json:"response_headers"`
	RespBody    string `json:"response_body"` // base64 encoded
	RespSize    int    `json:"response_size"`
}

// =============================================================================
// OAST Types
// =============================================================================

// OastCreateResponse is the response for POST /oast/create.
type OastCreateResponse struct {
	OastID string `json:"oast_id"`
	Domain string `json:"domain"`
}

// OastPollRequest is the request for POST /oast/poll.
type OastPollRequest struct {
	OastID string `json:"oast_id"`
	Since  string `json:"since,omitempty"`
	Wait   string `json:"wait,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// OastPollResponse is the response for POST /oast/poll.
type OastPollResponse struct {
	Events       []OastEvent `json:"events"`
	DroppedCount int         `json:"dropped_count,omitempty"`
}

// OastEvent represents a single OAST interaction event.
type OastEvent struct {
	EventID   string                 `json:"event_id"`
	Time      string                 `json:"time"`
	Type      string                 `json:"type"` // dns, http, smtp
	SourceIP  string                 `json:"source_ip"`
	Subdomain string                 `json:"subdomain"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// OastListRequest is the request for POST /oast/list.
type OastListRequest struct {
	Limit int `json:"limit,omitempty"`
}

// OastListResponse is the response for POST /oast/list.
type OastListResponse struct {
	Sessions []OastSession `json:"sessions"`
}

// OastSession represents an active OAST session.
type OastSession struct {
	OastID    string `json:"oast_id"`
	Domain    string `json:"domain"`
	CreatedAt string `json:"created_at"`
}

// OastGetRequest is the request for POST /oast/get.
type OastGetRequest struct {
	OastID  string `json:"oast_id"`
	EventID string `json:"event_id"`
}

// OastGetResponse is the response for POST /oast/get.
// Returns full event details without truncation.
type OastGetResponse struct {
	EventID   string                 `json:"event_id"`
	Time      string                 `json:"time"`
	Type      string                 `json:"type"`
	SourceIP  string                 `json:"source_ip"`
	Subdomain string                 `json:"subdomain"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// OastDeleteRequest is the request for POST /oast/delete.
type OastDeleteRequest struct {
	OastID string `json:"oast_id"`
}

// OastDeleteResponse is the response for POST /oast/delete.
type OastDeleteResponse struct{}

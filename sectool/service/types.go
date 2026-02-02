package service

import (
	"context"
	"errors"
	"net"
	"os"

	"github.com/go-appsec/llm-security-toolbox/sectool/protocol"
)

// HealthMetricProvider is a function that returns a metric value for a given key.
type HealthMetricProvider func() string

// IsTimeoutError returns true if the error is a timeout.
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

// =============================================================================
// Proxy Types
// =============================================================================

// ProxyListRequest contains filters for proxy list queries.
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
	Offset       int    `json:"offset,omitempty"`
}

// HasFilters returns true if any filter is set.
func (r *ProxyListRequest) HasFilters() bool {
	return r.Host != "" || r.Path != "" || r.Method != "" || r.Status != "" ||
		r.Contains != "" || r.ContainsBody != "" || r.Since != "" ||
		r.ExcludeHost != "" || r.ExcludePath != "" || r.Limit > 0
}

// =============================================================================
// Replay Types
// =============================================================================

// ReplaySendRequest contains options for replay_send.
type ReplaySendRequest struct {
	FlowID          string   `json:"flow_id,omitempty"`
	Target          string   `json:"target,omitempty"`
	AddHeaders      []string `json:"add_headers,omitempty"`
	RemoveHeaders   []string `json:"remove_headers,omitempty"`
	Path            string   `json:"path,omitempty"`
	Query           string   `json:"query,omitempty"`
	SetQuery        []string `json:"set_query,omitempty"`
	RemoveQuery     []string `json:"remove_query,omitempty"`
	SetJSON         []string `json:"set_json,omitempty"`
	RemoveJSON      []string `json:"remove_json,omitempty"`
	FollowRedirects bool     `json:"follow_redirects,omitempty"`
	Timeout         string   `json:"timeout,omitempty"`
	Force           bool     `json:"force,omitempty"`
}

// RuleDeleteResponse is the response for proxy_rule_delete.
type RuleDeleteResponse struct{}

// =============================================================================
// OAST Types
// =============================================================================

// OastDeleteResponse is the response for oast_delete.
type OastDeleteResponse struct{}

// =============================================================================
// Crawler Types
// =============================================================================

// CrawlStopResponse is the response for crawl_stop.
type CrawlStopResponse struct {
	Stopped bool `json:"stopped"`
}

// formsToAPI converts DiscoveredForm slice to API format.
func formsToAPI(forms []DiscoveredForm) []protocol.CrawlForm {
	result := make([]protocol.CrawlForm, 0, len(forms))
	for _, f := range forms {
		inputs := make([]protocol.FormInput, 0, len(f.Inputs))
		for _, inp := range f.Inputs {
			inputs = append(inputs, protocol.FormInput(inp))
		}
		result = append(result, protocol.CrawlForm{
			FormID:  f.ID,
			URL:     f.URL,
			Action:  f.Action,
			Method:  f.Method,
			HasCSRF: f.HasCSRF,
			Inputs:  inputs,
		})
	}
	return result
}

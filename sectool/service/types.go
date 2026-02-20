package service

import (
	"context"
	"errors"
	"net"
	"os"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

// Flow source constants for display and sorting.
const (
	SourceProxy  = "proxy"
	SourceReplay = "replay"
	SourceCrawl  = "crawl"
)

// Output mode constants for poll tools.
const (
	OutputModeFlows   = "flows"
	OutputModeSummary = "summary"
	OutputModeForms   = "forms"
	OutputModeErrors  = "errors"
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
	SearchHeader string `json:"search_header,omitempty"`
	SearchBody   string `json:"search_body,omitempty"`
	Since        string `json:"since,omitempty"`
	ExcludeHost  string `json:"exclude_host,omitempty"`
	ExcludePath  string `json:"exclude_path,omitempty"`
	Limit        int    `json:"limit,omitempty"`
	Offset       int    `json:"offset,omitempty"`
	Source       string `json:"source,omitempty"`
}

// HasFilters returns true if any filter is set.
func (r *ProxyListRequest) HasFilters() bool {
	return r.Host != "" || r.Path != "" || r.Method != "" || r.Status != "" ||
		r.SearchHeader != "" || r.SearchBody != "" || r.Since != "" ||
		r.ExcludeHost != "" || r.ExcludePath != "" || r.Limit > 0 ||
		r.Source != ""
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

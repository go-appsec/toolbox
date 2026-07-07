package proxy

import "github.com/go-appsec/toolbox/sectool/service/proxy/types"

// CaptureFilter decides whether a flow should be stored.
// Returns true if the flow should be captured, false to discard.
type CaptureFilter func(flow *types.Flow) bool

// SetCaptureFilter sets the filter checked by ShouldCapture.
// Callers of Store are responsible for checking ShouldCapture first.
func (h *HistoryStore) SetCaptureFilter(f CaptureFilter) {
	if f == nil {
		return
	}
	h.captureFilter.Store(f)
}

// ShouldCapture returns true if the flow passes the capture filter,
// or true when no filter is configured.
func (h *HistoryStore) ShouldCapture(flow *types.Flow) bool {
	f := h.captureFilter.Load()
	if f == nil {
		return true
	}
	return f.(CaptureFilter)(flow)
}

package proxy

// CaptureFilter decides whether a history entry should be stored.
// Returns true if the entry should be captured, false to discard.
type CaptureFilter func(entry *HistoryEntry) bool

// SetCaptureFilter sets the filter checked by ShouldCapture.
// Callers of Store are responsible for checking ShouldCapture first.
func (h *HistoryStore) SetCaptureFilter(f CaptureFilter) {
	if f == nil {
		return
	}
	h.captureFilter.Store(f)
}

// ShouldCapture returns true if the entry passes the capture filter,
// or true when no filter is configured.
func (h *HistoryStore) ShouldCapture(entry *HistoryEntry) bool {
	f := h.captureFilter.Load()
	if f == nil {
		return true
	}
	return f.(CaptureFilter)(entry)
}

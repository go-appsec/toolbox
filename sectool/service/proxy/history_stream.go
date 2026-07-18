package proxy

import "time"

const (
	// streamFlushBytes coalesces history writes: flush once this many new body bytes accumulate.
	streamFlushBytes = 64 << 10
	// streamFlushInterval coalesces history writes: flush at least this often while data trickles.
	streamFlushInterval = 250 * time.Millisecond
)

// Annotation keys and reasons recorded on a finalized streaming flow.
const (
	annStreamTruncated     = "stream_truncated"          // stream ended before the body completed
	annStreamReason        = "stream_reason"             // why the stream was truncated
	annBodyTruncated       = "body_truncated_in_history" // stored body hit maxBodyBytes; wire was complete
	reasonClientDisconnect = "client_disconnect"
	reasonUpstreamError    = "upstream_error"
	reasonStreamIdle       = "stream_idle" // stream reaped after idle timeout
	reasonConnClosed       = "conn_closed" // connection torn down with the stream still open
)

// flushThrottle gates coalesced two-phase history writes during a streaming
// response. Wire forwarding is always per-unit; only persistence is throttled,
// so a poller sees a slightly-stale snapshot with no fidelity cost.
type flushThrottle struct {
	minBytes    int           // byte-delta threshold since the last flush
	minInterval time.Duration // time threshold since the last flush
	lastLen     int           // body length at the last flush
	lastAt      time.Time     // wall-clock of the last flush
}

// newFlushThrottle returns a throttle using the default byte and interval thresholds.
func newFlushThrottle() flushThrottle {
	return flushThrottle{minBytes: streamFlushBytes, minInterval: streamFlushInterval}
}

// should reports whether a flush is due at body length curLen and time now,
// based on bytes added or time elapsed since the last mark. The first call
// (before any mark) is always due, for prompt initial visibility.
func (t *flushThrottle) should(curLen int, now time.Time) bool {
	if t.lastAt.IsZero() || curLen-t.lastLen >= t.minBytes {
		return true
	}
	return now.Sub(t.lastAt) >= t.minInterval
}

// mark records a flush at body length curLen and time now.
func (t *flushThrottle) mark(curLen int, now time.Time) {
	t.lastLen = curLen
	t.lastAt = now
}

// truncationAnnotations builds finalize-time annotations for a streamed flow,
// or nil when the stream was neither truncated nor body-capped.
func truncationAnnotations(reason string, bodyTruncated bool) map[string]any {
	if reason == "" && !bodyTruncated {
		return nil
	}
	ann := make(map[string]any, 3)
	if reason != "" {
		ann[annStreamTruncated] = true
		ann[annStreamReason] = reason
	}
	if bodyTruncated {
		ann[annBodyTruncated] = true
	}
	return ann
}

package proxy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFlushThrottleShould(t *testing.T) {
	t.Parallel()

	base := time.Unix(1700000000, 0)

	t.Run("first_call_always_due", func(t *testing.T) {
		tr := flushThrottle{minBytes: 1024, minInterval: time.Second}
		assert.True(t, tr.should(0, base))
	})

	t.Run("byte_threshold", func(t *testing.T) {
		tr := flushThrottle{minBytes: 1024, minInterval: time.Second}
		tr.mark(0, base)
		assert.False(t, tr.should(1023, base))
		assert.True(t, tr.should(1024, base))
	})

	t.Run("time_threshold", func(t *testing.T) {
		tr := flushThrottle{minBytes: 1024, minInterval: time.Second}
		tr.mark(0, base)
		assert.False(t, tr.should(10, base.Add(999*time.Millisecond)))
		assert.True(t, tr.should(10, base.Add(time.Second)))
	})

	t.Run("mark_resets_baseline", func(t *testing.T) {
		tr := flushThrottle{minBytes: 1024, minInterval: time.Second}
		tr.mark(0, base)
		tr.mark(2000, base.Add(2*time.Second))
		assert.False(t, tr.should(2500, base.Add(2*time.Second)))
	})
}

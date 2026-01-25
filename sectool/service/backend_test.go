package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseSinceTimestamp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantOK  bool
		wantUTC string // expected time in UTC format for comparison
	}{
		{"rfc3339_utc", "2024-01-15T10:30:00Z", true, "2024-01-15T10:30:00Z"},
		{"rfc3339_offset", "2024-01-15T10:30:00+05:00", true, "2024-01-15T05:30:00Z"},
		{"rfc3339_negative_offset", "2024-01-15T10:30:00-08:00", true, "2024-01-15T18:30:00Z"},
		{"datetime_no_tz", "2024-01-15T10:30:00", true, ""}, // local TZ, can't compare directly
		{"time_only", "10:30:00", true, ""},                 // assumes today's date, local TZ
		{"flow_id", "abc123", false, ""},
		{"last_keyword", "last", false, ""},
		{"invalid_format", "2024/01/15", false, ""},
		{"empty", "", false, ""},
		{"partial_date", "2024-01", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := parseSinceTimestamp(tt.input)
			assert.Equal(t, tt.wantOK, ok, "parseSinceTimestamp(%q) ok mismatch", tt.input)
			if ok && tt.wantUTC != "" {
				assert.Equal(t, tt.wantUTC, result.UTC().Format(time.RFC3339))
			}
			if ok {
				assert.False(t, result.IsZero(), "parsed time should not be zero")
			}
		})
	}
}

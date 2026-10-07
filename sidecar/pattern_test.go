package sidecar

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQuotePattern(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in, out string
	}{
		{in: "ctrl.example.com", out: `ctrl\.example\.com`},
		{in: "plain/path", out: "plain/path"},
		{in: `a[b](c){d}|e^$.*+?\`, out: `a\[b\]\(c\)\{d\}\|e\^\$\.\*\+\?\\`},
		{in: "", out: ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.out, QuotePattern(tt.in))
	}
}

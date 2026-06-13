package dedupe

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"single", []string{"a"}, []string{"a"}},
		{"no_dups", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"adjacent_dups", []string{"a", "a", "b"}, []string{"a", "b"}},
		{"preserves_order", []string{"c", "a", "c", "b", "a"}, []string{"c", "a", "b"}},
		{"empty_string", []string{"", "", "a"}, []string{"", "a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, Slice(tt.in))
		})
	}
}

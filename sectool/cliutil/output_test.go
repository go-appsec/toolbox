package cliutil

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOutputConfig_IsTTY(t *testing.T) {
	tests := []struct {
		name      string
		config    *OutputConfig
		wantIsTTY bool
	}{
		{
			name:      "nil_config",
			config:    nil,
			wantIsTTY: false,
		},
		{
			name: "color_always",
			config: &OutputConfig{
				Writer:    &bytes.Buffer{},
				ColorMode: ColorAlways,
			},
			wantIsTTY: true,
		},
		{
			name: "color_never",
			config: &OutputConfig{
				Writer:    os.Stdout,
				ColorMode: ColorNever,
			},
			wantIsTTY: false,
		},
		{
			name: "non_file_writer",
			config: &OutputConfig{
				Writer:    &bytes.Buffer{},
				ColorMode: ColorAuto,
			},
			wantIsTTY: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantIsTTY, tc.config.IsTTY())
		})
	}
}

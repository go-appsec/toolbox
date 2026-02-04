package cliutil

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	ansiFaint = "\x1b[2m"
	ansiCyan  = "\x1b[36m"
	ansiReset = "\x1b[0m"
)

func TestHint(t *testing.T) {
	t.Run("no_color", func(t *testing.T) {
		Output = &OutputConfig{
			Writer:    &bytes.Buffer{},
			ColorMode: ColorNever,
		}

		buf := &bytes.Buffer{}
		Hint(buf, "This is a hint")
		assert.Equal(t, "This is a hint\n", buf.String())
	})

	t.Run("with_color", func(t *testing.T) {
		Output = &OutputConfig{
			Writer:    &bytes.Buffer{},
			ColorMode: ColorAlways,
		}

		buf := &bytes.Buffer{}
		Hint(buf, "This is a hint")
		got := buf.String()

		assert.Contains(t, got, ansiFaint)
		assert.Contains(t, got, ansiReset)
		assert.Contains(t, got, "This is a hint")
		assert.Equal(t, ansiFaint+"This is a hint"+ansiReset+"\n", got)
	})
}

func TestHint_NilWriter(t *testing.T) {
	Output = &OutputConfig{
		Writer:    &bytes.Buffer{},
		ColorMode: ColorNever,
	}

	// should not panic with nil writer
	Hint(nil, "message")
}

func TestHintCommand(t *testing.T) {
	t.Run("no_color", func(t *testing.T) {
		Output = &OutputConfig{
			Writer:    &bytes.Buffer{},
			ColorMode: ColorNever,
		}

		buf := &bytes.Buffer{}
		HintCommand(buf, "To list flows", "sectool proxy list")
		got := buf.String()

		assert.Equal(t, "To list flows: sectool proxy list\n", got)
	})

	t.Run("with_color", func(t *testing.T) {
		Output = &OutputConfig{
			Writer:    &bytes.Buffer{},
			ColorMode: ColorAlways,
		}

		buf := &bytes.Buffer{}
		HintCommand(buf, "To list flows", "sectool proxy list")
		got := buf.String()

		// description uses Muted (faint)
		assert.Contains(t, got, ansiFaint+"To list flows"+ansiReset)
		// command uses ID (cyan)
		assert.Contains(t, got, ansiCyan+"sectool proxy list"+ansiReset)
		// full format: "muted_desc: cyan_cmd\n"
		expected := ansiFaint + "To list flows" + ansiReset + ": " + ansiCyan + "sectool proxy list" + ansiReset + "\n"
		assert.Equal(t, expected, got)
	})
}

func TestHintCommand_NilWriter(t *testing.T) {
	Output = &OutputConfig{
		Writer:    &bytes.Buffer{},
		ColorMode: ColorNever,
	}

	// should not panic with nil writer
	HintCommand(nil, "desc", "cmd")
}

func TestSummary(t *testing.T) {
	t.Run("no_color", func(t *testing.T) {
		tests := []struct {
			name     string
			count    int
			singular string
			plural   string
			want     string
		}{
			{
				name:     "plural",
				count:    5,
				singular: "flow",
				plural:   "flows",
				want:     "\n5 flows\n",
			},
			{
				name:     "singular",
				count:    1,
				singular: "flow",
				plural:   "flows",
				want:     "\n1 flow\n",
			},
			{
				name:     "zero",
				count:    0,
				singular: "flow",
				plural:   "flows",
				want:     "\n0 flows\n",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				Output = &OutputConfig{
					Writer:    &bytes.Buffer{},
					ColorMode: ColorNever,
				}

				buf := &bytes.Buffer{}
				Summary(buf, tc.count, tc.singular, tc.plural)
				assert.Equal(t, tc.want, buf.String())
			})
		}
	})

	t.Run("with_color", func(t *testing.T) {
		tests := []struct {
			name     string
			count    int
			singular string
			plural   string
			want     string
		}{
			{
				name:     "plural",
				count:    5,
				singular: "flow",
				plural:   "flows",
				want:     "\n" + ansiFaint + "5 flows" + ansiReset + "\n",
			},
			{
				name:     "singular",
				count:    1,
				singular: "flow",
				plural:   "flows",
				want:     "\n" + ansiFaint + "1 flow" + ansiReset + "\n",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				Output = &OutputConfig{
					Writer:    &bytes.Buffer{},
					ColorMode: ColorAlways,
				}

				buf := &bytes.Buffer{}
				Summary(buf, tc.count, tc.singular, tc.plural)
				got := buf.String()

				assert.Contains(t, got, ansiFaint)
				assert.Contains(t, got, ansiReset)
				assert.Equal(t, tc.want, got)
			})
		}
	})
}

func TestSummary_NilWriter(t *testing.T) {
	Output = &OutputConfig{
		Writer:    &bytes.Buffer{},
		ColorMode: ColorNever,
	}

	// should not panic with nil writer
	Summary(nil, 5, "flow", "flows")
}

func TestNoResults(t *testing.T) {
	t.Run("no_color", func(t *testing.T) {
		Output = &OutputConfig{
			Writer:    &bytes.Buffer{},
			ColorMode: ColorNever,
		}

		buf := &bytes.Buffer{}
		NoResults(buf, "No matching entries found.")
		assert.Equal(t, "No matching entries found.\n", buf.String())
	})

	t.Run("with_color", func(t *testing.T) {
		Output = &OutputConfig{
			Writer:    &bytes.Buffer{},
			ColorMode: ColorAlways,
		}

		buf := &bytes.Buffer{}
		NoResults(buf, "No matching entries found.")
		got := buf.String()

		assert.Contains(t, got, ansiFaint)
		assert.Contains(t, got, ansiReset)
		assert.Equal(t, ansiFaint+"No matching entries found."+ansiReset+"\n", got)
	})
}

func TestNoResults_NilWriter(t *testing.T) {
	Output = &OutputConfig{
		Writer:    &bytes.Buffer{},
		ColorMode: ColorNever,
	}

	// should not panic with nil writer
	NoResults(nil, "No results")
}

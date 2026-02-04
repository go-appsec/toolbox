package cliutil

import (
	"io"
	"os"

	"golang.org/x/term"
)

type ColorMode int

const (
	ColorAuto ColorMode = iota // auto-detect based on TTY
	ColorAlways
	ColorNever
)

type OutputConfig struct {
	Writer    io.Writer
	ColorMode ColorMode
}

var Output *OutputConfig

func init() {
	colorMode := ColorAuto
	if os.Getenv("NO_COLOR") != "" {
		colorMode = ColorNever
	} else if os.Getenv("FORCE_COLOR") != "" {
		colorMode = ColorAlways
	}

	Output = &OutputConfig{
		Writer:    os.Stdout,
		ColorMode: colorMode,
	}
}

// IsTTY returns true if output should be formatted for a terminal.
func (o *OutputConfig) IsTTY() bool {
	if o == nil {
		return false
	} else if o.ColorMode == ColorAlways {
		return true
	} else if o.ColorMode == ColorNever {
		return false
	} else if f, ok := o.Writer.(*os.File); ok {
		return term.IsTerminal(int(f.Fd()))
	}
	return false
}

func (o *OutputConfig) ColorsEnabled() bool {
	return o.IsTTY()
}

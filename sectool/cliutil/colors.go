package cliutil

import (
	"strconv"

	"github.com/jedib0t/go-pretty/v6/text"
)

func formatColor(c text.Color, s string) string {
	if !Output.ColorsEnabled() {
		return s
	}
	return c.Sprint(s)
}

// StatusColor returns the appropriate color for an HTTP status code.
func StatusColor(status int) text.Color {
	switch {
	case status >= 200 && status < 300:
		return text.FgGreen
	case status >= 300 && status < 400:
		return text.FgCyan
	case status >= 400 && status < 500:
		return text.FgYellow
	case status >= 500:
		return text.FgRed
	default:
		return text.Reset
	}
}

// FormatStatus returns a colored status code string.
func FormatStatus(status int) string {
	if !Output.ColorsEnabled() {
		return strconv.Itoa(status)
	}
	return StatusColor(status).Sprint(status)
}

// Bold returns text with bold formatting.
func Bold(s string) string {
	return formatColor(text.Bold, s)
}

// Muted returns text with faint/dim formatting.
func Muted(s string) string {
	return formatColor(text.Faint, s)
}

// ID returns text formatted as an identifier.
func ID(s string) string {
	return formatColor(text.FgCyan, s)
}

// Success returns text formatted as success.
func Success(s string) string {
	return formatColor(text.FgGreen, s)
}

// Warning returns text formatted as warning.
func Warning(s string) string {
	return formatColor(text.FgYellow, s)
}

// Error returns text formatted as error.
func Error(s string) string {
	return formatColor(text.FgRed, s)
}

package proxy

import (
	"strings"
)

func escapeMarkdown(s string) string {
	// Escape characters that break markdown tables
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

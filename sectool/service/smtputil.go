package service

import "strings"

// extractEmailTo extracts addresses from the "To:" email header, handling folded lines.
// Returns nil if no To header is found.
func extractEmailTo(headers string) []string {
	var toValue string
	lines := strings.Split(headers, "\n")
	for i, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		if len(trimmed) >= 3 && strings.EqualFold(trimmed[:3], "to:") {
			var b strings.Builder
			b.WriteString(strings.TrimSpace(trimmed[3:]))
			// Collect folded continuation lines (start with space or tab)
			for j := i + 1; j < len(lines); j++ {
				next := strings.TrimRight(lines[j], "\r")
				if len(next) > 0 && (next[0] == ' ' || next[0] == '\t') {
					b.WriteByte(' ')
					b.WriteString(strings.TrimSpace(next))
				} else {
					break
				}
			}
			toValue = b.String()
			break
		}
	}
	if toValue == "" {
		return nil
	}

	parts := strings.Split(toValue, ",")
	var addrs []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Extract angle-bracket address: "Name <addr>" -> "addr"
		if start := strings.LastIndexByte(part, '<'); start >= 0 {
			if end := strings.IndexByte(part[start:], '>'); end >= 0 {
				addr := part[start+1 : start+end]
				if addr != "" {
					addrs = append(addrs, addr)
				}
				continue
			}
		}
		addrs = append(addrs, part)
	}
	return addrs
}

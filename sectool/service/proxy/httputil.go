package proxy

import (
	"bytes"
	"net/url"
	"strings"

	"github.com/go-analyze/bulk"
)

// ExtractMethod extracts the HTTP method from raw request bytes.
// Returns the first space-delimited token from the request line.
// Handles both CRLF and bare-LF line endings. Defaults to "GET"
// for empty input or lines without a space.
func ExtractMethod(raw []byte) string {
	if len(raw) == 0 {
		return "GET"
	}
	// Find end of request line (CRLF or bare LF)
	line := raw
	if idx := bytes.IndexByte(raw, '\n'); idx >= 0 {
		line = raw[:idx]
	}
	// Trim trailing CR if present
	line = bytes.TrimRight(line, "\r")
	// Extract method (first token before space)
	if idx := bytes.IndexByte(line, ' '); idx > 0 {
		return string(line[:idx])
	}
	if len(line) > 0 {
		return string(line)
	}
	return "GET"
}

// HeaderGroup represents headers sharing the same name (case-insensitive).
type HeaderGroup struct {
	Key     string   // lowercase header name
	Entries []string // original "Name: Value" strings
}

// GroupHeaderEntries groups "Name: Value" strings by header name
// (case-insensitive), preserving insertion order.
func GroupHeaderEntries(entries []string) []HeaderGroup {
	groups := make(map[string]*HeaderGroup)
	var order []string

	for _, h := range entries {
		idx := strings.Index(h, ":")
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(h[:idx]))
		if g, ok := groups[key]; ok {
			g.Entries = append(g.Entries, h)
		} else {
			groups[key] = &HeaderGroup{Key: key, Entries: []string{h}}
			order = append(order, key)
		}
	}

	result := make([]HeaderGroup, len(order))
	for i, key := range order {
		result[i] = *groups[key]
	}
	return result
}

// ContainsHeader checks if any "Name: Value" entry matches the given
// header name (case-insensitive).
func ContainsHeader(entries []string, name string) bool {
	name = strings.ToLower(name)
	for _, h := range entries {
		if idx := strings.Index(h, ":"); idx > 0 {
			if strings.ToLower(strings.TrimSpace(h[:idx])) == name {
				return true
			}
		}
	}
	return false
}

// keysMatch compares a raw query key against a parameter key.
// Matches literally first, then falls back to URL-decoding either side.
func keysMatch(queryKey, paramKey string) bool {
	if queryKey == paramKey {
		return true
	} else if decoded, err := url.QueryUnescape(queryKey); err == nil && decoded != queryKey && decoded == paramKey {
		return true
	} else if decoded, err = url.QueryUnescape(paramKey); err == nil && decoded != paramKey && queryKey == decoded {
		return true
	}
	return false
}

// ApplyRawQueryModifications applies set and remove operations to a raw query
// string without parsing/re-encoding, preserving parameter order and percent-encoding.
func ApplyRawQueryModifications(query string, remove []string, set []string) string {
	parts := strings.Split(query, "&")
	if len(parts) == 1 && parts[0] == "" {
		parts = nil
	}

	if len(remove) > 0 {
		removeSet := bulk.SliceToSet(remove)
		parts = bulk.SliceFilterInPlace(func(p string) bool {
			key, _, _ := strings.Cut(p, "=")
			for rk := range removeSet {
				if keysMatch(key, rk) {
					return false
				}
			}
			return true
		}, parts)
	}

	for _, entry := range set {
		key, _, _ := strings.Cut(entry, "=")
		var replaced bool
		for i, p := range parts {
			existingKey, _, _ := strings.Cut(p, "=")
			if keysMatch(existingKey, key) {
				parts[i] = entry
				replaced = true
				break
			}
		}
		if !replaced {
			parts = append(parts, entry)
		}
	}

	return strings.Join(parts, "&")
}

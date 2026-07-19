package proxy

import (
	"bytes"
	"net"
	"strconv"
	"strings"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
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

// sendError writes a plain-text HTTP/1.1 error response to the client and closes.
func sendError(conn net.Conn, code int, message string) {
	body := []byte(message + "\n")
	resp := &types.RawHTTP1Response{
		Version:    "HTTP/1.1",
		StatusCode: code,
		StatusText: message,
		Headers: []types.Header{
			{Name: "Content-Type", Value: "text/plain"},
			{Name: "Content-Length", Value: strconv.Itoa(len(body))},
			{Name: "Connection", Value: "close"},
		},
		Body: body,
	}
	_, _ = conn.Write(resp.SerializeRaw(bytes.NewBuffer(nil)))
}

// PathWithoutQuery returns the path portion before any query string.
func PathWithoutQuery(p string) string {
	if idx := strings.Index(p, "?"); idx >= 0 {
		return p[:idx]
	}
	return p
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

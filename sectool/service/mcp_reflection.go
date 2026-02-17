package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

const minReflectionValueLen = 4

// Standard headers unlikely to represent user-controlled reflection vectors.
// Uses lowercase keys for case-insensitive lookup (matches H2 lowercase headers directly).
var skipReflectionHeader = map[string]bool{
	"host":                true,
	"content-type":        true,
	"content-length":      true,
	"cookie":              true,
	"accept":              true,
	"accept-encoding":     true,
	"accept-language":     true,
	"connection":          true,
	"cache-control":       true,
	"pragma":              true,
	"upgrade":             true,
	"te":                  true,
	"sec-fetch-dest":      true,
	"sec-fetch-mode":      true,
	"sec-fetch-site":      true,
	"sec-fetch-user":      true,
	"sec-ch-ua":           true,
	"sec-ch-ua-mobile":    true,
	"sec-ch-ua-platform":  true,
	"authorization":       true,
	"proxy-authorization": true,
	"if-modified-since":   true,
	"if-none-match":       true,
	"if-match":            true,
	"if-unmodified-since": true,
	"if-range":            true,
	"range":               true,
	"expect":              true,
	"dnt":                 true,
}

func (m *mcpServer) addReflectionTools() {
	m.server.AddTool(m.findReflectedTool(), m.handleFindReflected)
}

func (m *mcpServer) findReflectedTool() mcp.Tool {
	return mcp.NewTool("find_reflected",
		mcp.WithDescription(`Detect request parameter values reflected in the response.

Extracts parameters from the request (query string, form body, JSON body, multipart, cookies, headers) and searches the response for each value across multiple encoding variants. Compressed payloads are decompressed before extraction and searching.

Returns only parameters with at least one reflection. Skips values shorter than 4 characters.

Locations indicate where: body:<context> (html_text, html_attribute, url, script, css, html_comment, json) or header:<name>. The raw_reflected flag signals special characters appeared unencoded (no sanitization).`),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow ID (from proxy_poll, replay_send, or crawl_poll)")),
	)
}

func (m *mcpServer) handleFindReflected(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	flowID := req.GetString("flow_id", "")
	if flowID == "" {
		return errorResult("flow_id is required"), nil
	}

	flow, errResult := m.resolveFlow(ctx, flowID)
	if errResult != nil {
		return errResult, nil
	}

	params := extractParams(flow.RawRequest)
	reflections := findReflections(params, flow.RawResponse)

	log.Printf("reflected: flow=%s %d reflections from %d params", flowID, len(reflections), len(params))
	return jsonResult(&protocol.FindReflectedResponse{
		Reflections: reflections,
	})
}

func leafToString(val interface{}) string {
	switch v := val.(type) {
	case string:
		return v
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		return ""
	}
}

// extractParams extracts all parameters from a raw HTTP request.
func extractParams(rawReq []byte) []protocol.Reflection {
	var params []protocol.Reflection
	reqHeaders, reqBody := splitHeadersBody(rawReq)
	headerStr := string(reqHeaders)
	headerMap := parseHeadersToMap(headerStr)

	// Extract request URI from the first line (e.g. "GET /path?q=1 HTTP/1.1")
	var fullPath string
	if firstLine, _, _ := strings.Cut(headerStr, "\r\n"); firstLine != "" {
		if parts := strings.SplitN(firstLine, " ", 3); len(parts) >= 2 {
			fullPath = parts[1]
		}
	}

	// Query string
	if idx := strings.Index(fullPath, "?"); idx >= 0 {
		values, _ := url.ParseQuery(fullPath[idx+1:])
		for name, vals := range values {
			for _, v := range vals {
				params = append(params, protocol.Reflection{Name: name, Source: "query", Value: v})
			}
		}
	}

	// Body params based on content type
	if len(reqBody) > 0 {
		body, _ := decompressForDisplay(reqBody, headerStr)
		var contentType string
		if ct := headerMap["Content-Type"]; len(ct) > 0 {
			contentType = ct[0]
		}
		mediaType, mediaParams, _ := mime.ParseMediaType(contentType)

		switch {
		case mediaType == "application/x-www-form-urlencoded":
			values, _ := url.ParseQuery(string(body))
			for name, vals := range values {
				for _, v := range vals {
					params = append(params, protocol.Reflection{Name: name, Source: "body", Value: v})
				}
			}

		case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
			var data interface{}
			if err := json.Unmarshal(body, &data); err == nil {
				for path, val := range flattenJSON("", data) {
					if path == "" {
						continue // root scalar
					}
					str := leafToString(val)
					if str == "" {
						continue
					}
					params = append(params, protocol.Reflection{Name: path, Source: "json", Value: str})
				}
			}

		case mediaType == "multipart/form-data":
			if boundary := mediaParams["boundary"]; boundary != "" {
				reader := multipart.NewReader(bytes.NewReader(body), boundary)
				for {
					part, err := reader.NextPart()
					if err != nil {
						break
					}
					name := part.FormName()
					if name == "" || part.FileName() != "" {
						continue
					}
					val, err := io.ReadAll(part)
					if err != nil {
						continue
					}
					params = append(params, protocol.Reflection{Name: name, Source: "body", Value: string(val)})
				}
			}
		}
	}

	// Cookie values (iterates all Cookie headers; H2 may split across multiple)
	for _, cookieHeader := range headerMap["Cookie"] {
		for _, pair := range strings.Split(cookieHeader, ";") {
			if name, value, ok := strings.Cut(strings.TrimSpace(pair), "="); ok {
				params = append(params, protocol.Reflection{
					Name:   strings.TrimSpace(name),
					Source: "cookie",
					Value:  strings.TrimSpace(value),
				})
			}
		}
	}

	for name, vals := range headerMap {
		if skipReflectionHeader[strings.ToLower(name)] {
			continue
		}
		for _, v := range vals {
			params = append(params, protocol.Reflection{Name: name, Source: "header", Value: v})
		}
	}

	return params
}

// encodedVariant pairs an encoded string with its encoding label.
type encodedVariant struct {
	encoded  string
	encoding string
}

// encodingVariants generates encoded forms of a value for reflection matching.
func encodingVariants(value string) []encodedVariant {
	seen := map[string]bool{value: true}
	variants := []encodedVariant{{encoded: value, encoding: "raw"}}
	add := func(encoded, encoding string) {
		if !seen[encoded] {
			seen[encoded] = true
			variants = append(variants, encodedVariant{encoded: encoded, encoding: encoding})
		}
	}

	add(url.QueryEscape(value), "url_query")
	add(url.PathEscape(value), "url_path")
	add(html.EscapeString(value), "html_entity")

	if !strings.ContainsAny(value, `<>&'"/`) {
		return variants
	}

	type labeledEncoder struct {
		label string
		fn    func(rune) string
	}
	encoders := []labeledEncoder{
		{"js_unicode", func(r rune) string { return fmt.Sprintf("\\u%04x", r) }},
		{"js_unicode", func(r rune) string { return fmt.Sprintf("\\u%04X", r) }},
		{"js_hex", func(r rune) string { return fmt.Sprintf("\\x%02x", r) }},
		{"js_hex", func(r rune) string { return fmt.Sprintf("\\x%02X", r) }},
		{"html_decimal", func(r rune) string { return fmt.Sprintf("&#%d;", r) }},
		{"html_hex", func(r rune) string { return fmt.Sprintf("&#x%x;", r) }},
		{"html_hex", func(r rune) string { return fmt.Sprintf("&#x%X;", r) }},
	}

	for _, enc := range encoders {
		var b strings.Builder
		for _, r := range value {
			switch r {
			case '<', '>', '&', '\'', '"', '/':
				b.WriteString(enc.fn(r))
			default:
				b.WriteRune(r)
			}
		}
		add(b.String(), enc.label)
	}

	return variants
}

// findReflections checks each parameter value against the response body and headers.
func findReflections(params []protocol.Reflection, rawResp []byte) []protocol.Reflection {
	respHeaders, respBody := splitHeadersBody(rawResp)
	respBody, _ = decompressForDisplay(respBody, string(respHeaders))
	respBodyStr := string(respBody)
	respHeaderMap := parseHeadersToMap(string(respHeaders))

	// Content-Type-based default context for non-HTML responses
	baseContext := inferBaseContext(respHeaderMap)

	reflections := []protocol.Reflection{}
	for _, p := range params {
		if len(p.Value) < minReflectionValueLen {
			continue
		}

		variants := encodingVariants(p.Value)

		var locations []string
		var rawBodyMatch bool // at least one raw (unencoded) body match

		seen := make(map[string]bool)
		for _, v := range variants {
			idx := strings.Index(respBodyStr, v.encoded)
			if idx >= 0 {
				ctx := baseContext
				if ctx == "" {
					ctx = classifyReflectionContext(respBodyStr, idx)
				}
				loc := "body:" + ctx
				if !seen[loc] {
					seen[loc] = true
					locations = append(locations, loc)
				}
				if v.encoding == "raw" {
					rawBodyMatch = true
				}
			}
		}

		for headerName, headerVals := range respHeaderMap {
			for _, hv := range headerVals {
				if slices.ContainsFunc(variants, func(v encodedVariant) bool { return strings.Contains(hv, v.encoded) }) {
					locations = append(locations, "header:"+headerName)
					break
				}
			}
		}

		if len(locations) > 0 {
			sort.Strings(locations)
			p.Locations = locations
			p.RawReflected = rawBodyMatch && strings.ContainsAny(p.Value, `<>&'"`)
			reflections = append(reflections, p)
		}
	}

	sort.Slice(reflections, func(i, j int) bool {
		if reflections[i].Source != reflections[j].Source {
			return reflections[i].Source < reflections[j].Source
		}
		return reflections[i].Name < reflections[j].Name
	})

	return reflections
}

// inferBaseContext determines the default context from the response Content-Type.
// Returns empty string for HTML (requiring structural analysis) or unknown types.
func inferBaseContext(respHeaderMap map[string][]string) string {
	ct := ""
	if vals := respHeaderMap["Content-Type"]; len(vals) > 0 {
		ct = vals[0]
	}
	if ct == "" {
		return ""
	}
	mediaType, _, _ := mime.ParseMediaType(ct)
	switch {
	case mediaType == "application/javascript" || mediaType == "text/javascript" ||
		mediaType == "application/x-javascript":
		return "script"
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		return "json"
	case mediaType == "text/css":
		return "css"
	default:
		return ""
	}
}

// classifyReflectionContext determines the HTML/JS/CSS context at a match position.
func classifyReflectionContext(body string, matchStart int) string {
	before := body[:matchStart]

	// Check for HTML comment context
	commentOpen := strings.LastIndex(before, "<!--")
	if commentOpen >= 0 {
		commentClose := strings.LastIndex(before[commentOpen:], "-->")
		if commentClose < 0 {
			return "html_comment"
		}
	}

	// Check for <script> context
	scriptOpen := strings.LastIndex(strings.ToLower(before), "<script")
	if scriptOpen >= 0 {
		scriptClose := strings.LastIndex(strings.ToLower(before[scriptOpen:]), "</script")
		if scriptClose < 0 {
			return "script"
		}
	}

	// Check for <style> context
	styleOpen := strings.LastIndex(strings.ToLower(before), "<style")
	if styleOpen >= 0 {
		styleClose := strings.LastIndex(strings.ToLower(before[styleOpen:]), "</style")
		if styleClose < 0 {
			return "css"
		}
	}

	// Check if inside a tag (< more recent than >)
	lastLT := strings.LastIndex(before, "<")
	lastGT := strings.LastIndex(before, ">")
	if lastLT >= 0 && lastLT > lastGT {
		// Inside a tag — check for URL attributes
		tagContent := strings.ToLower(before[lastLT:])
		for _, attr := range []string{"href=", "src=", "action=", "formaction="} {
			if strings.Contains(tagContent, attr) {
				return "url"
			}
		}
		return "html_attribute"
	}

	// Check for JSON-like context
	lastBrace := strings.LastIndex(before, "{")
	if lastBrace >= 0 {
		segment := before[lastBrace:]
		if strings.Contains(segment, ":") && !strings.Contains(segment, "}") {
			return "json"
		}
	}

	return "html_text"
}

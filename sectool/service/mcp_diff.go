package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net/url"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/go-analyze/bulk"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/pmezard/go-difflib/difflib"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

const (
	defaultMaxDiffLinesText = 50
	defaultMaxDiffLinesJSON = 20
)

func (m *mcpServer) diffFlowTool() mcp.Tool {
	return mcp.NewTool("diff_flow",
		mcp.WithDescription(`Compare two captured flows, surfacing exactly what differs in requests and responses.

Scope controls what is compared:
- "request" — method, path, query, request headers, request body
- "response" — status, response headers, response body
- "request_headers" — method, path, query, request headers only (no body diff)
- "response_headers" — status, response headers only (no body diff)
- "request_body" — request body only
- "response_body" — response body only

Flows can come from any source (proxy, replay, crawl) and can be mixed.
Sections where everything is identical are omitted. Returns {"same": true} when scoped sections are entirely identical.`),
		mcp.WithString("flow_a", mcp.Required(), mcp.Description("Flow ID (from proxy_poll, replay_send, or crawl_poll)")),
		mcp.WithString("flow_b", mcp.Required(), mcp.Description("Flow ID (from any source)")),
		mcp.WithString("scope", mcp.Required(),
			mcp.Enum("request", "response", "request_headers", "response_headers", "request_body", "response_body"),
			mcp.Description("What to compare")),
		mcp.WithNumber("max_diff_lines", mcp.Description("Cap body diff output (default: 50 for text, 20 for JSON paths)")),
	)
}

func (m *mcpServer) handleDiffFlow(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if err := m.requireWorkflow(); err != nil {
		return err, nil
	}

	flowAID := req.GetString("flow_a", "")
	flowBID := req.GetString("flow_b", "")
	scope := req.GetString("scope", "")

	if flowAID == "" {
		return errorResult("flow_a is required"), nil
	} else if flowBID == "" {
		return errorResult("flow_b is required"), nil
	} else if scope == "" {
		return errorResult("scope is required"), nil
	}

	maxDiffLines := req.GetInt("max_diff_lines", 0)

	flowA, errResult := m.resolveFlow(ctx, flowAID)
	if errResult != nil {
		return errResult, nil
	}
	flowB, errResult := m.resolveFlow(ctx, flowBID)
	if errResult != nil {
		return errResult, nil
	}

	log.Printf("mcp/diff_flow: comparing %s vs %s scope=%s", flowAID, flowBID, scope)

	resp := &protocol.DiffFlowResponse{}

	includeReqHeaders := scope == "request" || scope == "request_headers"
	includeReqBody := scope == "request" || scope == "request_body"
	includeRespHeaders := scope == "response" || scope == "response_headers"
	includeRespBody := scope == "response" || scope == "response_body"

	reqHeadersA, reqBodyA := splitHeadersBody(flowA.RawRequest)
	reqHeadersB, reqBodyB := splitHeadersBody(flowB.RawRequest)
	respHeadersA, respBodyA := splitHeadersBody(flowA.RawResponse)
	respHeadersB, respBodyB := splitHeadersBody(flowB.RawResponse)

	// Decompress bodies before diffing
	if includeReqBody {
		reqBodyA, _ = decompressForDisplay(reqBodyA, string(reqHeadersA))
		reqBodyB, _ = decompressForDisplay(reqBodyB, string(reqHeadersB))
	}
	if includeRespBody {
		respBodyA, _ = decompressForDisplay(respBodyA, string(respHeadersA))
		respBodyB, _ = decompressForDisplay(respBodyB, string(respHeadersB))
	}

	if includeReqHeaders || includeReqBody {
		reqDiff := diffRequest(reqHeadersA, reqHeadersB, reqBodyA, reqBodyB,
			includeReqHeaders, includeReqBody, maxDiffLines)
		if reqDiff != nil {
			resp.Request = reqDiff
		}
	}

	if includeRespHeaders || includeRespBody {
		respDiff := diffResponse(respHeadersA, respHeadersB, respBodyA, respBodyB,
			includeRespHeaders, includeRespBody, maxDiffLines)
		if respDiff != nil {
			resp.Response = respDiff
		}
	}

	if resp.Request == nil && resp.Response == nil {
		resp.Same = true
	}

	return jsonResult(resp)
}

// diffRequest compares request components and returns nil if identical.
func diffRequest(headersA, headersB, bodyA, bodyB []byte, includeHeaders, includeBody bool, maxLines int) *protocol.RequestDiff {
	var diff protocol.RequestDiff
	var hasDiff bool

	if includeHeaders {
		methodA, _, pathA := extractRequestMeta(string(headersA))
		methodB, _, pathB := extractRequestMeta(string(headersB))

		if methodA != methodB {
			diff.Method = &protocol.ABPair{A: methodA, B: methodB}
			hasDiff = true
		}

		pathOnlyA, queryA := splitPathQuery(pathA)
		pathOnlyB, queryB := splitPathQuery(pathB)

		if pathOnlyA != pathOnlyB {
			diff.Path = &protocol.ABPair{A: pathOnlyA, B: pathOnlyB}
			hasDiff = true
		}

		if queryDiff := diffQueryStrings(queryA, queryB); queryDiff != nil {
			diff.Query = queryDiff
			hasDiff = true
		}

		headerDiff := diffNameValues(parseHeadersToMap(string(headersA)), parseHeadersToMap(string(headersB)))
		if headerDiff != nil {
			diff.Headers = headerDiff
			hasDiff = true
		}
	}

	if includeBody {
		ct := detectContentType(headersA, headersB)
		if bodyDiff := diffBodies(bodyA, bodyB, ct, maxLines); bodyDiff != nil {
			diff.Body = bodyDiff
			hasDiff = true
		}
	}

	if !hasDiff {
		return nil
	}
	return &diff
}

// diffResponse compares response components and returns nil if identical.
func diffResponse(headersA, headersB, bodyA, bodyB []byte, includeHeaders, includeBody bool, maxLines int) *protocol.ResponseDiff {
	var diff protocol.ResponseDiff
	var hasDiff bool

	if includeHeaders {
		statusA, _ := parseResponseStatus(headersA)
		statusB, _ := parseResponseStatus(headersB)

		if statusA != statusB {
			diff.Status = &protocol.ABIntPair{A: statusA, B: statusB}
			hasDiff = true
		}

		headerDiff := diffNameValues(parseHeadersToMap(string(headersA)), parseHeadersToMap(string(headersB)))
		if headerDiff != nil {
			diff.Headers = headerDiff
			hasDiff = true
		}
	}

	if includeBody {
		ct := detectContentType(headersA, headersB)
		if bodyDiff := diffBodies(bodyA, bodyB, ct, maxLines); bodyDiff != nil {
			diff.Body = bodyDiff
			hasDiff = true
		}
	}

	if !hasDiff {
		return nil
	}
	return &diff
}

// splitPathQuery splits "/path?query" into path and query parts.
func splitPathQuery(fullPath string) (path, query string) {
	if idx := strings.Index(fullPath, "?"); idx >= 0 {
		return fullPath[:idx], fullPath[idx+1:]
	}
	return fullPath, ""
}

// diffQueryStrings compares two query strings and returns nil if identical.
func diffQueryStrings(qsA, qsB string) *protocol.ParamsDiff {
	if qsA == qsB {
		return nil
	}

	valuesA, _ := url.ParseQuery(qsA)
	valuesB, _ := url.ParseQuery(qsB)
	return diffNameValues(valuesA, valuesB)
}

// diffNameValues compares two sets of name-value pairs (headers or query params).
// Returns nil if identical.
func diffNameValues(a, b map[string][]string) *protocol.ParamsDiff {
	var added, removed []protocol.NameValue
	var changed []protocol.NameABChange
	var unchangedCount int

	// Collect and sort all keys (deterministic output)
	keyMap := maps.Clone(a)
	maps.Copy(keyMap, b)
	allKeys := bulk.MapKeysSlice(keyMap)
	sort.Strings(allKeys)

	for _, key := range allKeys {
		valA := a[key]
		valB := b[key]

		if len(valA) == 0 && len(valB) > 0 {
			added = append(added, protocol.NameValue{Name: key, Value: strings.Join(valB, ", ")})
		} else if len(valA) > 0 && len(valB) == 0 {
			removed = append(removed, protocol.NameValue{Name: key, Value: strings.Join(valA, ", ")})
		} else if !slices.Equal(valA, valB) {
			changed = append(changed, protocol.NameABChange{Name: key, A: strings.Join(valA, ", "), B: strings.Join(valB, ", ")})
		} else {
			unchangedCount++
		}
	}

	if len(added) == 0 && len(removed) == 0 && len(changed) == 0 {
		return nil
	}

	return &protocol.ParamsDiff{
		Added:          added,
		Removed:        removed,
		Changed:        changed,
		UnchangedCount: unchangedCount,
	}
}

// detectContentType returns the Content-Type from the first header set that has one,
// preferring flow A. Used to decide body diff strategy.
func detectContentType(headersA, headersB []byte) string {
	ct := extractHeader(string(headersA), "Content-Type")
	if ct == "" {
		return extractHeader(string(headersB), "Content-Type")
	}
	return ct
}

// diffBodies compares two bodies using content-type-aware diffing.
// Returns nil if bodies are identical.
func diffBodies(bodyA, bodyB []byte, contentType string, maxLines int) *protocol.BodyDiff {
	if bytes.Equal(bodyA, bodyB) {
		return nil
	}

	if isDiffJSONContentType(contentType) {
		return diffJSONBodies(bodyA, bodyB, maxLines)
	}
	// Heuristic: try JSON diff when both bodies look like JSON regardless of Content-Type.
	// Safe because diffJSONBodies falls back to text diff on parse failure.
	if looksLikeJSON(bodyA) && looksLikeJSON(bodyB) {
		return diffJSONBodies(bodyA, bodyB, maxLines)
	} else if isDiffTextContentType(contentType) || (utf8.Valid(bodyA) && utf8.Valid(bodyB)) {
		return diffTextBodies(bodyA, bodyB, maxLines)
	}
	return diffBinaryBodies(bodyA, bodyB)
}

// looksLikeJSON returns true if the first non-whitespace byte is { or [.
func looksLikeJSON(data []byte) bool {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

func isDiffJSONContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "application/json") || strings.HasSuffix(strings.Split(ct, ";")[0], "+json")
}

func isDiffTextContentType(ct string) bool {
	ct = strings.ToLower(ct)
	if strings.HasPrefix(ct, "text/") {
		return true
	}
	textTypes := []string{
		"application/xml",
		"application/x-www-form-urlencoded",
		"application/javascript",
		"application/ecmascript",
	}
	for _, t := range textTypes {
		if strings.Contains(ct, t) {
			return true
		}
	}
	return strings.HasSuffix(strings.Split(ct, ";")[0], "+xml")
}

// diffJSONBodies performs a structural JSON diff.
func diffJSONBodies(bodyA, bodyB []byte, maxLines int) *protocol.BodyDiff {
	var dataA, dataB interface{}
	errA := json.Unmarshal(bodyA, &dataA)
	errB := json.Unmarshal(bodyB, &dataB)

	// If either fails to parse as JSON, fall back to text diff
	if errA != nil || errB != nil {
		return diffTextBodies(bodyA, bodyB, maxLines)
	}

	pathsA := flattenJSON("", dataA)
	pathsB := flattenJSON("", dataB)

	maxPaths := maxLines
	if maxPaths <= 0 {
		maxPaths = defaultMaxDiffLinesJSON
	}

	var added []protocol.PathValue
	var removed []protocol.PathEntry
	var changed []protocol.PathABChange
	var unchangedCount int

	// Collect and sort all paths
	keyMap := maps.Clone(pathsA)
	maps.Copy(keyMap, pathsB)
	allPaths := bulk.MapKeysSlice(keyMap)
	sort.Strings(allPaths)

	var totalDiffs int
	var truncated bool
	for _, p := range allPaths {
		valA, inA := pathsA[p]
		valB, inB := pathsB[p]

		if !inA && inB {
			totalDiffs++
			if totalDiffs <= maxPaths {
				added = append(added, protocol.PathValue{Path: p, Value: valB})
			} else {
				truncated = true
			}
		} else if inA && !inB {
			totalDiffs++
			if totalDiffs <= maxPaths {
				removed = append(removed, protocol.PathEntry{Path: p})
			} else {
				truncated = true
			}
		} else if !jsonValuesEqual(valA, valB) {
			totalDiffs++
			if totalDiffs <= maxPaths {
				changed = append(changed, protocol.PathABChange{Path: p, A: valA, B: valB})
			} else {
				truncated = true
			}
		} else {
			unchangedCount++
		}
	}

	return &protocol.BodyDiff{
		Format:         "json",
		Added:          added,
		Removed:        removed,
		Changed:        changed,
		UnchangedCount: unchangedCount,
		Truncated:      truncated,
	}
}

// jsonValuesEqual compares two JSON leaf values.
func jsonValuesEqual(a, b interface{}) bool {
	if a == nil && b == nil {
		return true
	} else if a == nil || b == nil {
		return false
	}

	// Marshal and compare for type-safe comparison
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
	}
	return bytes.Equal(ja, jb)
}

// diffTextBodies performs a unified text diff.
func diffTextBodies(bodyA, bodyB []byte, maxLines int) *protocol.BodyDiff {
	if maxLines <= 0 {
		maxLines = defaultMaxDiffLinesText
	}

	diff := difflib.UnifiedDiff{
		A:        splitLines(string(bodyA)),
		B:        splitLines(string(bodyB)),
		FromFile: "a",
		ToFile:   "b",
		Context:  3,
	}

	text, err := difflib.GetUnifiedDiffString(diff)
	if err != nil {
		text = fmt.Sprintf("(diff error: %v)", err)
	}

	// Count additions and removals
	var addCount, removeCount int
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			addCount++
		} else if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
			removeCount++
		}
	}

	// Truncate diff output
	var truncated bool
	diffLines := strings.Split(text, "\n")
	if len(diffLines) > maxLines {
		diffLines = diffLines[:maxLines]
		text = strings.Join(diffLines, "\n")
		truncated = true
	}

	return &protocol.BodyDiff{
		Format:    "text",
		ASize:     len(bodyA),
		BSize:     len(bodyB),
		Diff:      text,
		Summary:   fmt.Sprintf("%d lines added, %d removed", addCount, removeCount),
		Truncated: truncated,
	}
}

// diffBinaryBodies returns size metadata for non-text body differences.
func diffBinaryBodies(bodyA, bodyB []byte) *protocol.BodyDiff {
	same := bytes.Equal(bodyA, bodyB)
	return &protocol.BodyDiff{
		Format: "binary",
		Same:   &same,
		ASize:  len(bodyA),
		BSize:  len(bodyB),
	}
}

// splitLines splits text into lines for difflib (preserving trailing newline behavior).
func splitLines(s string) []string {
	lines := strings.SplitAfter(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

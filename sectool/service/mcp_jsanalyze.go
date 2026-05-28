package service

import (
	"bytes"
	"context"
	"log"
	"mime"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/js"
)

// jsPrefixes lists leading byte sequences that mark an unlabeled body as JavaScript.
var jsPrefixes = [][]byte{
	[]byte("function"),
	[]byte("var "),
	[]byte("let "),
	[]byte("const "),
	[]byte("import "),
	[]byte("export "),
	[]byte("class "),
	[]byte("(function"),
	[]byte("!function"),
	[]byte("/*"),
	[]byte("//"),
}

func (m *mcpServer) addJSAnalyzeTools() {
	m.server.AddTool(m.jsAnalyzeTool(), m.handleJSAnalyze)
}

func (m *mcpServer) jsAnalyzeTool() mcp.Tool {
	return mcp.NewTool("js_analyze",
		mcp.WithDescription(`Extract the API surface from a JavaScript or HTML response flow.

Returns a deduplicated map of:
- endpoints: every URL referenced by the JS. "literal" entries are URL-shaped string literals found outside any known sink; everything else is a concrete call site or constructor argument.
- routes: client-side framework routes.
- secrets: high-precision credential matches.
- external_scripts: <script src=...> URLs from HTML responses.
- source_maps: sourceMappingURL hints from the body.

For HTML responses, inline <script> blocks are parsed independently. Each endpoint includes a "last_flow" field (when present) pointing to the most recent matching proxy flow_id.`),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow ID (from proxy_poll, replay_send, or crawl_poll)")),
	)
}

func (m *mcpServer) handleJSAnalyze(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

	respHeaders, respBody := splitHeadersBody(flow.RawResponse)
	headerStr := string(respHeaders)
	body, _ := decompressForDisplay(respBody, headerStr)

	contentType := extractHeader(headerStr, "Content-Type")
	mediaType, _, _ := mime.ParseMediaType(contentType)
	mediaType = strings.ToLower(mediaType)

	var result js.Result
	switch {
	case isHTMLMediaType(mediaType):
		result = js.AnalyzeHTML(body)
	case isJSMediaType(mediaType), mediaType == "" && looksLikeJS(body):
		result = js.AnalyzeJS(body)
	default:
		return errorResult("flow response is not JavaScript or HTML (Content-Type: " + contentType + ")"), nil
	}

	_, bundleHost, _ := extractRequestMeta(string(flow.DisplayRequest()))
	annotateLastFlow(ctx, m, &result, bundleHost)

	resp := &protocol.JSAnalyzeResponse{
		Source: result.Source,
		Stats: protocol.JSAnalyzeStats{
			InputBytes:   len(body),
			ScriptBlocks: result.ScriptBlocks,
			ParseErrors:  result.ParseErrors,
		},
		Endpoints:       result.Endpoints,
		Routes:          result.Routes,
		Secrets:         result.Secrets,
		ExternalScripts: result.ExternalScripts,
		SourceMaps:      result.SourceMaps,
		Warnings:        result.Warnings,
	}

	log.Printf("js_analyze: flow=%s source=%s endpoints=%d routes=%d secrets=%d parse_errors=%d",
		flowID, resp.Source,
		len(resp.Endpoints), len(resp.Routes), len(resp.Secrets), resp.Stats.ParseErrors)
	return jsonResult(resp)
}

// isHTMLMediaType reports whether the media type denotes an HTML response.
func isHTMLMediaType(mt string) bool {
	return mt == "text/html" || mt == "application/xhtml+xml"
}

// isJSMediaType reports whether the media type denotes a JavaScript response.
func isJSMediaType(mt string) bool {
	switch mt {
	case "application/javascript", "text/javascript", "application/x-javascript",
		"application/ecmascript", "text/ecmascript":
		return true
	}
	return false
}

// looksLikeJS sniffs the start of a body for JS-like content. Used when the
// content-type is absent (some bundlers and CDNs omit it).
func looksLikeJS(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] == '<' {
		return false
	}
	for _, prefix := range jsPrefixes {
		if bytes.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

// annotateLastFlow sets LastFlow on each endpoint to the most recent matching proxy flow_id.
// bundleHost is the implicit origin for path-relative URLs.
// History retrieval errors are non-fatal; endpoints are returned without annotations.
func annotateLastFlow(ctx context.Context, m *mcpServer, r *js.Result, bundleHost string) {
	if len(r.Endpoints) == 0 {
		return
	}
	entries, err := drainProxyHistory(ctx, m.service.httpBackend, false)
	if err != nil || len(entries) == 0 {
		return
	}
	idx := buildLastFlowIndex(entries)
	for i := range r.Endpoints {
		if id := idx.lookup(r.Endpoints[i].URL, bundleHost); id != "" {
			r.Endpoints[i].LastFlow = id
		}
	}
}

// lastFlowIndex maps (host, path) to the most recent flow_id.
// Path-only layers allow query-less literals to match history with queries.
// blind* maps are host-blind fallbacks for when neither host is known.
type lastFlowIndex struct {
	byHost         map[string]map[string]string
	byHostPathOnly map[string]map[string]string
	blindPath      map[string]string
	blindPathOnly  map[string]string
}

func buildLastFlowIndex(entries []flowEntry) *lastFlowIndex {
	idx := &lastFlowIndex{
		byHost:         make(map[string]map[string]string),
		byHostPathOnly: make(map[string]map[string]string),
		blindPath:      make(map[string]string, len(entries)),
		blindPathOnly:  make(map[string]string, len(entries)),
	}
	for _, e := range entries {
		if e.path == "" {
			continue
		}
		pathOnly := js.StripQuery(e.path)
		if e.host != "" {
			if idx.byHost[e.host] == nil {
				idx.byHost[e.host] = make(map[string]string)
				idx.byHostPathOnly[e.host] = make(map[string]string)
			}
			idx.byHost[e.host][e.path] = e.flowID
			idx.byHostPathOnly[e.host][pathOnly] = e.flowID
		}
		idx.blindPath[e.path] = e.flowID
		idx.blindPathOnly[pathOnly] = e.flowID
	}
	return idx
}

func (idx *lastFlowIndex) lookup(rawURL, bundleHost string) string {
	host, path := js.ClassifyURL(rawURL)
	if path == "" {
		return ""
	}
	if host == "" {
		host = bundleHost
	}
	if host != "" {
		if id, ok := idx.byHost[host][path]; ok {
			return id
		}
		if id, ok := idx.byHostPathOnly[host][js.StripQuery(path)]; ok {
			return id
		}
		return ""
	}
	// bundle host unknown AND URL is path-relative: last-resort host-blind lookup
	if id, ok := idx.blindPath[path]; ok {
		return id
	}
	if id, ok := idx.blindPathOnly[js.StripQuery(path)]; ok {
		return id
	}
	return ""
}

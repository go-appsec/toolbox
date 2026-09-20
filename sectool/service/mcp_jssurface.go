package service

import (
	"bytes"
	"context"
	"log"
	"mime"
	"net/url"
	"slices"
	"strings"

	"github.com/go-analyze/bulk"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/js"
)

const (
	originSameOrigin = "same-origin"
	originSummary    = "summary"
	originFull       = "full"
	sameOriginLabel  = "(same-origin)" // summary key for relative paths when host is unknown
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
	m.server.AddTool(m.jsAnalyzeTool(), m.requireWorkflow(m.handleJSAnalyze))
}

func (m *mcpServer) jsAnalyzeTool() mcp.Tool {
	return mcp.NewTool("js_surface",
		mcp.WithDescription(`Extract the API surface from a JavaScript or HTML response flow.

Returns a deduplicated map of:
- endpoints: every URL/path referenced by the JS. "literal" entries are not tied to a recognized sink (lower confidence); everything else (fetch/axios/xhr/websocket/request) is a concrete call site or constructor argument with a method when determinable. Static-asset references (.js/.css/.map/fonts) are dropped by default; set include_assets=true to include them.
- routes: client-side framework routes.
- secrets: high-precision credential matches.
- script_src: every <script src=...> URL from HTML responses.
- source_maps: sourceMappingURL hints from the body.

For HTML responses, inline <script> blocks are parsed independently. When present an included "last_flow" field provides the most recent matching proxy flow_id.

An endpoint with an "endpoint_id" field carries extractable request-shape detail (body fields, headers, or path-parameter names): expand it with js_endpoint using "<flow_id>.<endpoint_id>" to get everything needed to craft a request without an example flow.

Endpoint scope and focus are configurable to same-origin and by host set via the "origin" parameter.`),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow ID (from proxy_poll, replay_send, or crawl_poll)")),
		mcp.WithString("origin", mcp.Description(`Endpoint scope: "same-origin" (default) same-origin only; "summary" per-host counts to guide follow-up calls; "full" all endpoints same and external; or a comma-separated host set (e.g. "a.com,b.com") for full detail on the named host(s)`)),
		mcp.WithBoolean("include_assets", mcp.Description("Include static-asset references that are dropped by default")),
	)
}

func (m *mcpServer) handleJSAnalyze(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	flowID := req.GetString("flow_id", "")
	if flowID == "" {
		return errorResult("flow_id is required"), nil
	}

	body, headerStr, isHTML, flow, errResult := m.decodeJSFlowBody(ctx, flowID)
	if errResult != nil {
		return errResult, nil
	}

	var result js.Result
	if isHTML {
		result = js.AnalyzeHTML(body)
	} else {
		result = js.AnalyzeJS(body)
	}

	_, bundleHost, bundlePath := extractRequestMeta(string(flow.DisplayRequest()))
	annotateLastFlow(ctx, m, &result, bundleHost, bundleBaseURL(bundleHost, bundlePath))

	eps := result.Endpoints
	if !req.GetBool("include_assets", false) {
		// Drop static-asset references (vite/webpack chunk manifests, etc.), noise in the API surface
		eps = bulk.SliceFilter(func(e protocol.ExtractedEndpoint) bool { return !js.IsAsset(e.URL) }, eps)
	}

	mode := req.GetString("origin", originSameOrigin)
	sameOrigin := sameOriginHosts(bundleHost, headerStr)
	endpoints, summary := applyOrigin(eps, sameOrigin, bundleHost, mode)

	stats := protocol.JSAnalyzeStats{InputBytes: len(body)}
	if result.Source != js.SourceJavaScript {
		// script_blocks counts <script> elements; for pure JS it is always 1
		stats.ScriptBlocks = result.ScriptBlocks
	}

	resp := &protocol.JSAnalyzeResponse{
		Source:        result.Source,
		Stats:         stats,
		Endpoints:     endpoints,
		Routes:        result.Routes,
		Secrets:       result.Secrets,
		ScriptSrc:     result.ScriptSrc,
		SourceMaps:    result.SourceMaps,
		OriginSummary: summary,
	}

	log.Printf("js_surface: flow=%s source=%s origin=%s endpoints=%d routes=%d secrets=%d parse_errors=%d",
		flowID, resp.Source, mode,
		len(result.Endpoints), len(resp.Routes), len(resp.Secrets), result.ParseErrors)
	return jsonResult(resp)
}

// decodeJSFlowBody resolves a flow and returns its decompressed response body and whether it
// is HTML (otherwise JavaScript). errResult is non-nil when the flow can't be resolved or is
// neither JavaScript nor HTML; callers should return it to the agent unchanged.
func (m *mcpServer) decodeJSFlowBody(ctx context.Context, flowID string) (body []byte, headerStr string, isHTML bool, flow *resolvedFlow, errResult *mcp.CallToolResult) {
	flow, errResult = m.resolveFlow(ctx, flowID)
	if errResult != nil {
		return nil, "", false, nil, errResult
	}

	respHeaders, respBody := splitHeadersBody(flow.RawResponse)
	headerStr = string(respHeaders)
	body, _ = decompressForDisplay(respBody, headerStr)

	contentType := extractHeader(headerStr, "Content-Type")
	mediaType, _, _ := mime.ParseMediaType(contentType)
	mediaType = strings.ToLower(mediaType)

	switch {
	case isHTMLMediaType(mediaType):
		return body, headerStr, true, flow, nil
	case isJSMediaType(mediaType), mediaType == "" && looksLikeJS(body):
		return body, headerStr, false, flow, nil
	default:
		return nil, "", false, flow, errorResult("flow response is not JavaScript or HTML (Content-Type: " + contentType + ")")
	}
}

// isHTMLMediaType reports whether the media type denotes an HTML response.
func isHTMLMediaType(mt string) bool {
	return mt == "text/html" || mt == "application/xhtml+xml"
}

// isJSMediaType reports whether the media type denotes a JavaScript response.
func isJSMediaType(mt string) bool {
	switch mt {
	case mimeJavaScript, mimeTextJavascript, mimeXJavaScript,
		mimeEcmaScript, mimeTextEcmaScript:
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

// bundleBaseURL builds the bundle's request URL as a base for resolving relative
// endpoint literals (e.g. "assets/User-x.js"). Returns nil when host is unknown.
func bundleBaseURL(host, path string) *url.URL {
	if host == "" {
		return nil
	}
	u, err := url.Parse("https://" + host + path)
	if err != nil {
		return nil
	}
	return u
}

// annotateLastFlow sets LastFlow on each endpoint to the most recent matching proxy flow_id.
// bundleHost is the implicit origin for path-relative URLs; base resolves document-relative literals.
// History retrieval errors are non-fatal; endpoints are returned without annotations.
func annotateLastFlow(ctx context.Context, m *mcpServer, r *js.Result, bundleHost string, base *url.URL) {
	if len(r.Endpoints) == 0 {
		return
	}
	entries, err := drainProxyHistory(ctx, m.service.httpBackend, false)
	if err != nil || len(entries) == 0 {
		return
	}
	idx := buildLastFlowIndex(entries)
	for i := range r.Endpoints {
		if id := idx.lookup(r.Endpoints[i].URL, bundleHost, base); id != "" {
			r.Endpoints[i].LastFlow = id
		}
	}
}

// lastFlowIndex maps (host, path) to the most recent flow_id. Path-only layers allow query-less
// literals to match history with queries. blind* maps are host-blind fallbacks for when neither host is known.
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
		full := normalizePathKey(e.path)
		pathOnly := normalizePathKey(js.StripQuery(e.path))
		if e.host != "" {
			if idx.byHost[e.host] == nil {
				idx.byHost[e.host] = make(map[string]string)
				idx.byHostPathOnly[e.host] = make(map[string]string)
			}
			idx.byHost[e.host][full] = e.flowID
			idx.byHostPathOnly[e.host][pathOnly] = e.flowID
		}
		idx.blindPath[full] = e.flowID
		idx.blindPathOnly[pathOnly] = e.flowID
	}
	return idx
}

// normalizePathKey canonicalizes a path for history correlation: it drops the
// #fragment and trims a trailing slash (except root) so "/x", "/x/", and "/x#a"
// collapse to one key, while preserving the query string.
func normalizePathKey(p string) string {
	if i := strings.IndexByte(p, '#'); i >= 0 {
		p = p[:i]
	}
	path, query := p, ""
	if i := strings.IndexByte(p, '?'); i >= 0 {
		path, query = p[:i], p[i:]
	}
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = path[:len(path)-1]
	}
	return path + query
}

func (idx *lastFlowIndex) lookup(rawURL, bundleHost string, base *url.URL) string {
	for _, c := range resolveCandidates(rawURL, base) {
		if id := idx.matchPath(c.host, c.path, bundleHost); id != "" {
			return id
		}
	}
	return ""
}

// matchPath looks up a single (host, path) against history: exact path (with query)
// then query-stripped, host-scoped with a host-blind fallback.
func (idx *lastFlowIndex) matchPath(host, path, bundleHost string) string {
	full := normalizePathKey(path)
	pathOnly := normalizePathKey(js.StripQuery(path))
	if host == "" {
		host = bundleHost
	}
	if host != "" {
		if id, ok := idx.byHost[host][full]; ok {
			return id
		}
		if id, ok := idx.byHostPathOnly[host][pathOnly]; ok {
			return id
		}
		return ""
	}
	if id, ok := idx.blindPath[full]; ok {
		return id
	}
	if id, ok := idx.blindPathOnly[pathOnly]; ok {
		return id
	}
	return ""
}

// pathCandidate is a (host, path) pair resolved from an endpoint URL.
type pathCandidate struct{ host, path string }

// resolveCandidates returns the (host, path) pairs to try for rawURL. Absolute and rooted URLs yield one candidate;
// a document-relative literal is resolved against the bundle base and against the base forced to a directory.
func resolveCandidates(rawURL string, base *url.URL) []pathCandidate {
	var out []pathCandidate
	add := func(host, path string) {
		if path == "" {
			return
		}
		for _, c := range out {
			if c.host == host && c.path == path {
				return
			}
		}
		out = append(out, pathCandidate{host, path})
	}

	if host, path := js.ClassifyURL(rawURL); path != "" {
		add(host, path)
		return out
	}
	if base == nil {
		return out
	}
	ref, err := url.Parse(rawURL)
	if err != nil {
		return out
	}
	host, path := js.ClassifyURL(base.ResolveReference(ref).String())
	add(host, path)
	if !strings.HasSuffix(base.Path, "/") {
		dir := *base
		dir.Path = base.Path + "/"
		host, path = js.ClassifyURL(dir.ResolveReference(ref).String())
		add(host, path)
	}
	return out
}

// sameOriginHosts returns the hosts treated as same-origin: the bundle host plus any specific hosts
// named in the response's Access-Control-Allow-Origin header (`*` and `null` are ignored).
func sameOriginHosts(bundleHost, headerStr string) map[string]struct{} {
	set := make(map[string]struct{})
	if bundleHost != "" {
		set[bundleHost] = struct{}{}
	}
	acao := extractHeader(headerStr, "Access-Control-Allow-Origin")
	for _, field := range strings.FieldsFunc(acao, func(r rune) bool { return r == ',' || r == ' ' }) {
		if field == "*" || strings.EqualFold(field, "null") {
			continue
		}

		if h := endpointHost(field); h != "" {
			set[h] = struct{}{}
		}
	}
	return set
}

// endpointHost returns the host (with port if present) of an absolute,
// protocol-relative, or ws(s) URL, or "" for a relative path.
func endpointHost(u string) string {
	if strings.HasPrefix(u, "//") {
		u = "https:" + u
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return parsed.Host
}

// applyOrigin filters or summarizes endpoints by mode. Relative paths and hosts in same are treated as same-origin.
// Returns (endpoints, nil) for filtering modes and (nil, summary) for "summary".
func applyOrigin(eps []protocol.ExtractedEndpoint, same map[string]struct{}, bundleHost, mode string) ([]protocol.ExtractedEndpoint, []protocol.OriginCount) {
	isSame := func(host string) bool {
		if host == "" {
			return true
		}
		_, ok := same[host]
		return ok
	}

	switch mode {
	case originFull:
		return eps, nil
	case originSummary:
		counts := make(map[string]int)
		flags := make(map[string]bool)
		for _, e := range eps {
			host := endpointHost(e.URL)
			key := host
			if host == "" {
				if key = bundleHost; key == "" {
					key = sameOriginLabel
				}
			}
			counts[key]++
			flags[key] = isSame(host)
		}
		summary := make([]protocol.OriginCount, 0, len(counts))
		for origin, n := range counts {
			summary = append(summary, protocol.OriginCount{Origin: origin, Count: n})
		}
		// flags drives ordering only (same-origin first); it is not serialized
		slices.SortFunc(summary, func(a, b protocol.OriginCount) int {
			if flags[a.Origin] != flags[b.Origin] {
				if flags[a.Origin] {
					return -1
				}
				return 1
			} else if a.Count != b.Count {
				return b.Count - a.Count
			}
			return strings.Compare(a.Origin, b.Origin)
		})
		return nil, summary
	case originSameOrigin, "":
		return bulk.SliceFilter(func(e protocol.ExtractedEndpoint) bool {
			return isSame(endpointHost(e.URL))
		}, eps), nil
	default:
		want := bulk.SliceToSet(strings.FieldsFunc(mode, func(r rune) bool { return r == ',' || r == ' ' }))
		return bulk.SliceFilter(func(e protocol.ExtractedEndpoint) bool {
			host := endpointHost(e.URL)
			if host == "" {
				host = bundleHost // relative paths belong to the bundle's own host
			}
			_, ok := want[host]
			return ok
		}, eps), nil
	}
}

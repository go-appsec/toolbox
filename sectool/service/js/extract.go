package js

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/tdewolff/parse/v2/js"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

// Library labels for extracted endpoints. libLiteral marks bare string literals;
// other values indicate a concrete call site or constructor argument.
const (
	libFetch       = "fetch"
	libAxios       = "axios"
	libXHR         = "xhr"
	libJQuery      = "jquery"
	libNavigation  = "navigation"
	libWebSocket   = "websocket"
	libEventSource = "eventsource"
	libBeacon      = "beacon"
	libImport      = "import"
	libLiteral     = "literal"
	libRequest     = "request"
)

var httpMethods = map[string]struct{}{
	http.MethodGet: {}, http.MethodPost: {}, http.MethodPut: {}, http.MethodDelete: {},
	http.MethodPatch: {}, http.MethodHead: {}, http.MethodOptions: {},
}

// Frameworks recognized for route extraction.
const (
	frameworkReactRouter   = "react-router"
	frameworkVueRouter     = "vue-router"
	frameworkAngularRouter = "angular-router"
)

// Global-object names treated as transparent receivers (window.fetch resolves to fetch).
const (
	globalWindow     = "window"
	globalSelf       = "self"
	globalGlobalThis = "globalThis"
	globalDocument   = "document"
	propLocation     = "location"
)

// urlPathChars is the RFC 3986 pchar set plus path/query/fragment reserved characters.
const urlPathChars = `A-Za-z0-9._~%+\-/?#&=:@!*$,;()'\[\]`

// urlLiteralRe matches absolute URLs, protocol-relative, absolute-path, and
// relative-path-with-slash literals. Bare identifiers and i18n keys are rejected.
var urlLiteralRe = regexp.MustCompile(
	`^(?:(?:https?|wss?)://[` + urlPathChars + `]+` +
		`|//[A-Za-z0-9.\-]+/[` + urlPathChars + `]*` +
		`|/[` + urlPathChars + `]*` +
		`|(?:\.{1,2}/)[` + urlPathChars + `]*` +
		`|[A-Za-z0-9._~\-][` + urlPathChars + `]*/[` + urlPathChars + `]*)$`,
)

// sourceMapRe captures the URL from a sourceMappingURL comment.
var sourceMapRe = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=(\S+)`)

// urlSegChars are the characters allowed inside a path/host segment by the raw scanner.
// ${ } are included so template placeholders survive.
const urlSegChars = `\w~%.${}\-`

// assetDropExts are static bundler-asset extensions (scripts, styles, fonts, images).
// Data formats (json/xml/html) are excluded as they may be API responses.
const assetDropExts = `js|mjs|cjs|css|map|woff2?|ttf|otf|eot|png|jpe?g|gif|svg|webp|avif|ico|wasm`

// assetExts are the file extensions that qualify a bare relative path as an asset reference rather than a MIME type or i18n key.
const assetExts = assetDropExts + `|json|html?|xml`

// assetExtRe matches a known asset extension at the end of a path (allowing a trailing query/fragment).
var assetExtRe = regexp.MustCompile(`\.(?:` + assetExts + `)(?:[?#]|$)`)

// assetDropRe matches static bundler-asset extensions (scripts, styles, fonts, images).
var assetDropRe = regexp.MustCompile(`\.(?:` + assetDropExts + `)(?:[?#]|$)`)

// IsAsset reports whether u points at a static bundler asset rather than an API endpoint.
func IsAsset(u string) bool {
	return assetDropRe.MatchString(u)
}

// urlScanRe finds URL/path candidate substrings in decoded string literals: absolute
// and protocol-relative URLs, rooted paths with >=2 segments, quote-anchored rooted
// paths (group 1), and bare relative paths ending in an asset extension.
var urlScanRe = regexp.MustCompile(
	`(?:https?:|wss?:)?//[^\s"'` + "`" + `<>,;()]+` +
		`|\.{0,2}/[` + urlSegChars + `]+(?:/[` + urlSegChars + `]*)+` +
		`|["'` + "`" + `](\.{0,2}/[` + urlSegChars + `]+(?:/[` + urlSegChars + `]*)*)` +
		`|[` + urlSegChars + `]+(?:/[` + urlSegChars + `]+)+\.(?:` + assetExts + `)`)

// placeholderRe matches a ${...} or {...} interpolation placeholder.
var placeholderRe = regexp.MustCompile(`\$?\{[^}]*\}`)

// hostnameRe matches a plausible hostname (alphanumeric, no leading/trailing dot or
// hyphen, no regex metachars), used to reject bogus hosts like ".+", ".test", "api.".
var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$`)

// looksLikeURL reports whether s is acceptable as an endpoint URL.
// Template-literal expansions containing `${...}` placeholders are always accepted.
func looksLikeURL(s string) bool {
	return urlLiteralRe.MatchString(s) || strings.Contains(s, "${")
}

// looksLikeWebSocketURL reports whether s is a valid WebSocket URL (absolute ws:// or wss://).
func looksLikeWebSocketURL(s string) bool {
	return strings.HasPrefix(s, "ws://") || strings.HasPrefix(s, "wss://") || strings.Contains(s, "${")
}

// Extracted is the raw, pre-dedup output of a single source pass.
type Extracted struct {
	Endpoints  []protocol.ExtractedEndpoint
	Routes     []protocol.ExtractedRoute
	SourceMaps []string
}

// extractFromSource returns the extracted API surface and the raw string literals from src.
// The literals are reused by secret detection. AST sinks (when ast != nil) supply method/library/route labels.
func extractFromSource(src []byte, ast *js.AST) (Extracted, []string) {
	var out Extracted

	if ast != nil {
		s := buildScope(ast)
		v := &sinkVisitor{out: &out, scope: s}
		js.Walk(v, ast)
	}

	literals := scanStringLiterals(src)

	// Seed the seen set with AST-derived URLs/routes so the raw scan only contributes links the AST could not resolve
	knownURLs := make(map[string]struct{}, len(out.Endpoints)+len(out.Routes))
	seedKnown := func(u string) {
		n := normalizeURL(u)
		knownURLs[n] = struct{}{}
		// A sink URL with a dynamic placeholder base (`${...}/api/x`) would otherwise
		// be re-listed by the literal scan as a bare `/api/x`; seed that path tail too.
		if rest, ok := stripPlaceholderPrefix(n); ok {
			if c := acceptCandidate(rest); c != "" {
				knownURLs[c] = struct{}{}
			}
		}
	}
	for _, e := range out.Endpoints {
		seedKnown(e.URL)
	}
	for _, r := range out.Routes {
		seedKnown(r.Path)
	}

	addCandidate := func(raw string) {
		u := acceptCandidate(raw)
		if u == "" {
			return
		} else if _, seen := knownURLs[u]; seen {
			return
		}
		knownURLs[u] = struct{}{}
		out.Endpoints = append(out.Endpoints, protocol.ExtractedEndpoint{
			URL:     u,
			Library: libLiteral,
		})
	}

	// Scan only lexer-identified string content, so regex literals, division, and comments cannot be mistaken for URLs.
	// The whole literal catches single-segment paths and absolute URLs; the substring scan catches paths behind
	// a placeholder prefix (e.g. "/api/org" inside "%s/api/org").
	for _, lit := range literals {
		addCandidate(lit)
		for _, c := range scanURLCandidates([]byte(lit)) {
			addCandidate(c)
		}
	}

	for _, m := range sourceMapRe.FindAllSubmatch(src, -1) {
		out.SourceMaps = append(out.SourceMaps, string(m[1]))
	}

	return out, literals
}

// maxURLCandidateLen bounds an accepted URL/path length.
const maxURLCandidateLen = 1000

// urlShaped reports whether s resembles a URL/path rather than code.
func urlShaped(s string) bool {
	s = placeholderRe.ReplaceAllString(s, "")
	return !strings.ContainsAny(s, " \t\r\n\"'`(){}$;\\^<>|")
}

// scanURLCandidates returns the raw URL/path candidate substrings found in b.
func scanURLCandidates(b []byte) []string {
	ms := urlScanRe.FindAllSubmatch(b, -1)
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		c := m[0]
		if len(m[1]) > 0 {
			c = m[1]
		}
		out = append(out, string(c))
	}
	return out
}

// acceptCandidate validates and normalizes a raw URL/path candidate, returning "" to reject non-URL strings.
func acceptCandidate(raw string) string {
	s := decodeJSEscapes(raw)
	if len(s) > maxURLCandidateLen || !urlShaped(s) {
		return "" // length/shape bound: rejects swallowed code and minified blobs
	}
	if host, path, ok := splitHostPath(s); ok {
		if hostname := stripPort(host); strings.Contains(hostname, ".") && hostnameRe.MatchString(hostname) {
			return normalizeURL(s)
		}
		if countSegments(path) >= 2 && !hasEntropySegment(path) {
			return normalizeURL(path)
		}
		return ""
	}
	// Strip a leading placeholder/base prefix so a single-segment path built as
	// `${host}/methods` or "%s/methods" exposes its "/methods" path.
	if rest, ok := stripPlaceholderPrefix(s); ok {
		s = rest
	}
	if hasEntropySegment(s) {
		return ""
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") {
		if countSegments(s) == 0 || looksLikeRegexLiteral(s) || regexMethodTailRe.MatchString(s) {
			return "" // bare "/", a regex literal (/~1/g), or a /regex/.test() call
		}
		// CSS-in-JS property lists carry both ',' and ':' in the path; real paths
		// have at most one (comma-list or gRPC resource:method), never both.
		if p := StripQuery(s); strings.ContainsRune(p, ',') && strings.ContainsRune(p, ':') {
			return ""
		}
		// A single-segment path must be word-like to exclude noise such as /g
		// (regex flag), /2 (fraction), or /${...} (display template).
		if countSegments(s) == 1 && !wordLikeSegment(s) {
			return ""
		}
		return normalizeURL(s)
	}
	// Bare relative: only accept real asset references, not word/word shapes (MIME types, i18n keys)
	if !assetExtRe.MatchString(s) {
		return ""
	}
	return normalizeURL(s)
}

// stripPlaceholderPrefix returns the rooted path of s after a leading dynamic base
// (e.g. "${host}", "%s"), or (s, false) when there is none.
func stripPlaceholderPrefix(s string) (string, bool) {
	i := strings.IndexByte(s, '/')
	if i <= 0 {
		return s, false
	}
	if !strings.ContainsAny(s[:i], "${}%") {
		return s, false
	}
	return s[i:], true
}

// regexLiteralRe matches a /pattern/flags shape.
var regexLiteralRe = regexp.MustCompile(`^/(.+)/[gimsuy]{1,6}$`)

// regexMethodTailRe matches a /regex/.method() call mistaken for a path (e.g. /Android/.test).
var regexMethodTailRe = regexp.MustCompile(`/[gimsuy]*\.(?:test|exec|match|matchAll|replace|replaceAll|split|search)$`)

// resourceExtRe matches a fetchable file extension, used to accept slash-less
// sink args like "config.json"; TLD-like endings (.com) are excluded by omission.
var resourceExtRe = regexp.MustCompile(`(?i)\.(?:json|txt|csv|xml|html?|js|mjs|cjs|css|map|svg|png|jpe?g|gif|webp|avif|ico|woff2?|ttf|otf|eot|wasm|pdf|md|ya?ml)(?:[?#]|$)`)

// isURLArg reports whether a definite-sink argument (fetch/axios/...) is a recordable
// request target. The sink establishes it is a URL, so a slash-less relative file like
// "foo.txt" is kept, but a bare i18n key ("translation.key") or host ("www.google.com")
// is not. Base64 alphabets and error-message templates are also rejected.
func isURLArg(s string) bool {
	if len(s) > maxURLCandidateLen || !urlShaped(s) || hasEntropySegment(s) {
		return false
	}
	return looksLikeURL(s) || resourceExtRe.MatchString(s)
}

// looksLikeRegexLiteral reports whether s is a regex literal (e.g. /~1/g) rather than a path.
func looksLikeRegexLiteral(s string) bool {
	m := regexLiteralRe.FindStringSubmatch(s)
	if m == nil {
		return false
	}
	return strings.ContainsAny(m[1], `.^$[]*+?\~(){}|`)
}

// wordLikeSegment reports whether the last path segment of s looks like a real name.
func wordLikeSegment(s string) bool {
	seg := s
	if i := strings.LastIndexByte(seg, '/'); i >= 0 {
		seg = seg[i+1:]
	}
	seg = placeholderRe.ReplaceAllString(seg, "") // ignore ${...} placeholder content
	if len(seg) < 2 {
		return false
	}
	for _, r := range seg {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			return true
		}
	}
	return false
}

// splitHostPath splits a scheme-relative or absolute URL into host and path.
// ok is false when s is not URL-shaped (no "//" that follows a scheme colon).
func splitHostPath(s string) (host, path string, ok bool) {
	i := strings.Index(s, "//")
	if i < 0 || (i > 0 && s[i-1] != ':') {
		return "", "", false
	}
	rest := s[i+2:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		return rest[:j], rest[j:], true
	}
	return rest, "", true
}

// stripPort returns host with ":port" removed, to validate against hostnameRe. host must be an authority with no path;
// only a digits-after-colon suffix is treated as a port, leaving other colons in place.
func stripPort(host string) string {
	i := strings.LastIndexByte(host, ':')
	if i < 0 || i == len(host)-1 {
		return host
	}
	for _, r := range host[i+1:] {
		if r < '0' || r > '9' {
			return host
		}
	}
	return host[:i]
}

// countSegments counts non-empty "/"-delimited segments in path.
func countSegments(path string) int {
	var n int
	for _, seg := range strings.Split(path, "/") {
		if seg != "" {
			n++
		}
	}
	return n
}

// hasEntropySegment reports whether any segment looks like a base64/random token.
func hasEntropySegment(s string) bool {
	for _, seg := range strings.Split(s, "/") {
		if seg == "" || strings.ContainsAny(seg, "${}") {
			continue
		} else if len(seg) < 8 || strings.ContainsAny(seg, "-_.") {
			continue
		}
		var up, lo, dig bool
		for _, r := range seg {
			switch {
			case r >= 'A' && r <= 'Z':
				up = true
			case r >= 'a' && r <= 'z':
				lo = true
			case r >= '0' && r <= '9':
				dig = true
			}
		}
		if up && lo && dig {
			return true
		}
	}
	return false
}

// normalizeURL collapses ${...}/{...} interpolation placeholders to a canonical
// ${...} so raw matches dedupe against AST-reconstructed template URLs.
func normalizeURL(s string) string {
	if !strings.ContainsAny(s, "${") {
		return s
	}
	return placeholderRe.ReplaceAllString(s, "${...}")
}

// sinkVisitor walks AST nodes collecting sink-arg endpoints, routes, and sockets.
// When details is non-nil, each sink's full per-call-site request shape is collected.
type sinkVisitor struct {
	out     *Extracted
	scope   *scope
	details *[]callDetail
}

func (v *sinkVisitor) Exit(_ js.INode) {}

// addEndpoint records an endpoint, deriving its EndpointID when the call site carries
// request-shape detail (body/headers/path params) and collecting that detail when enabled.
// node renders the call expression; urlArg supplies path params; ex carries options detail.
func (v *sinkVisitor) addEndpoint(ep protocol.ExtractedEndpoint, node js.INode, urlArg js.IExpr, ex detailExtras) {
	d := callDetail{
		Method:     ep.Method,
		URL:        ep.URL,
		Library:    ep.Library,
		Body:       ex.body,
		Headers:    ex.headers,
		Query:      append(queryFromURL(ep.URL), ex.query...),
		PathParams: pathParamsFromArg(urlArg),
	}
	// Param-sourced query (e.g. axios {params:{...}}) is extra detail not visible in the
	// list URL, so it makes the endpoint queryable; URL-embedded query does not.
	if d.structured() || len(ex.query) > 0 {
		ep.EndpointID = EndpointID(ep.Method, ep.URL)
	}
	v.out.Endpoints = append(v.out.Endpoints, ep)
	if v.details != nil {
		if node != nil {
			d.Call = node.String()
		}
		*v.details = append(*v.details, d)
	}
}

func (v *sinkVisitor) Enter(n js.INode) js.IVisitor {
	switch node := n.(type) {
	case *js.CallExpr:
		v.visitCall(node)
	case *js.NewExpr:
		v.visitNew(node)
	case *js.BinaryExpr:
		v.visitAssign(node)
	}
	return v
}

// visitCall inspects a call expression's callee shape to identify sinks.
func (v *sinkVisitor) visitCall(c *js.CallExpr) {
	switch {
	case isImportCallee(c.X):
		v.captureDynamicImport(c)
	case isIdentCallee(c.X):
		name, _ := dotObjectName(c.X)
		v.visitIdentCall(name, c)
	default:
		if d, ok := c.X.(*js.DotExpr); ok {
			v.visitMemberCall(d, c)
		}
	}
	// Generic request wrapper: f(METHOD, url, ...). Runs after specific sinks so an
	// already-classified call (e.g. xhr.open) wins dedupe on (method, url).
	v.captureMethodWrapper(c)
}

// isIdentCallee reports whether the callee is a bare identifier (not a member access).
func isIdentCallee(expr js.IExpr) bool {
	switch e := expr.(type) {
	case *js.Var:
		return true
	case *js.LiteralExpr:
		return e.TokenType == js.IdentifierToken
	case js.LiteralExpr:
		return e.TokenType == js.IdentifierToken
	}
	return false
}

// captureMethodWrapper handles request wrappers whose first argument is a static HTTP
// method literal and whose second argument resolves to a URL (e.g. superagent's
// request("POST", url) / buildRequest("GET", url)). The method literal is the
// confident signal, so the URL need not be the first argument.
func (v *sinkVisitor) captureMethodWrapper(c *js.CallExpr) {
	if len(c.Args.List) < 2 {
		return
	}
	m, ok := staticString(c.Args.List[0].Value)
	if !ok {
		return
	}
	method := strings.ToUpper(m)
	if _, ok := httpMethods[method]; !ok {
		return
	}
	u, ok := v.resolveURLArg(c.Args.List[1].Value)
	// Heuristic sink (any f(METHOD, x)): require a path/scheme so non-URL args like
	// "state-${id}" don't match a generic wrapper called with every verb.
	if !ok || !isURLArg(u) || !strings.Contains(u, "/") {
		return
	}
	v.addEndpoint(protocol.ExtractedEndpoint{
		Method:  method,
		URL:     u,
		Library: libRequest,
	}, c, c.Args.List[1].Value, detailExtras{})
}

// visitIdentCall handles fetch, router factories, and call-form router navigation.
func (v *sinkVisitor) visitIdentCall(name string, c *js.CallExpr) {
	if fw, ok := v.scope.routerReceivers[name]; ok && len(c.Args.List) >= 1 {
		if route, rok := routeFromArg(c.Args.List[0].Value); rok {
			v.out.Routes = append(v.out.Routes, protocol.ExtractedRoute{
				Path:      route,
				Framework: fw,
			})
		}
	}
	switch name {
	case "fetch":
		v.captureFetch(c)
	case "axios":
		v.captureAxiosCall(c)
	case "importScripts":
		v.captureImportScripts(c)
	case "createBrowserRouter", "createHashRouter", "createMemoryRouter":
		if len(c.Args.List) >= 1 {
			v.captureRouteArray(c.Args.List[0].Value, frameworkReactRouter)
		}
	case "createRouter":
		if len(c.Args.List) >= 1 {
			v.captureRouteConfigObject(c.Args.List[0].Value, frameworkVueRouter)
		}
	}
}

// resolveURLArg returns the static string value of expr, resolving a bare
// identifier through scope.stringVars so a variable-held URL still yields its
// value (light intra-bundle constant propagation).
func (v *sinkVisitor) resolveURLArg(expr js.IExpr) (string, bool) {
	if s, ok := staticString(expr); ok {
		return s, true
	}
	if name, ok := dotObjectName(expr); ok {
		if s, ok := v.scope.stringVars[name]; ok {
			return s, true
		}
	}
	return "", false
}

// captureFetch appends an endpoint for a `fetch(url, [opts])` call.
func (v *sinkVisitor) captureFetch(c *js.CallExpr) {
	if len(c.Args.List) == 0 {
		return
	}
	url, ok := v.resolveURLArg(c.Args.List[0].Value)
	if !ok || !isURLArg(url) {
		return
	}
	ep := protocol.ExtractedEndpoint{
		URL:     url,
		Library: libFetch,
	}
	var opts *js.ObjectExpr
	if len(c.Args.List) >= 2 {
		ep.Method = methodFromOptionsArg(c.Args.List[1].Value)
		opts = objArg(c, 1)
	}
	v.addEndpoint(ep, c, c.Args.List[0].Value, configExtras(libFetch, opts))
}

// captureAxiosCall handles the axios(url[, opts]) and axios({url, method}) direct-call forms.
// The axios.<method>() shortcuts are handled by visitAxiosCall.
func (v *sinkVisitor) captureAxiosCall(c *js.CallExpr) {
	if len(c.Args.List) == 0 {
		return
	}
	first := c.Args.List[0].Value
	if u, ok := v.resolveURLArg(first); ok {
		if !isURLArg(u) {
			return
		}
		ep := protocol.ExtractedEndpoint{URL: u, Library: libAxios}
		var opts *js.ObjectExpr
		if len(c.Args.List) >= 2 {
			ep.Method = methodFromOptionsArg(c.Args.List[1].Value)
			opts = objArg(c, 1)
		}
		v.addEndpoint(ep, c, first, configExtras(libAxios, opts))
		return
	}
	if obj, ok := first.(*js.ObjectExpr); ok {
		u := stringProp(obj, "url")
		if u == "" || !isURLArg(u) {
			return
		}
		v.addEndpoint(protocol.ExtractedEndpoint{
			Method:  strings.ToUpper(stringProp(obj, "method")),
			URL:     u,
			Library: libAxios,
		}, c, propValue(obj, "url"), configExtras(libAxios, obj))
	}
}

// captureDynamicImport handles dynamic import('...') calls. Only path- or URL-shaped
// specifiers are captured; bare module (npm package) names are ignored.
func (v *sinkVisitor) captureDynamicImport(c *js.CallExpr) {
	if len(c.Args.List) == 0 {
		return
	}
	if u, ok := v.resolveURLArg(c.Args.List[0].Value); ok && importSpecifierIsPath(u) {
		v.addEndpoint(protocol.ExtractedEndpoint{
			URL:     u,
			Library: libImport,
		}, c, c.Args.List[0].Value, detailExtras{})
	}
}

// captureImportScripts handles importScripts(url, ...) worker script loads.
// Every static string argument is a script URL by API contract.
func (v *sinkVisitor) captureImportScripts(c *js.CallExpr) {
	for _, arg := range c.Args.List {
		if u, ok := staticString(arg.Value); ok && u != "" {
			v.addEndpoint(protocol.ExtractedEndpoint{
				URL:     u,
				Library: libImport,
			}, c, arg.Value, detailExtras{})
		}
	}
}

// visitMemberCall handles `<obj>.<prop>(...)` shaped sinks.
func (v *sinkVisitor) visitMemberCall(d *js.DotExpr, c *js.CallExpr) {
	prop, ok := dotPropertyName(d.Y)
	if !ok {
		return
	}

	// (window|document|self).location.assign|replace(url) and bare location.assign(...)
	if (prop == "assign" || prop == "replace") && isLocationObject(d.X) {
		v.captureNavURL(c)
		return
	}

	objName, ok := dotObjectName(d.X)
	if !ok {
		return
	}

	switch objName {
	case "axios":
		v.visitAxiosCall(prop, c)
	case "$", "jQuery":
		v.visitJQueryCall(prop, c)
	}

	// (window|self|globalThis).fetch(...) treated as fetch sink
	if prop == "fetch" && isGlobalThisName(objName) {
		v.captureFetch(c)
	}

	// window.open(url, ...)
	if (objName == globalWindow || objName == globalSelf) && prop == "open" {
		v.captureNavURL(c)
	}

	// navigator.sendBeacon(url, data) - always a POST
	if objName == "navigator" && prop == "sendBeacon" && len(c.Args.List) >= 1 {
		if u, ok := v.resolveURLArg(c.Args.List[0].Value); ok && isURLArg(u) {
			v.addEndpoint(protocol.ExtractedEndpoint{
				Method:  http.MethodPost,
				URL:     u,
				Library: libBeacon,
			}, c, c.Args.List[0].Value, detailExtras{})
		}
	}

	// XMLHttpRequest.open(method, url, ...); receiver must be bound to `new XMLHttpRequest()`
	if prop == "open" && len(c.Args.List) >= 2 {
		if _, isXHR := v.scope.xhrReceivers[objName]; isXHR {
			if m, mok := staticString(c.Args.List[0].Value); mok {
				if u, uok := v.resolveURLArg(c.Args.List[1].Value); uok && isURLArg(u) {
					v.addEndpoint(protocol.ExtractedEndpoint{
						Method:  strings.ToUpper(m),
						URL:     u,
						Library: libXHR,
					}, c, c.Args.List[1].Value, detailExtras{})
				}
			}
		}
	}

	// Router navigation: <router-receiver>.push/replace(arg)
	if prop == "push" || prop == "replace" {
		if fw, ok := v.scope.routerReceivers[objName]; ok && len(c.Args.List) >= 1 {
			if route, rok := routeFromArg(c.Args.List[0].Value); rok {
				v.out.Routes = append(v.out.Routes, protocol.ExtractedRoute{
					Path:      route,
					Framework: fw,
				})
			}
		}
	}

	// Vue Router constructor `new VueRouter({routes: [...]})` is handled by visitNew
	// Angular RouterModule.forRoot([...]) / forChild([...])
	if objName == "RouterModule" && (prop == "forRoot" || prop == "forChild") && len(c.Args.List) >= 1 {
		v.captureRouteArray(c.Args.List[0].Value, frameworkAngularRouter)
	}
}

// visitAxiosCall handles axios.<method>() shortcuts (get/post/put/delete/patch/head/options).
func (v *sinkVisitor) visitAxiosCall(method string, c *js.CallExpr) {
	upper := strings.ToUpper(method)
	switch upper {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete,
		http.MethodPatch, http.MethodHead, http.MethodOptions:
	default:
		return
	}
	if len(c.Args.List) == 0 {
		return
	}
	u, ok := v.resolveURLArg(c.Args.List[0].Value)
	if !ok || !isURLArg(u) {
		return
	}
	// axios.post/put/patch(url, data[, config]); axios.get/delete(url[, config]).
	var ex detailExtras
	switch upper {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		if len(c.Args.List) >= 2 {
			ex = configExtras(libAxios, objArg(c, 2))
			ex.body = bodyFromValue(c.Args.List[1].Value)
		}
	default:
		ex = configExtras(libAxios, objArg(c, 1))
	}
	v.addEndpoint(protocol.ExtractedEndpoint{
		Method:  upper,
		URL:     u,
		Library: libAxios,
	}, c, c.Args.List[0].Value, ex)
}

// visitJQueryCall handles $.ajax / $.get / $.post / $.getJSON.
func (v *sinkVisitor) visitJQueryCall(method string, c *js.CallExpr) {
	if len(c.Args.List) == 0 {
		return
	}
	var url string
	var ok bool
	var m string
	urlArg := c.Args.List[0].Value
	var ex detailExtras

	switch strings.ToLower(method) {
	case "get", "getjson":
		m = http.MethodGet
		url, ok = v.resolveURLArg(urlArg)
	case "post":
		m = http.MethodPost
		url, ok = v.resolveURLArg(urlArg)
		if len(c.Args.List) >= 2 {
			ex.body = bodyFromValue(c.Args.List[1].Value)
		}
	case "ajax":
		if obj, isObj := urlArg.(*js.ObjectExpr); isObj {
			url = stringProp(obj, "url")
			m = strings.ToUpper(stringProp(obj, "method"))
			if m == "" {
				m = strings.ToUpper(stringProp(obj, "type"))
			}
			ok = url != ""
			urlArg = propValue(obj, "url")
			ex = configExtras(libJQuery, obj)
		}
	default:
		return
	}
	if !ok || !isURLArg(url) {
		return
	}
	v.addEndpoint(protocol.ExtractedEndpoint{
		Method:  m,
		URL:     url,
		Library: libJQuery,
	}, c, urlArg, ex)
}

// visitNew handles `new WebSocket(url, ...)` and `new VueRouter({routes:[...]})`.
func (v *sinkVisitor) visitNew(n *js.NewExpr) {
	name, ok := constructorName(n.X)
	if !ok {
		return
	}
	switch name {
	case "WebSocket":
		if n.Args == nil || len(n.Args.List) == 0 {
			return
		}
		if u, ok := v.resolveURLArg(n.Args.List[0].Value); ok && looksLikeWebSocketURL(u) {
			v.addEndpoint(protocol.ExtractedEndpoint{
				URL:     u,
				Library: libWebSocket,
			}, n, n.Args.List[0].Value, detailExtras{})
		}
	case "EventSource":
		if n.Args == nil || len(n.Args.List) == 0 {
			return
		}
		if u, ok := v.resolveURLArg(n.Args.List[0].Value); ok && isURLArg(u) {
			v.addEndpoint(protocol.ExtractedEndpoint{
				URL:     u,
				Library: libEventSource,
			}, n, n.Args.List[0].Value, detailExtras{})
		}
	case "VueRouter":
		if n.Args != nil && len(n.Args.List) >= 1 {
			v.captureRouteConfigObject(n.Args.List[0].Value, frameworkVueRouter)
		}
	}
}

// visitAssign handles `document.location = url` and `window.location.href = url`.
func (v *sinkVisitor) visitAssign(b *js.BinaryExpr) {
	if b.Op != js.EqToken {
		return
	} else if !isLocationLHS(b.X) {
		return
	}
	if u, ok := v.resolveURLArg(b.Y); ok && isURLArg(u) {
		v.addEndpoint(protocol.ExtractedEndpoint{
			URL:     u,
			Library: libNavigation,
		}, b, b.Y, detailExtras{})
	}
}

// captureRouteArray walks an array-literal argument and pulls `{path: '/x'}`
// entries as routes for the given framework. Non-array arguments are ignored.
func (v *sinkVisitor) captureRouteArray(expr js.IExpr, framework string) {
	arr, ok := expr.(*js.ArrayExpr)
	if !ok {
		return
	}
	for _, el := range arr.List {
		if el.Value == nil {
			continue
		}
		obj, ok := el.Value.(*js.ObjectExpr)
		if !ok {
			continue
		}
		if p := stringProp(obj, "path"); p != "" {
			v.out.Routes = append(v.out.Routes, protocol.ExtractedRoute{
				Path:      p,
				Framework: framework,
			})
		}
	}
}

// captureRouteConfigObject walks an object literal `{routes: [...]}` argument
// and pulls each `{path: '/x'}` route entry for the given framework.
func (v *sinkVisitor) captureRouteConfigObject(expr js.IExpr, framework string) {
	obj, ok := expr.(*js.ObjectExpr)
	if !ok {
		return
	}
	for _, p := range obj.List {
		if p.Name == nil {
			continue
		} else if propertyKeyName(p) != "routes" {
			continue
		}
		v.captureRouteArray(p.Value, framework)
	}
}

// captureNavURL appends a navigation endpoint for the first static URL argument of c.
func (v *sinkVisitor) captureNavURL(c *js.CallExpr) {
	if len(c.Args.List) == 0 {
		return
	}
	if u, ok := v.resolveURLArg(c.Args.List[0].Value); ok && isURLArg(u) {
		v.addEndpoint(protocol.ExtractedEndpoint{
			URL:     u,
			Library: libNavigation,
		}, c, c.Args.List[0].Value, detailExtras{})
	}
}

// isGlobalThisName reports whether name refers to the global object.
func isGlobalThisName(name string) bool {
	return name == globalWindow || name == globalSelf || name == globalGlobalThis
}

// isImportCallee reports whether a call expression's callee is the `import` keyword, i.e. a dynamic import() expression.
func isImportCallee(expr js.IExpr) bool {
	switch e := expr.(type) {
	case *js.LiteralExpr:
		return e.TokenType == js.ImportToken
	case js.LiteralExpr:
		return e.TokenType == js.ImportToken
	}
	return false
}

// importSpecifierIsPath reports whether a dynamic-import specifier is a path or URL
// rather than a bare module (npm package) name.
func importSpecifierIsPath(s string) bool {
	return strings.HasPrefix(s, "/") ||
		strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, "../") ||
		strings.Contains(s, "://")
}

// isLocationObject reports whether expr refers to a location object:
// bare `location`, or `(window|document|self|globalThis).location`.
func isLocationObject(expr js.IExpr) bool {
	if name, ok := dotObjectName(expr); ok {
		return name == propLocation
	}
	d, ok := expr.(*js.DotExpr)
	if !ok {
		return false
	}
	prop, ok := dotPropertyName(d.Y)
	if !ok || prop != propLocation {
		return false
	}
	base, ok := dotObjectName(d.X)
	return ok && (isGlobalThisName(base) || base == globalDocument)
}

// constructorName returns the constructor identifier for a `new` expression,
// unwrapping `window.`/`self.`/`globalThis.` prefixes (e.g. `new window.WebSocket(...)`).
func constructorName(expr js.IExpr) (string, bool) {
	if name, ok := dotObjectName(expr); ok {
		return name, true
	}
	if d, ok := expr.(*js.DotExpr); ok {
		if base, ok := dotObjectName(d.X); !ok || !isGlobalThisName(base) {
			return "", false
		}
		return dotPropertyName(d.Y)
	}
	return "", false
}

// isLocationLHS reports whether expr is an assignment target on a location object
// (window./document./self. prefix, with or without a .href tail, or bare location.href).
func isLocationLHS(expr js.IExpr) bool {
	d, ok := expr.(*js.DotExpr)
	if !ok {
		return false
	}
	prop, ok := dotPropertyName(d.Y)
	if !ok {
		return false
	}

	if prop == "href" {
		// Bare `location.href = ...` (no receiver)
		if v, ok := d.X.(*js.Var); ok {
			return string(v.Data) == propLocation
		}
		inner, ok := d.X.(*js.DotExpr)
		if !ok {
			return false
		}
		innerProp, ok := dotPropertyName(inner.Y)
		if !ok || innerProp != propLocation {
			return false
		}
		base, ok := dotObjectName(inner.X)
		return ok && (isGlobalThisName(base) || base == globalDocument)
	}

	if prop == propLocation {
		base, ok := dotObjectName(d.X)
		return ok && (isGlobalThisName(base) || base == globalDocument)
	}

	return false
}

// staticString returns the literal string value of expr when it is statically
// resolvable: a quoted string literal or a template literal with no expressions.
func staticString(expr js.IExpr) (string, bool) {
	switch e := expr.(type) {
	case *js.LiteralExpr:
		if e.TokenType == js.StringToken {
			return unquote(e.Data)
		}
	case js.LiteralExpr:
		if e.TokenType == js.StringToken {
			return unquote(e.Data)
		}
	case *js.TemplateExpr:
		if e.Tag != nil {
			return "", false
		}
		if len(e.List) == 0 {
			return unquote(e.Tail)
		}
		var b strings.Builder
		for _, part := range e.List {
			if s, ok := unquote(part.Value); ok {
				b.WriteString(s)
			}
			b.WriteString("${...}")
		}
		if s, ok := unquote(e.Tail); ok {
			b.WriteString(s)
		}
		return b.String(), true
	}
	return "", false
}

// dotObjectName returns the identifier name for the base of a dot/var expression.
// Handles both pointer and value forms of LiteralExpr because the parser uses both.
func dotObjectName(expr js.IExpr) (string, bool) {
	switch e := expr.(type) {
	case *js.Var:
		return string(e.Data), true
	case *js.LiteralExpr:
		if e.TokenType == js.IdentifierToken {
			return string(e.Data), true
		}
	case js.LiteralExpr:
		if e.TokenType == js.IdentifierToken {
			return string(e.Data), true
		}
	}
	return "", false
}

// dotPropertyName returns the property name on the right of a DotExpr.
// Handles both pointer and value forms of LiteralExpr because the parser uses both.
// StringToken data is unquoted so `obj["key"]`-shaped access resolves to `key`.
func dotPropertyName(expr js.IExpr) (string, bool) {
	switch e := expr.(type) {
	case *js.Var:
		return string(e.Data), true
	case *js.LiteralExpr:
		if e.TokenType == js.StringToken {
			return unquote(e.Data)
		}
		return string(e.Data), true
	case js.LiteralExpr:
		if e.TokenType == js.StringToken {
			return unquote(e.Data)
		}
		return string(e.Data), true
	}
	return "", false
}

// methodFromOptionsArg pulls a method literal from a fetch options object: `{method: 'POST'}`.
func methodFromOptionsArg(expr js.IExpr) string {
	obj, ok := expr.(*js.ObjectExpr)
	if !ok {
		return ""
	}
	return strings.ToUpper(stringProp(obj, "method"))
}

// stringProp returns the static string value for an object literal property of the given key.
func stringProp(obj *js.ObjectExpr, key string) string {
	for _, p := range obj.List {
		if p.Name == nil {
			continue
		} else if propertyKeyName(p) != key {
			continue
		}

		if s, ok := staticString(p.Value); ok {
			return s
		}
	}
	return ""
}

// propertyKeyName extracts a property's key name from a Property,
// supporting both identifier and string-literal forms.
func propertyKeyName(p js.Property) string {
	if p.Name == nil {
		return ""
	}
	switch p.Name.Literal.TokenType {
	case js.StringToken:
		if s, ok := unquote(p.Name.Literal.Data); ok {
			return s
		}
	case js.IdentifierToken:
		return string(p.Name.Literal.Data)
	}
	return ""
}

// routeFromArg returns the route path argument for Router.push/replace.
// Accepts a string literal or `{path: '/route'}` object literal.
func routeFromArg(expr js.IExpr) (string, bool) {
	if s, ok := staticString(expr); ok && strings.HasPrefix(s, "/") {
		return s, true
	}
	if obj, ok := expr.(*js.ObjectExpr); ok {
		if p := stringProp(obj, "path"); p != "" {
			return p, true
		}
	}
	return "", false
}

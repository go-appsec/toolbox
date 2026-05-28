package js

import (
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
)

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
// The literals are reused by secret detection.
func extractFromSource(src []byte, ast *js.AST) (Extracted, []string) {
	var out Extracted

	if ast != nil {
		s := buildScope(ast)
		v := &sinkVisitor{out: &out, scope: s}
		js.Walk(v, ast)
	}

	literals := scanStringLiterals(src)

	// Token-stream scan catches URL-shaped literals outside known sinks.
	// Seed the seen set so literals don't duplicate already-classified entries.
	knownURLs := make(map[string]struct{}, len(out.Endpoints)+len(out.Routes))
	for _, e := range out.Endpoints {
		knownURLs[e.URL] = struct{}{}
	}
	for _, r := range out.Routes {
		knownURLs[r.Path] = struct{}{}
	}
	for _, lit := range literals {
		if !urlLiteralRe.MatchString(lit) {
			continue
		} else if _, seen := knownURLs[lit]; seen {
			continue
		}
		knownURLs[lit] = struct{}{}

		out.Endpoints = append(out.Endpoints, protocol.ExtractedEndpoint{
			URL:     lit,
			Library: libLiteral,
		})
	}

	for _, m := range sourceMapRe.FindAllSubmatch(src, -1) {
		out.SourceMaps = append(out.SourceMaps, string(m[1]))
	}

	return out, literals
}

// sinkVisitor walks AST nodes collecting sink-arg endpoints, routes, and sockets.
type sinkVisitor struct {
	out   *Extracted
	scope *scope
}

func (v *sinkVisitor) Exit(_ js.INode) {}

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
	if isImportCallee(c.X) {
		v.captureDynamicImport(c)
		return
	}
	if name, ok := dotObjectName(c.X); ok {
		v.visitIdentCall(name, c)
		return
	}
	if d, ok := c.X.(*js.DotExpr); ok {
		v.visitMemberCall(d, c)
	}
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

// captureFetch appends an endpoint for a `fetch(url, [opts])` call.
func (v *sinkVisitor) captureFetch(c *js.CallExpr) {
	if len(c.Args.List) == 0 {
		return
	}
	url, ok := staticString(c.Args.List[0].Value)
	if !ok || !looksLikeURL(url) {
		return
	}
	ep := protocol.ExtractedEndpoint{
		URL:     url,
		Library: libFetch,
	}
	if len(c.Args.List) >= 2 {
		ep.Method = methodFromOptionsArg(c.Args.List[1].Value)
	}
	v.out.Endpoints = append(v.out.Endpoints, ep)
}

// captureAxiosCall handles the axios(url[, opts]) and axios({url, method}) direct-call forms.
// The axios.<method>() shortcuts are handled by visitAxiosCall.
func (v *sinkVisitor) captureAxiosCall(c *js.CallExpr) {
	if len(c.Args.List) == 0 {
		return
	}
	first := c.Args.List[0].Value
	if u, ok := staticString(first); ok {
		if !looksLikeURL(u) {
			return
		}
		ep := protocol.ExtractedEndpoint{URL: u, Library: libAxios}
		if len(c.Args.List) >= 2 {
			ep.Method = methodFromOptionsArg(c.Args.List[1].Value)
		}
		v.out.Endpoints = append(v.out.Endpoints, ep)
		return
	}
	if obj, ok := first.(*js.ObjectExpr); ok {
		u := stringProp(obj, "url")
		if u == "" || !looksLikeURL(u) {
			return
		}
		v.out.Endpoints = append(v.out.Endpoints, protocol.ExtractedEndpoint{
			Method:  strings.ToUpper(stringProp(obj, "method")),
			URL:     u,
			Library: libAxios,
		})
	}
}

// captureDynamicImport handles dynamic import('...') calls. Only path- or URL-shaped
// specifiers are captured; bare module (npm package) names are ignored.
func (v *sinkVisitor) captureDynamicImport(c *js.CallExpr) {
	if len(c.Args.List) == 0 {
		return
	}
	if u, ok := staticString(c.Args.List[0].Value); ok && importSpecifierIsPath(u) {
		v.out.Endpoints = append(v.out.Endpoints, protocol.ExtractedEndpoint{
			URL:     u,
			Library: libImport,
		})
	}
}

// captureImportScripts handles importScripts(url, ...) worker script loads.
// Every static string argument is a script URL by API contract.
func (v *sinkVisitor) captureImportScripts(c *js.CallExpr) {
	for _, arg := range c.Args.List {
		if u, ok := staticString(arg.Value); ok && u != "" {
			v.out.Endpoints = append(v.out.Endpoints, protocol.ExtractedEndpoint{
				URL:     u,
				Library: libImport,
			})
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

	// navigator.sendBeacon(url, data) — always a POST
	if objName == "navigator" && prop == "sendBeacon" && len(c.Args.List) >= 1 {
		if u, ok := staticString(c.Args.List[0].Value); ok && looksLikeURL(u) {
			v.out.Endpoints = append(v.out.Endpoints, protocol.ExtractedEndpoint{
				Method:  "POST",
				URL:     u,
				Library: libBeacon,
			})
		}
	}

	// XMLHttpRequest.open(method, url, ...); receiver must be bound to `new XMLHttpRequest()`
	if prop == "open" && len(c.Args.List) >= 2 {
		if _, isXHR := v.scope.xhrReceivers[objName]; isXHR {
			if m, mok := staticString(c.Args.List[0].Value); mok {
				if u, uok := staticString(c.Args.List[1].Value); uok && looksLikeURL(u) {
					v.out.Endpoints = append(v.out.Endpoints, protocol.ExtractedEndpoint{
						Method:  strings.ToUpper(m),
						URL:     u,
						Library: libXHR,
					})
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

	// Vue Router constructor `new VueRouter({routes: [...]})` is handled by visitNew.
	// Angular RouterModule.forRoot([...]) / forChild([...]).
	if objName == "RouterModule" && (prop == "forRoot" || prop == "forChild") && len(c.Args.List) >= 1 {
		v.captureRouteArray(c.Args.List[0].Value, frameworkAngularRouter)
	}
}

// visitAxiosCall handles axios.<method>() shortcuts (get/post/put/delete/patch/head/options).
func (v *sinkVisitor) visitAxiosCall(method string, c *js.CallExpr) {
	upper := strings.ToUpper(method)
	switch upper {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
	default:
		return
	}
	if len(c.Args.List) == 0 {
		return
	}
	u, ok := staticString(c.Args.List[0].Value)
	if !ok || !looksLikeURL(u) {
		return
	}
	v.out.Endpoints = append(v.out.Endpoints, protocol.ExtractedEndpoint{
		Method:  upper,
		URL:     u,
		Library: libAxios,
	})
}

// visitJQueryCall handles $.ajax / $.get / $.post / $.getJSON.
func (v *sinkVisitor) visitJQueryCall(method string, c *js.CallExpr) {
	if len(c.Args.List) == 0 {
		return
	}
	var url string
	var ok bool
	var m string

	switch strings.ToLower(method) {
	case "get", "getjson":
		m = "GET"
		url, ok = staticString(c.Args.List[0].Value)
	case "post":
		m = "POST"
		url, ok = staticString(c.Args.List[0].Value)
	case "ajax":
		if obj, isObj := c.Args.List[0].Value.(*js.ObjectExpr); isObj {
			url = stringProp(obj, "url")
			m = strings.ToUpper(stringProp(obj, "method"))
			if m == "" {
				m = strings.ToUpper(stringProp(obj, "type"))
			}
			ok = url != ""
		}
	default:
		return
	}
	if !ok || !looksLikeURL(url) {
		return
	}
	v.out.Endpoints = append(v.out.Endpoints, protocol.ExtractedEndpoint{
		Method:  m,
		URL:     url,
		Library: libJQuery,
	})
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
		if u, ok := staticString(n.Args.List[0].Value); ok && looksLikeWebSocketURL(u) {
			v.out.Endpoints = append(v.out.Endpoints, protocol.ExtractedEndpoint{
				URL:     u,
				Library: libWebSocket,
			})
		}
	case "EventSource":
		if n.Args == nil || len(n.Args.List) == 0 {
			return
		}
		if u, ok := staticString(n.Args.List[0].Value); ok && looksLikeURL(u) {
			v.out.Endpoints = append(v.out.Endpoints, protocol.ExtractedEndpoint{
				URL:     u,
				Library: libEventSource,
			})
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
	if u, ok := staticString(b.Y); ok && looksLikeURL(u) {
		v.out.Endpoints = append(v.out.Endpoints, protocol.ExtractedEndpoint{
			URL:     u,
			Library: libNavigation,
		})
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
	if u, ok := staticString(c.Args.List[0].Value); ok && looksLikeURL(u) {
		v.out.Endpoints = append(v.out.Endpoints, protocol.ExtractedEndpoint{
			URL:     u,
			Library: libNavigation,
		})
	}
}

// isGlobalThisName reports whether name refers to the global object.
func isGlobalThisName(name string) bool {
	return name == globalWindow || name == globalSelf || name == globalGlobalThis
}

// isImportCallee reports whether a call expression's callee is the `import` keyword,
// i.e. a dynamic import() expression.
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

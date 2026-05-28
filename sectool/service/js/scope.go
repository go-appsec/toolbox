package js

import (
	"strings"

	"github.com/tdewolff/parse/v2/js"
)

// scope holds identifier bindings collected in a pre-pass over the AST.
// sinkVisitor consults it to gate XHR and router-receiver heuristics.
// Cross-file and destructured bindings are not tracked.
type scope struct {
	xhrReceivers    map[string]struct{}
	routerReceivers map[string]string // identifier to framework label
}

// routerProducerCalls lists hook and factory names that return a router instance
// when imported from a recognized router library.
var routerProducerCalls = map[string]struct{}{
	"useNavigate":         {},
	"useHistory":          {},
	"useRouter":           {},
	"useRouterHistory":    {},
	"createRouter":        {},
	"createBrowserRouter": {},
	"createHashRouter":    {},
	"createMemoryRouter":  {},
}

// routerConstructors lists classes that produce a router instance via `new`
// when imported from a recognized router library.
var routerConstructors = map[string]struct{}{
	"VueRouter": {},
}

// buildScope returns the populated scope for ast. Returns an empty scope when ast is nil.
func buildScope(ast *js.AST) *scope {
	s := &scope{
		xhrReceivers:    make(map[string]struct{}),
		routerReceivers: make(map[string]string),
	}
	if ast == nil {
		return s
	}
	v := &scopeVisitor{s: s, routerImports: make(map[string]string)}
	js.Walk(v, ast)
	return s
}

// scopeVisitor walks the AST collecting imports and bindings into scope.
type scopeVisitor struct {
	s *scope
	// routerImports maps locally-bound identifiers from router-library imports to their framework label.
	routerImports map[string]string
}

func (v *scopeVisitor) Exit(_ js.INode) {}

func (v *scopeVisitor) Enter(n js.INode) js.IVisitor {
	switch node := n.(type) {
	case *js.ImportStmt:
		v.visitImport(node)
	case *js.VarDecl:
		v.visitVarDecl(node)
	case *js.BinaryExpr:
		v.visitAssign(node)
	}
	return v
}

// frameworkForModule returns the framework label for an import module, or "" if unrecognized.
// rawModule is the quoted module string as emitted by the lexer.
func frameworkForModule(rawModule string) string {
	m, ok := unquote([]byte(rawModule))
	if !ok {
		m = rawModule
	}
	switch {
	case strings.HasPrefix(m, "react-router"):
		return frameworkReactRouter
	case strings.HasPrefix(m, "vue-router"):
		return frameworkVueRouter
	case m == "@angular/router" || strings.HasPrefix(m, "@angular/router/"):
		return frameworkAngularRouter
	}
	return ""
}

func (v *scopeVisitor) visitImport(imp *js.ImportStmt) {
	fw := frameworkForModule(string(imp.Module))
	if fw == "" {
		return
	}
	if len(imp.Default) > 0 {
		v.routerImports[string(imp.Default)] = fw
	}
	for _, a := range imp.List {
		name := a.Binding
		if len(name) == 0 {
			name = a.Name
		}
		if len(name) == 0 {
			continue
		}
		v.routerImports[string(name)] = fw
	}
}

func (v *scopeVisitor) visitVarDecl(d *js.VarDecl) {
	for _, el := range d.List {
		name, ok := bindingVarName(el.Binding)
		if !ok || el.Default == nil {
			continue
		}
		v.classifyBinding(name, el.Default)
	}
}

// visitAssign handles plain reassignment of XHR or router receivers.
// var/let/const bindings flow through visitVarDecl instead.
func (v *scopeVisitor) visitAssign(b *js.BinaryExpr) {
	if b.Op != js.EqToken {
		return
	}
	name, ok := dotObjectName(b.X)
	if !ok {
		return
	}
	v.classifyBinding(name, b.Y)
}

// classifyBinding records name in scope when expr matches a known XHR or router shape.
func (v *scopeVisitor) classifyBinding(name string, expr js.IExpr) {
	switch e := expr.(type) {
	case *js.NewExpr:
		cname, ok := constructorName(e.X)
		if !ok {
			return
		}
		if cname == "XMLHttpRequest" {
			v.s.xhrReceivers[name] = struct{}{}
			return
		}
		if _, isCtor := routerConstructors[cname]; isCtor {
			if fw, imported := v.routerImports[cname]; imported {
				v.s.routerReceivers[name] = fw
			}
		}
	case *js.CallExpr:
		cname, ok := dotObjectName(e.X)
		if !ok {
			return
		}
		if _, prod := routerProducerCalls[cname]; !prod {
			return
		}
		if fw, imported := v.routerImports[cname]; imported {
			v.s.routerReceivers[name] = fw
		}
	}
}

// bindingVarName returns the identifier name for a simple Var binding.
// Destructuring patterns are intentionally unsupported.
func bindingVarName(b js.IBinding) (string, bool) {
	if v, ok := b.(*js.Var); ok {
		return string(v.Data), true
	}
	return "", false
}

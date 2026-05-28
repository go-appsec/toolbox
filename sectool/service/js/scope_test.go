package js

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

func TestFrameworkForModule(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// rawModule is the raw token form the lexer would emit (quoted).
		rawModule string
		want      string
	}{
		{"react_router_quoted", `"react-router"`, frameworkReactRouter},
		{"react_router_dom_quoted", `"react-router-dom"`, frameworkReactRouter},
		{"react_router_native_quoted", `'react-router-native'`, frameworkReactRouter},
		{"vue_router_quoted", `"vue-router"`, frameworkVueRouter},
		{"vue_router_subpath", `"vue-router/auto"`, frameworkVueRouter},
		{"angular_router_quoted", `"@angular/router"`, frameworkAngularRouter},
		{"angular_router_subpath", `"@angular/router/testing"`, frameworkAngularRouter},
		{"unrelated_module", `"lodash"`, ""},
		{"empty_module", `""`, ""},
		// Real-world: imports come in quoted; the function also tolerates a bare unquoted form.
		{"bare_unquoted_react_router", `react-router`, frameworkReactRouter},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, frameworkForModule(tc.rawModule))
		})
	}
}

func TestBuildScope(t *testing.T) {
	t.Parallel()

	t.Run("xhr_var_binding", func(t *testing.T) {
		s := scopeFor(t, `var xhr = new XMLHttpRequest();`)
		_, ok := s.xhrReceivers["xhr"]
		assert.True(t, ok)
	})

	t.Run("xhr_assign_binding", func(t *testing.T) {
		s := scopeFor(t, `let xhr; xhr = new XMLHttpRequest();`)
		_, ok := s.xhrReceivers["xhr"]
		assert.True(t, ok)
	})

	t.Run("xhr_unrelated_constructor_ignored", func(t *testing.T) {
		s := scopeFor(t, `var x = new Foo();`)
		_, ok := s.xhrReceivers["x"]
		assert.False(t, ok)
	})

	t.Run("router_named_import_use_navigate", func(t *testing.T) {
		s := scopeFor(t, `
import { useNavigate } from 'react-router';
const nav = useNavigate();
`)
		assert.Equal(t, frameworkReactRouter, s.routerReceivers["nav"])
	})

	t.Run("router_default_import_use_router", func(t *testing.T) {
		s := scopeFor(t, `
import VueRouter from 'vue-router';
const r = new VueRouter();
`)
		assert.Equal(t, frameworkVueRouter, s.routerReceivers["r"])
	})

	t.Run("router_producer_without_import_rejected", func(t *testing.T) {
		// useNavigate is recognized only when imported from a router library.
		s := scopeFor(t, `const nav = useNavigate();`)
		_, ok := s.routerReceivers["nav"]
		assert.False(t, ok)
	})

	t.Run("nil_ast_returns_empty_scope", func(t *testing.T) {
		s := buildScope(nil)
		require.NotNil(t, s)
		assert.Empty(t, s.xhrReceivers)
		assert.Empty(t, s.routerReceivers)
	})
}

func scopeFor(t *testing.T, src string) *scope {
	t.Helper()
	ast, err := js.Parse(parse.NewInputBytes([]byte(src)), js.Options{})
	require.NoError(t, err)
	return buildScope(ast)
}

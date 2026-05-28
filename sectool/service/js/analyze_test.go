package js

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnalyzeJS(t *testing.T) {
	t.Parallel()

	t.Run("endpoint_and_route_extraction", func(t *testing.T) {
		cases := []struct {
			name string
			src  string
			// "<library> <method> <url>" for endpoints (method "" elided after space split).
			endpoints []string
			routes    []string
		}{
			{
				name: "fetch_basic",
				src:  `fetch('/api/users');`,
				endpoints: []string{
					"fetch  /api/users",
				},
			},
			{
				name: "fetch_with_method",
				src:  `fetch('/api/users', {method: 'POST'});`,
				endpoints: []string{
					"fetch POST /api/users",
				},
			},
			{
				name: "axios_methods",
				src: `
axios.get('/a/x');
axios.post('/b/x');
axios.delete('/c/x');
`,
				endpoints: []string{
					"axios GET /a/x",
					"axios POST /b/x",
					"axios DELETE /c/x",
				},
			},
			{
				name: "axios_bare_call",
				src:  `axios('/api/x');`,
				endpoints: []string{
					"axios  /api/x",
				},
			},
			{
				name: "axios_bare_call_with_config",
				src:  `axios('/api/x', {method: 'put'});`,
				endpoints: []string{
					"axios PUT /api/x",
				},
			},
			{
				name: "axios_config_object",
				src:  `axios({url: '/api/y', method: 'post'});`,
				endpoints: []string{
					"axios POST /api/y",
				},
			},
			{
				name: "axios_config_object_no_method",
				src:  `axios({url: '/api/z'});`,
				endpoints: []string{
					"axios  /api/z",
				},
			},
			{
				name: "xhr_open",
				src: `
var xhr = new XMLHttpRequest();
xhr.open('PUT', '/api/save');
`,
				endpoints: []string{"xhr PUT /api/save"},
			},
			{
				name: "xhr_open_window_prefix",
				src: `
var xhr = new window.XMLHttpRequest();
xhr.open('GET', '/api/g');
`,
				endpoints: []string{"xhr GET /api/g"},
			},
			{
				name: "xhr_open_assign",
				src: `
let xhr;
xhr = new XMLHttpRequest();
xhr.open('POST', '/api/p');
`,
				endpoints: []string{"xhr POST /api/p"},
			},
			{
				name: "open_without_xhr_binding",
				src:  `cache.open('GET', '/api/x');`,
				endpoints: []string{
					// /api/x is still picked up as a URL-shaped literal, but not as xhr.
					"literal  /api/x",
				},
			},
			{
				name: "open_mis_bound_xhr",
				src: `
let xhr = somethingElse();
xhr.open('GET', '/api/x');
`,
				endpoints: []string{
					"literal  /api/x",
				},
			},
			{
				name: "jquery_ajax_config",
				src:  `$.ajax({url: '/api/x', method: 'POST'});`,
				endpoints: []string{
					"jquery POST /api/x",
				},
			},
			{
				name: "websocket",
				src:  `new WebSocket('wss://example.com/ws');`,
				endpoints: []string{
					"websocket  wss://example.com/ws",
				},
			},
			{
				name:      "websocket_rejects_non_url",
				src:       `new WebSocket('notaurl');`,
				endpoints: nil,
			},
			{
				name: "websocket_rejects_relative",
				src:  `new WebSocket('/socket');`,
				// /socket is rejected as a WebSocket URL (no ws/wss scheme); the
				// token scan still picks it up as a generic literal.
				endpoints: []string{"literal  /socket"},
			},
			{
				name: "navigation_assign",
				src:  `window.location.href = '/login';`,
				endpoints: []string{
					"navigation  /login",
				},
			},
			{
				name: "location_assign_call",
				src:  `window.location.assign('/login');`,
				endpoints: []string{
					"navigation  /login",
				},
			},
			{
				name: "location_replace_bare",
				src:  `location.replace('/home');`,
				endpoints: []string{
					"navigation  /home",
				},
			},
			{
				name: "document_location_assign",
				src:  `document.location.assign('/d');`,
				endpoints: []string{
					"navigation  /d",
				},
			},
			{
				name: "globalthis_location_assign",
				src:  `globalThis.location.assign('/gt');`,
				endpoints: []string{
					"navigation  /gt",
				},
			},
			{
				name: "globalthis_location_href",
				src:  `globalThis.location.href = '/gt-href';`,
				endpoints: []string{
					"navigation  /gt-href",
				},
			},
			{
				name: "string_replace_not_navigation",
				src:  `var s = 'a'; s.replace('/x/y', 'z');`,
				endpoints: []string{
					// receiver is not a location object: /x/y is only a URL-shaped literal.
					"literal  /x/y",
				},
			},
			{
				name: "eventsource",
				src:  `new EventSource('/sse/stream');`,
				endpoints: []string{
					"eventsource  /sse/stream",
				},
			},
			{
				name: "send_beacon",
				src:  `navigator.sendBeacon('/analytics', data);`,
				endpoints: []string{
					"beacon POST /analytics",
				},
			},
			{
				name: "dynamic_import_relative",
				src:  `import('./routes/Foo.js');`,
				endpoints: []string{
					"import  ./routes/Foo.js",
				},
			},
			{
				name:      "dynamic_import_bare_module_rejected",
				src:       `import('lodash');`,
				endpoints: nil,
			},
			{
				name: "import_scripts",
				src:  `importScripts('/js/worker.js');`,
				endpoints: []string{
					"import  /js/worker.js",
				},
			},
			{
				name: "import_scripts_multiple",
				src:  `importScripts('a.js', 'b.js');`,
				endpoints: []string{
					"import  a.js",
					"import  b.js",
				},
			},
			{
				name: "template_literal_interpolation",
				src:  "fetch(`/api/users/${id}`);",
				endpoints: []string{
					"fetch  /api/users/${...}",
				},
			},
			{
				name: "url_literal_outside_sink",
				src:  `var endpoints = ['/api/foo', '/api/bar'];`,
				endpoints: []string{
					"literal  /api/foo",
					"literal  /api/bar",
				},
			},
			{
				name: "protocol_relative_url_literal",
				src:  `var s = "//cdn.example.com/bundle.js";`,
				endpoints: []string{
					"literal  //cdn.example.com/bundle.js",
				},
			},
			{
				name:      "bare_identifier_rejected",
				src:       `var x = 'foo'; var y = 'helloWorld';`,
				endpoints: nil,
			},
			{
				name:      "ignores_unrelated_string",
				src:       `var msg = 'hello world';`,
				endpoints: nil,
			},
			{
				name: "window_fetch",
				src:  `window.fetch('/api/global');`,
				endpoints: []string{
					"fetch  /api/global",
				},
			},
			{
				name: "globalthis_websocket",
				src:  `new globalThis.WebSocket('wss://a/b');`,
				endpoints: []string{
					"websocket  wss://a/b",
				},
			},
			{
				name: "self_websocket",
				src:  `new self.WebSocket('wss://x/y');`,
				endpoints: []string{
					"websocket  wss://x/y",
				},
			},
			{
				name: "relative_path_accepted",
				src:  `fetch('api/x');`,
				endpoints: []string{
					"fetch  api/x",
				},
			},
			{
				name: "dot_relative_path_accepted",
				src:  `axios.get('./api/x');`,
				endpoints: []string{
					"axios GET ./api/x",
				},
			},
			{
				name:      "non_url_literal_rejected",
				src:       `fetch('hello world'); axios.get('translation.key');`,
				endpoints: nil,
			},
			{
				name: "array_push_not_route",
				src:  `var a = []; a.push('/x/y');`,
				endpoints: []string{
					"literal  /x/y",
				},
			},
			{
				name: "history_push_with_import",
				src: `
import { useHistory } from 'react-router-dom';
const history = useHistory();
history.push('/login');
`,
				routes: []string{
					"/login",
				},
			},
			{
				name: "navigate_call_with_import",
				src: `
import { useNavigate } from 'react-router';
const navigate = useNavigate();
navigate('/dashboard');
`,
				routes: []string{
					"/dashboard",
				},
			},
			{
				name: "router_push_vue_with_import",
				src: `
import { useRouter } from 'vue-router';
const router = useRouter();
router.push('/users');
`,
				routes: []string{
					"/users",
				},
			},
			{
				name: "bare_history_push_rejected",
				src:  `history.push('/login');`,
				endpoints: []string{
					// Without router-library evidence, the path is only a URL-shaped literal.
					"literal  /login",
				},
			},
			{
				name: "create_browser_router",
				src: `
const r = createBrowserRouter([
  { path: '/home', element: H },
  { path: '/about', element: A },
]);
`,
				routes: []string{"/home", "/about"},
			},
			{
				name: "create_hash_router",
				src:  `createHashRouter([{path:'/h'}]);`,
				routes: []string{
					"/h",
				},
			},
			{
				name: "vue_router_config",
				src: `
const r = createRouter({
  routes: [
    { path: '/v1' },
    { path: '/v2' },
  ],
});
`,
				routes: []string{"/v1", "/v2"},
			},
			{
				name: "vue_router_constructor",
				src:  `new VueRouter({ routes: [{ path: '/vv' }] });`,
				routes: []string{
					"/vv",
				},
			},
			{
				name:   "angular_route_config",
				src:    `RouterModule.forRoot([{ path: '/ang1' }, { path: '/ang2' }]);`,
				routes: []string{"/ang1", "/ang2"},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				r := AnalyzeJS([]byte(tc.src))

				var gotEndpoints []string
				for _, e := range r.Endpoints {
					gotEndpoints = append(gotEndpoints, e.Library+" "+e.Method+" "+e.URL)
				}
				assert.ElementsMatch(t, tc.endpoints, gotEndpoints)

				var gotRoutes []string
				for _, rt := range r.Routes {
					gotRoutes = append(gotRoutes, rt.Path)
				}
				assert.ElementsMatch(t, tc.routes, gotRoutes)
			})
		}
	})

	t.Run("modern_syntax", func(t *testing.T) {
		src := `
class C {
  #x = 1n;
  m() { return this.#x ?? 0; }
}
const a = b?.c ?? d;
e ||= f;
import('./mod').then(m => m.run());
fetch('/api/modern');
`
		r := AnalyzeJS([]byte(src))
		assert.Equal(t, 0, r.ParseErrors)
		var fetchURLs []string
		for _, e := range r.Endpoints {
			if e.Library == libFetch {
				fetchURLs = append(fetchURLs, e.URL)
			}
		}
		assert.Equal(t, []string{"/api/modern"}, fetchURLs)
	})

	t.Run("partial_on_parse_error", func(t *testing.T) {
		src := `fetch('/api/before'); function (`
		r := AnalyzeJS([]byte(src))
		assert.Positive(t, r.ParseErrors)
		assert.NotEmpty(t, r.Warnings)
		urls := make([]string, 0, len(r.Endpoints))
		for _, e := range r.Endpoints {
			urls = append(urls, e.URL)
		}
		assert.Contains(t, urls, "/api/before")
	})

	t.Run("dedupes_endpoints", func(t *testing.T) {
		src := `
fetch('/api/x');
fetch('/api/x');
axios.get('/api/x');
`
		r := AnalyzeJS([]byte(src))
		urls := make([]string, 0, len(r.Endpoints))
		for _, e := range r.Endpoints {
			urls = append(urls, e.Library+" "+e.Method+" "+e.URL)
		}
		assert.ElementsMatch(t, []string{
			"fetch  /api/x",
			"axios GET /api/x",
		}, urls)
	})

	t.Run("literal_yields_to_call_site", func(t *testing.T) {
		// Same URL appears as a fetch call site AND as a literal in an array.
		// The endpoint should keep the richer "fetch" library label, not "literal".
		src := `
fetch('/api/x');
var endpoints = ['/api/x', '/api/y'];
`
		r := AnalyzeJS([]byte(src))
		libByURL := map[string]string{}
		for _, e := range r.Endpoints {
			libByURL[e.URL] = e.Library
		}
		assert.Equal(t, libFetch, libByURL["/api/x"])
		assert.Equal(t, libLiteral, libByURL["/api/y"])
	})

	t.Run("cross_collection_dedup", func(t *testing.T) {
		src := `
import { useHistory } from 'react-router';
const history = useHistory();
fetch('/api/x');
new WebSocket('wss://example/socket');
history.push('/route-x');
var also = ['/api/x', '/route-x', '/lone'];
`
		r := AnalyzeJS([]byte(src))

		libByURL := map[string]string{}
		for _, e := range r.Endpoints {
			libByURL[e.URL] = e.Library
		}
		assert.Equal(t, libFetch, libByURL["/api/x"])
		assert.Equal(t, libWebSocket, libByURL["wss://example/socket"])
		assert.Equal(t, libLiteral, libByURL["/lone"])
		_, hasRouteAsEndpoint := libByURL["/route-x"]
		assert.False(t, hasRouteAsEndpoint)
	})

	t.Run("source_map_comment", func(t *testing.T) {
		src := `var x=1;
//# sourceMappingURL=app.js.map
`
		r := AnalyzeJS([]byte(src))
		assert.Equal(t, []string{"app.js.map"}, r.SourceMaps)
	})

	t.Run("bare_location_href_assignment", func(t *testing.T) {
		src := `location.href = "https://x.example/y";`
		r := AnalyzeJS([]byte(src))

		var navURLs []string
		for _, e := range r.Endpoints {
			if e.Library == libNavigation {
				navURLs = append(navURLs, e.URL)
			}
		}
		assert.Equal(t, []string{"https://x.example/y"}, navURLs)
	})

	t.Run("fetch_with_escaped_slashes", func(t *testing.T) {
		src := `fetch("\/api\/users\/123");`
		r := AnalyzeJS([]byte(src))

		var fetched []string
		for _, e := range r.Endpoints {
			if e.Library == libFetch {
				fetched = append(fetched, e.URL)
			}
		}
		assert.Equal(t, []string{"/api/users/123"}, fetched)
	})

	t.Run("sets_source_label", func(t *testing.T) {
		r := AnalyzeJS([]byte(`var x = 1;`))
		assert.Equal(t, SourceJavaScript, r.Source)
	})

	t.Run("counts_script_block", func(t *testing.T) {
		r := AnalyzeJS([]byte(`var x = 1;`))
		assert.Equal(t, 1, r.ScriptBlocks)
	})

	t.Run("empty_body", func(t *testing.T) {
		r := AnalyzeJS(nil)
		assert.Equal(t, SourceJavaScript, r.Source)
		assert.Equal(t, 0, r.ScriptBlocks)
		assert.Empty(t, r.Endpoints)
	})
}

func TestAnalyzeHTML(t *testing.T) {
	t.Parallel()

	t.Run("inline_and_external", func(t *testing.T) {
		src := `<html><head>
<script src="https://cdn.example/app.js"></script>
<script type="application/ld+json">{"ignored":"yes","url":"/skip"}</script>
<script>
  fetch('/api/from-inline');
  new WebSocket('wss://ws.example/socket');
</script>
</head></html>`

		r := AnalyzeHTML([]byte(src))
		assert.Equal(t, SourceHTMLInline, r.Source)
		assert.Equal(t, []string{"https://cdn.example/app.js"}, r.ExternalScripts)

		var fetched, socketed []string
		for _, e := range r.Endpoints {
			switch e.Library {
			case libFetch:
				fetched = append(fetched, e.URL)
			case libWebSocket:
				socketed = append(socketed, e.URL)
			}
		}
		assert.Contains(t, fetched, "/api/from-inline")
		for _, e := range r.Endpoints {
			assert.NotEqual(t, "/skip", e.URL)
		}
		assert.Equal(t, []string{"wss://ws.example/socket"}, socketed)
	})

	t.Run("only_external_scripts", func(t *testing.T) {
		src := `<html><head>
<script src="/a.js"></script>
<script src="/b.js"></script>
</head></html>`
		r := AnalyzeHTML([]byte(src))
		assert.Equal(t, SourceHTML, r.Source)
		assert.Equal(t, []string{"/a.js", "/b.js"}, r.ExternalScripts)
		assert.Empty(t, r.Endpoints)
	})

	t.Run("no_scripts", func(t *testing.T) {
		r := AnalyzeHTML([]byte(`<html><body><p>hi</p></body></html>`))
		assert.Equal(t, SourceHTML, r.Source)
		assert.Empty(t, r.ExternalScripts)
		assert.Empty(t, r.Endpoints)
	})

	t.Run("multiple_inline_blocks", func(t *testing.T) {
		src := `<html><head>
<script>fetch('/a');</script>
<script>fetch('/b');</script>
</head></html>`
		r := AnalyzeHTML([]byte(src))
		assert.Equal(t, SourceHTMLInline, r.Source)
		assert.Equal(t, 2, r.ScriptBlocks)
		var fetched []string
		for _, e := range r.Endpoints {
			if e.Library == libFetch {
				fetched = append(fetched, e.URL)
			}
		}
		assert.ElementsMatch(t, []string{"/a", "/b"}, fetched)
	})
}

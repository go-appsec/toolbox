package js

import (
	"cmp"
	"net/url"
	"slices"
	"strings"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/toolbox/sectool/protocol"
)

// dedupeExtracted collapses duplicate endpoints and routes.
// For endpoints sharing method+url, a concrete call site is preferred over a bare literal.
func dedupeExtracted(in Extracted) Extracted {
	return Extracted{
		Endpoints:  dedupeEndpoints(in.Endpoints),
		Routes:     dedupeRoutes(in.Routes),
		SourceMaps: dedupeStrings(in.SourceMaps),
	}
}

func dedupeEndpoints(eps []protocol.ExtractedEndpoint) []protocol.ExtractedEndpoint {
	type key struct{ method, url string }
	seen := make(map[key]int, len(eps))
	out := make([]protocol.ExtractedEndpoint, 0, len(eps))
	for _, e := range eps {
		k := key{e.Method, e.URL}
		if idx, ok := seen[k]; ok {
			if out[idx].Library == libLiteral && e.Library != libLiteral {
				out[idx] = e
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, e)
	}
	slices.SortStableFunc(out, func(a, b protocol.ExtractedEndpoint) int {
		return cmp.Or(cmp.Compare(a.URL, b.URL), cmp.Compare(a.Method, b.Method))
	})
	return out
}

func dedupe[T comparable](in []T) []T {
	if len(in) == 0 {
		return in
	}
	m := bulk.SliceToSet(in)
	if len(m) == len(in) {
		return in
	}
	out := bulk.MapKeysSlice(m)
	return out
}

func dedupeRoutes(rs []protocol.ExtractedRoute) []protocol.ExtractedRoute {
	out := dedupe(rs)
	slices.SortStableFunc(out, func(a, b protocol.ExtractedRoute) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Framework, b.Framework))
	})
	return out
}

func dedupeStrings(in []string) []string {
	out := dedupe(in)
	slices.Sort(out)
	return out
}

// dedupeSecrets returns secrets with duplicate (kind, value) pairs removed, sorted by kind then value.
func dedupeSecrets(in []protocol.ExtractedSecret) []protocol.ExtractedSecret {
	out := dedupe(in)
	slices.SortStableFunc(out, func(a, b protocol.ExtractedSecret) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Value, b.Value))
	})
	return out
}

// ClassifyURL returns the host and path+query of an HTTP-shaped URL, or ("", "") for unsupported shapes.
// Fragments are dropped.
func ClassifyURL(rawURL string) (host, path string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", ""
	}
	switch u.Scheme {
	case "", "http", "https":
		host = u.Host
	default:
		return "", ""
	}
	path = u.EscapedPath()
	if path == "" && host != "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "", ""
	}
	if u.RawQuery != "" {
		path = path + "?" + u.RawQuery
	}
	return host, path
}

// StripQuery returns p with the query string removed.
func StripQuery(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

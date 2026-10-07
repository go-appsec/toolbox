package sidecar

import "regexp"

// QuotePattern escapes RE2 metacharacters so p matches literally inside a larger
// claim or rule regex. Plain hostnames and paths need no quoting: claim
// compilation treats a pattern with no metacharacters beyond '.' as a literal.
func QuotePattern(p string) string {
	return regexp.QuoteMeta(p)
}

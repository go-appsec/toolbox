// Package dedupe provides small order-preserving deduplication helpers.
package dedupe

// Slice returns s with duplicate values removed, preserving first-seen order.
func Slice[T comparable](s []T) []T {
	if len(s) < 2 {
		return s
	}
	seen := make(map[T]struct{}, len(s))
	out := make([]T, 0, len(s))
	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

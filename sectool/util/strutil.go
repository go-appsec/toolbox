package util

// TruncateString ensures the returned string is at most the maxLen characters,
// truncating and adding a "..." suffix if necessary.
func TruncateString(str string, maxLen int) string {
	if len(str) <= maxLen || maxLen < 2 {
		return str
	}
	return str[:maxLen-2] + ".."
}

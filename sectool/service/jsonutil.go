package service

import (
	"encoding/json"
	"fmt"
	"strings"
)

// parseStringList parses a JSON array or comma-separated list into a slice.
func parseStringList(s string) []string {
	if s == "" {
		return nil
	}
	trimmed := strings.TrimSpace(s)
	if len(trimmed) > 1 && trimmed[0] == '[' {
		var arr []string
		if json.Unmarshal([]byte(trimmed), &arr) == nil {
			return arr
		}
	}
	return parseCommaSeparated(s)
}

// flattenJSON flattens a JSON value into a map of dot-notation paths to leaf values.
func flattenJSON(prefix string, data interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	switch v := data.(type) {
	case map[string]interface{}:
		if len(v) == 0 {
			result[prefix] = v
			return result
		}
		for key, val := range v {
			var childPrefix string
			if prefix == "" {
				childPrefix = key
			} else {
				childPrefix = prefix + "." + key
			}
			for p, leaf := range flattenJSON(childPrefix, val) {
				result[p] = leaf
			}
		}
	case []interface{}:
		if len(v) == 0 {
			result[prefix] = v
			return result
		}
		for i, val := range v {
			childPrefix := fmt.Sprintf("%s[%d]", prefix, i)
			for p, leaf := range flattenJSON(childPrefix, val) {
				result[p] = leaf
			}
		}
	default:
		result[prefix] = v
	}

	return result
}

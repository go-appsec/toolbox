package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// jsonPathRe matches path segments: key names or [index]
var jsonPathRe = regexp.MustCompile(`([^.\[\]]+)|\[(\d+)\]`)

// modifyJSONBody applies JSON modifications to the body.
// Returns error if body is not valid JSON.
func modifyJSONBody(body []byte, setJSON, removeJSON []string) ([]byte, error) {
	if len(setJSON) == 0 && len(removeJSON) == 0 {
		return body, nil
	}

	if len(body) == 0 {
		body = []byte("{}")
	}

	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("body is not valid JSON: %w (hint: export bundle and edit body.bin directly)", err)
	}

	for _, keyPath := range removeJSON {
		segments, err := parseJSONPath(keyPath)
		if err != nil {
			return nil, fmt.Errorf("--remove-json %q: %w", keyPath, err)
		}
		data, err = removeKeyAtPath(data, segments)
		if err != nil {
			return nil, fmt.Errorf("--remove-json %q: %w", keyPath, err)
		}
	}

	for _, kv := range setJSON {
		keyPath, valueStr, hasValue := strings.Cut(kv, "=")
		var value interface{}
		if !hasValue {
			value = nil // no "=" means set to null
		} else {
			value = inferJSONValue(valueStr)
		}
		segments, err := parseJSONPath(keyPath)
		if err != nil {
			return nil, fmt.Errorf("--set-json %q: %w", keyPath, err)
		}
		data, err = setValueAtPath(data, segments, value)
		if err != nil {
			return nil, fmt.Errorf("--set-json %q: %w", keyPath, err)
		}
	}

	return json.Marshal(data)
}

// inferJSONValue infers the JSON type from a string value.
// Priority: null, bool, number, JSON object/array, string
func inferJSONValue(s string) interface{} {
	if s == "null" {
		return nil
	}
	if s == "true" {
		return true
	}
	if s == "false" {
		return false
	}

	// Try number
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		// Verify it round-trips to avoid precision issues
		formatted := strconv.FormatFloat(f, 'f', -1, 64)
		formattedG := strconv.FormatFloat(f, 'g', -1, 64)
		if formatted == s || formattedG == s {
			return f
		}
		// Handle scientific notation (1e10 vs 1e+10)
		if strings.ContainsAny(s, "eE") {
			normalized := strings.ReplaceAll(strings.ToLower(s), "e+", "e")
			formattedNorm := strings.ReplaceAll(strings.ToLower(formattedG), "e+", "e")
			if normalized == formattedNorm {
				return f
			}
		}
	}

	// Try JSON object or array
	if len(s) >= 2 && ((s[0] == '{' && s[len(s)-1] == '}') || (s[0] == '[' && s[len(s)-1] == ']')) {
		var parsed interface{}
		if err := json.Unmarshal([]byte(s), &parsed); err == nil {
			return parsed
		}
	}

	return s
}

// pathSegment represents a single segment in a JSON path.
type pathSegment struct {
	Key   string // for object access
	Index int    // for array access (-1 means key access)
}

// parseJSONPath parses a dot-notation path into segments.
// Examples:
//   - "user" -> [{Key: "user", Index: -1}]
//   - "user.email" -> [{Key: "user", Index: -1}, {Key: "email", Index: -1}]
//   - "items[0]" -> [{Key: "items", Index: -1}, {Index: 0}]
//   - "data.items[0].name" -> [{Key: "data"}, {Key: "items"}, {Index: 0}, {Key: "name"}]
func parseJSONPath(path string) ([]pathSegment, error) {
	if path == "" {
		return nil, errors.New("empty path")
	}

	var segments []pathSegment
	matches := jsonPathRe.FindAllStringSubmatch(path, -1)

	if len(matches) == 0 {
		return nil, fmt.Errorf("invalid path: %q", path)
	}

	for _, m := range matches {
		if m[1] != "" { // Key segment
			segments = append(segments, pathSegment{Key: m[1], Index: -1})
		} else if m[2] != "" { // Index segment
			idx, err := strconv.Atoi(m[2])
			if err != nil {
				return nil, fmt.Errorf("invalid array index in path: %q", path)
			}
			segments = append(segments, pathSegment{Index: idx})
		}
	}

	return segments, nil
}

// setValueAtPath recursively sets a value at the path.
func setValueAtPath(data interface{}, segments []pathSegment, value interface{}) (interface{}, error) {
	if len(segments) == 0 {
		return value, nil
	}

	seg := segments[0]
	remaining := segments[1:]
	if seg.Index >= 0 {
		// Array access
		arr, ok := data.([]interface{})
		if !ok {
			// Create new array if data is nil or not an array
			if data == nil {
				arr = make([]interface{}, 0)
			} else {
				return nil, fmt.Errorf("expected array at index [%d], got %T", seg.Index, data)
			}
		}

		// Extend array if needed (append if index == len)
		for len(arr) <= seg.Index {
			arr = append(arr, nil)
		}

		if len(remaining) == 0 {
			arr[seg.Index] = value
		} else {
			newVal, err := setValueAtPath(arr[seg.Index], remaining, value)
			if err != nil {
				return nil, err
			}
			arr[seg.Index] = newVal
		}
		return arr, nil
	}

	// Object access
	obj, ok := data.(map[string]interface{})
	if !ok {
		// Create new object if data is nil or not an object
		if data == nil {
			obj = make(map[string]interface{})
		} else {
			return nil, fmt.Errorf("expected object at key %q, got %T", seg.Key, data)
		}
	}

	if len(remaining) == 0 {
		obj[seg.Key] = value
	} else {
		existing := obj[seg.Key]
		newVal, err := setValueAtPath(existing, remaining, value)
		if err != nil {
			return nil, err
		}
		obj[seg.Key] = newVal
	}
	return obj, nil
}

// removeKeyAtPath recursively removes a key at the path.
func removeKeyAtPath(data interface{}, segments []pathSegment) (interface{}, error) {
	if len(segments) == 0 {
		return data, nil
	}

	seg := segments[0]
	remaining := segments[1:]
	if seg.Index >= 0 {
		// Array access
		arr, ok := data.([]interface{})
		if !ok || seg.Index >= len(arr) {
			// Key doesn't exist, nothing to remove
			return data, nil
		}

		if len(remaining) == 0 {
			// Remove element from array
			return append(arr[:seg.Index], arr[seg.Index+1:]...), nil
		}

		newVal, err := removeKeyAtPath(arr[seg.Index], remaining)
		if err != nil {
			return nil, err
		}
		arr[seg.Index] = newVal
		return arr, nil
	}

	// Object access
	obj, ok := data.(map[string]interface{})
	if !ok {
		// Key doesn't exist, nothing to remove
		return data, nil
	}

	if len(remaining) == 0 {
		delete(obj, seg.Key)
	} else if existing, exists := obj[seg.Key]; exists {
		newVal, err := removeKeyAtPath(existing, remaining)
		if err != nil {
			return nil, err
		}
		obj[seg.Key] = newVal
	}
	return obj, nil
}

package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlattenJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		prefix   string
		data     interface{}
		expected map[string]interface{}
	}{
		{
			name: "flat_object",
			data: map[string]interface{}{"a": float64(1), "b": "two"},
			expected: map[string]interface{}{
				"a": float64(1),
				"b": "two",
			},
		},
		{
			name: "nested_object",
			data: map[string]interface{}{
				"user": map[string]interface{}{"name": "alice"},
			},
			expected: map[string]interface{}{
				"user.name": "alice",
			},
		},
		{
			name: "array_values",
			data: map[string]interface{}{
				"items": []interface{}{float64(1), float64(2)},
			},
			expected: map[string]interface{}{
				"items[0]": float64(1),
				"items[1]": float64(2),
			},
		},
		{
			name: "mixed_nesting",
			data: map[string]interface{}{
				"data": map[string]interface{}{
					"items": []interface{}{
						map[string]interface{}{"name": "a"},
					},
				},
			},
			expected: map[string]interface{}{
				"data.items[0].name": "a",
			},
		},
		{
			name:     "empty_object",
			data:     map[string]interface{}{},
			expected: map[string]interface{}{"": map[string]interface{}{}},
		},
		{
			name: "empty_nested_array",
			data: map[string]interface{}{
				"items": []interface{}{},
			},
			expected: map[string]interface{}{
				"items": []interface{}{},
			},
		},
		{
			name: "null_value",
			data: map[string]interface{}{"key": nil},
			expected: map[string]interface{}{
				"key": nil,
			},
		},
		{
			name:   "with_prefix",
			prefix: "root",
			data:   map[string]interface{}{"a": float64(1)},
			expected: map[string]interface{}{
				"root.a": float64(1),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, flattenJSON(tc.prefix, tc.data))
		})
	}
}

func TestParseStringList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"json_array", `["a","b","c"]`, []string{"a", "b", "c"}},
		{"json_array_spaces", ` ["a", "b"] `, []string{"a", "b"}},
		{"comma_fallback", "a,b,c", []string{"a", "b", "c"}},
		{"single_value", "abc", []string{"abc"}},
		{"empty", "", nil},
		{"invalid_json_array", `["a","b"`, []string{`["a"`, `"b"`}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseStringList(tt.input))
		})
	}
}

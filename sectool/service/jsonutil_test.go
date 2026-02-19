package service

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInferJSONValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected interface{}
	}{
		{"null", "null", nil},
		{"true", "true", true},
		{"false", "false", false},
		{"integer", "123", float64(123)},
		{"float", "123.45", float64(123.45)},
		{"negative", "-42", float64(-42)},
		{"zero", "0", float64(0)},
		{"string", "hello", "hello"},
		{"empty", "", ""},
		{"case_true", "True", "True"},    // case-sensitive
		{"case_false", "FALSE", "FALSE"}, // case-sensitive
		{"mixed", "12abc", "12abc"},      // not a number
		{"scientific", "1e10", float64(1e10)},
		{"large_int_string", "9999999999999999999", "9999999999999999999"}, // preserves precision
		{"leading_zeros", "00123", "00123"},                                // preserves formatting
		{"json_object", `{"a":1}`, map[string]interface{}{"a": float64(1)}},
		{"json_array", `[1,2,3]`, []interface{}{float64(1), float64(2), float64(3)}},
		{"nested_object", `{"user":{"name":"test"}}`, map[string]interface{}{"user": map[string]interface{}{"name": "test"}}},
		{"invalid_json_obj", `{not json}`, `{not json}`}, // falls back to string
		{"invalid_json_arr", `[1,2,`, `[1,2,`},           // falls back to string
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, inferJSONValue(tc.input))
		})
	}
}

func TestParseJSONPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		path     string
		expected []pathSegment
		wantErr  bool
	}{
		{
			name:     "simple_key",
			path:     "user",
			expected: []pathSegment{{Key: "user", Index: -1}},
		},
		{
			name:     "nested_keys",
			path:     "user.email",
			expected: []pathSegment{{Key: "user", Index: -1}, {Key: "email", Index: -1}},
		},
		{
			name:     "array_index",
			path:     "items[0]",
			expected: []pathSegment{{Key: "items", Index: -1}, {Index: 0}},
		},
		{
			name:     "complex_path",
			path:     "data.items[0].name",
			expected: []pathSegment{{Key: "data", Index: -1}, {Key: "items", Index: -1}, {Index: 0}, {Key: "name", Index: -1}},
		},
		{
			name:     "multiple_arrays",
			path:     "matrix[0][1]",
			expected: []pathSegment{{Key: "matrix", Index: -1}, {Index: 0}, {Index: 1}},
		},
		{
			name:     "bare_array_index",
			path:     "[0]",
			expected: []pathSegment{{Index: 0}},
		},
		{
			name:     "key_with_hyphen",
			path:     "content-type",
			expected: []pathSegment{{Key: "content-type", Index: -1}},
		},
		{
			name:     "key_with_underscore",
			path:     "user_id",
			expected: []pathSegment{{Key: "user_id", Index: -1}},
		},
		{
			name:    "empty_path",
			path:    "",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parseJSONPath(tc.path)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestModifyJSONBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		setJSON    []string
		removeJSON []string
		expected   string
		wantErr    bool
		rawCompare bool // compare raw output bytes instead of parsed JSON
	}{
		// Set operations
		{
			name:     "set_simple_key",
			input:    `{"name":"old"}`,
			setJSON:  []string{"name=new"},
			expected: `{"name":"new"}`,
		},
		{
			name:     "add_new_key",
			input:    `{"a":1}`,
			setJSON:  []string{"b=2"},
			expected: `{"a":1,"b":2}`,
		},
		{
			name:     "nested_set",
			input:    `{"user":{"name":"old"}}`,
			setJSON:  []string{"user.name=new"},
			expected: `{"user":{"name":"new"}}`,
		},
		{
			name:     "nested_path_create",
			input:    `{}`,
			setJSON:  []string{"user.email=test@evil.com"},
			expected: `{"user":{"email":"test@evil.com"}}`,
		},
		{
			name:     "set_nested_in_array",
			input:    `{"users":[{"name":"alice"},{"name":"bob"}]}`,
			setJSON:  []string{"users[1].name=BOB"},
			expected: `{"users":[{"name":"alice"},{"name":"BOB"}]}`,
		},
		{
			name:     "array_index_set",
			input:    `{"items":["a","b","c"]}`,
			setJSON:  []string{"items[1]=replaced"},
			expected: `{"items":["a","replaced","c"]}`,
		},
		{
			name:     "append_array",
			input:    `{"items":["a","b"]}`,
			setJSON:  []string{"items[2]=c"},
			expected: `{"items":["a","b","c"]}`,
		},
		{
			name:     "extend_array",
			input:    `{"items":[]}`,
			setJSON:  []string{"items[2]=c"},
			expected: `{"items":[null,null,"c"]}`,
		},
		// Remove operations
		{
			name:       "remove_simple",
			input:      `{"a":1,"b":2}`,
			removeJSON: []string{"a"},
			expected:   `{"b":2}`,
		},
		{
			name:       "remove_nested",
			input:      `{"user":{"name":"alice","email":"a@b.com"}}`,
			removeJSON: []string{"user.email"},
			expected:   `{"user":{"name":"alice"}}`,
		},
		{
			name:       "remove_array_element",
			input:      `{"items":["a","b","c"]}`,
			removeJSON: []string{"items[1]"},
			expected:   `{"items":["a","c"]}`,
		},
		{
			name:       "remove_nonexistent",
			input:      `{"a":1}`,
			removeJSON: []string{"b"},
			expected:   `{"a":1}`,
		},
		{
			name:       "remove_array_field",
			input:      `{"users":[{"name":"alice","age":30}]}`,
			removeJSON: []string{"users[0].age"},
			expected:   `{"users":[{"name":"alice"}]}`,
		},
		// Combined operations
		{
			name:       "combined_operations",
			input:      `{"old":"value","keep":"this"}`,
			removeJSON: []string{"old"},
			setJSON:    []string{"new=added"},
			expected:   `{"keep":"this","new":"added"}`,
		},
		{
			name:     "multiple_sets",
			input:    `{}`,
			setJSON:  []string{"a=1", "b=two", "c=true"},
			expected: `{"a":1,"b":"two","c":true}`,
		},
		// Type inference
		{
			name:     "infer_string",
			input:    `{}`,
			setJSON:  []string{"name=hello"},
			expected: `{"name":"hello"}`,
		},
		{
			name:     "infer_number",
			input:    `{}`,
			setJSON:  []string{"count=42"},
			expected: `{"count":42}`,
		},
		{
			name:     "infer_bool",
			input:    `{}`,
			setJSON:  []string{"active=true"},
			expected: `{"active":true}`,
		},
		{
			name:     "infer_null_explicit",
			input:    `{}`,
			setJSON:  []string{"value=null"},
			expected: `{"value":null}`,
		},
		{
			name:     "null_no_equals",
			input:    `{"existing":"value"}`,
			setJSON:  []string{"deleted_at"},
			expected: `{"existing":"value","deleted_at":null}`,
		},
		{
			name:     "overwrite_with_null",
			input:    `{"key":"value"}`,
			setJSON:  []string{"key"},
			expected: `{"key":null}`,
		},
		{
			name:     "infer_json_object",
			input:    `{}`,
			setJSON:  []string{`nested={"a":1,"b":2}`},
			expected: `{"nested":{"a":1,"b":2}}`,
		},
		{
			name:     "infer_json_array",
			input:    `{}`,
			setJSON:  []string{`items=[1,2,3]`},
			expected: `{"items":[1,2,3]}`,
		},
		// Encoded JSON strings
		{
			name:     "set_encoded_object",
			input:    `{"user": "{\"email\": \"old@test.com\"}"}`,
			setJSON:  []string{"user.email=new@test.com"},
			expected: `{"user":"{\"email\":\"new@test.com\"}"}`,
		},
		{
			name:     "add_encoded_field",
			input:    `{"user": "{\"email\": \"a@test.com\"}"}`,
			setJSON:  []string{"user.name=Bob"},
			expected: `{"user":"{\"email\":\"a@test.com\",\"name\":\"Bob\"}"}`,
		},
		{
			name:     "set_encoded_array",
			input:    `{"items": "[1,2,3]"}`,
			setJSON:  []string{"items[1]=99"},
			expected: `{"items":"[1,99,3]"}`,
		},
		{
			name:     "double_encoded_set",
			input:    `{"outer": "{\"inner\": \"{\\\"deep\\\": \\\"old\\\"}\"}"}`,
			setJSON:  []string{"outer.inner.deep=new"},
			expected: `{"outer":"{\"inner\":\"{\\\"deep\\\":\\\"new\\\"}\"}"}`,
		},
		{
			name:       "remove_encoded_field",
			input:      `{"user": "{\"a\":1,\"b\":2}"}`,
			removeJSON: []string{"user.b"},
			expected:   `{"user":"{\"a\":1}"}`,
		},
		{
			name:       "remove_encoded_array",
			input:      `{"items": "[1,2,3]"}`,
			removeJSON: []string{"items[1]"},
			expected:   `{"items":"[1,3]"}`,
		},
		{
			name:       "remove_double_encoded",
			input:      `{"outer": "{\"inner\": \"{\\\"a\\\": 1, \\\"b\\\": 2}\"}"}`,
			removeJSON: []string{"outer.inner.b"},
			expected:   `{"outer":"{\"inner\":\"{\\\"a\\\":1}\"}"}`,
		},
		// No HTML escaping (raw byte comparison)
		{
			name:       "angle_brackets",
			input:      `{}`,
			setJSON:    []string{`xss=<script>alert(1)</script>`},
			expected:   `{"xss":"<script>alert(1)</script>"}`,
			rawCompare: true,
		},
		{
			name:       "ampersand",
			input:      `{}`,
			setJSON:    []string{`q=a&b=c`},
			expected:   `{"q":"a&b=c"}`,
			rawCompare: true,
		},
		{
			name:       "nested_html",
			input:      `{"data":"{}"}`,
			setJSON:    []string{`data.tag=<img src=x>`},
			expected:   `{"data":"{\"tag\":\"<img src=x>\"}"}`,
			rawCompare: true,
		},
		// Edge cases
		{
			name:     "value_with_equals",
			input:    `{}`,
			setJSON:  []string{"url=https://example.com?a=b&c=d"},
			expected: `{"url":"https://example.com?a=b&c=d"}`,
		},
		{
			name:     "empty_value",
			input:    `{}`,
			setJSON:  []string{"empty="},
			expected: `{"empty":""}`,
		},
		{
			name:     "root_level_array",
			input:    `[1,2,3]`,
			setJSON:  []string{"[1]=replaced"},
			expected: `[1,"replaced",3]`,
		},
		{
			name:     "empty_body_creates_object",
			input:    ``,
			setJSON:  []string{"key=value"},
			expected: `{"key":"value"}`,
		},
		{
			name:     "no_modifications",
			input:    `{"unchanged": true}`,
			expected: `{"unchanged": true}`,
		},
		// Error cases
		{
			name:    "invalid_json_body",
			input:   `not valid json`,
			setJSON: []string{"key=value"},
			wantErr: true,
		},
		{
			name:    "invalid_encoded_json",
			input:   `{"data": "{not valid}"}`,
			setJSON: []string{"data.field=x"},
			wantErr: true,
		},
		{
			name:    "plain_string_error",
			input:   `{"data": "just text"}`,
			setJSON: []string{"data.field=x"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := modifyJSONBody([]byte(tc.input), tc.setJSON, tc.removeJSON)

			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			if tc.rawCompare {
				assert.Equal(t, tc.expected, string(result))
				return
			}

			var expectedVal, resultVal interface{}
			require.NoError(t, json.Unmarshal([]byte(tc.expected), &expectedVal))
			require.NoError(t, json.Unmarshal(result, &resultVal))
			assert.Equal(t, expectedVal, resultVal)
		})
	}
}

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

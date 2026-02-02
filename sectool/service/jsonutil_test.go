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

func TestSetJSONValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		path     string
		value    interface{}
		expected string
	}{
		{
			name:     "set_simple_key",
			input:    `{"name": "old"}`,
			path:     "name",
			value:    "new",
			expected: `{"name":"new"}`,
		},
		{
			name:     "add_new_key",
			input:    `{"a": 1}`,
			path:     "b",
			value:    2,
			expected: `{"a":1,"b":2}`,
		},
		{
			name:     "nested_set",
			input:    `{"user": {"name": "old"}}`,
			path:     "user.name",
			value:    "new",
			expected: `{"user":{"name":"new"}}`,
		},
		{
			name:     "create_nested",
			input:    `{}`,
			path:     "user.email",
			value:    "test@example.com",
			expected: `{"user":{"email":"test@example.com"}}`,
		},
		{
			name:     "set_array_element",
			input:    `{"items": ["a", "b", "c"]}`,
			path:     "items[1]",
			value:    "B",
			expected: `{"items":["a","B","c"]}`,
		},
		{
			name:     "append_array",
			input:    `{"items": ["a", "b"]}`,
			path:     "items[2]",
			value:    "c",
			expected: `{"items":["a","b","c"]}`,
		},
		{
			name:     "extend_array",
			input:    `{"items": []}`,
			path:     "items[2]",
			value:    "c",
			expected: `{"items":[null,null,"c"]}`,
		},
		{
			name:     "set_nested_in_array",
			input:    `{"users": [{"name": "alice"}, {"name": "bob"}]}`,
			path:     "users[1].name",
			value:    "BOB",
			expected: `{"users":[{"name":"alice"},{"name":"BOB"}]}`,
		},
		{
			name:     "set_null",
			input:    `{"key": "value"}`,
			path:     "key",
			value:    nil,
			expected: `{"key":null}`,
		},
		{
			name:     "empty_input",
			input:    ``,
			path:     "key",
			value:    "value",
			expected: `{"key":"value"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var input []byte
			if tc.input != "" {
				input = []byte(tc.input)
			}

			// Build the SetJSON value based on type
			var setVal string
			switch v := tc.value.(type) {
			case nil:
				setVal = tc.path // no "=" means null
			case string:
				setVal = tc.path + "=" + v
			default:
				setVal = tc.path + "=" + string(mustMarshal(t, v))
			}

			result, err := modifyJSONBody(input, []string{setVal}, nil)
			require.NoError(t, err)

			// Compare as parsed JSON to ignore ordering
			var expectedMap, resultMap interface{}
			require.NoError(t, json.Unmarshal([]byte(tc.expected), &expectedMap))
			require.NoError(t, json.Unmarshal(result, &resultMap))
			assert.Equal(t, expectedMap, resultMap)
		})
	}
}

func TestRemoveJSONKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		path     string
		expected string
	}{
		{
			name:     "remove_simple",
			input:    `{"a": 1, "b": 2}`,
			path:     "a",
			expected: `{"b":2}`,
		},
		{
			name:     "remove_nested",
			input:    `{"user": {"name": "alice", "email": "a@b.com"}}`,
			path:     "user.email",
			expected: `{"user":{"name":"alice"}}`,
		},
		{
			name:     "remove_array_element",
			input:    `{"items": ["a", "b", "c"]}`,
			path:     "items[1]",
			expected: `{"items":["a","c"]}`,
		},
		{
			name:     "remove_nonexistent",
			input:    `{"a": 1}`,
			path:     "b",
			expected: `{"a":1}`,
		},
		{
			name:     "remove_from_array_object",
			input:    `{"users": [{"name": "alice", "age": 30}]}`,
			path:     "users[0].age",
			expected: `{"users":[{"name":"alice"}]}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := modifyJSONBody([]byte(tc.input), nil, []string{tc.path})
			require.NoError(t, err)

			var expectedMap, resultMap interface{}
			require.NoError(t, json.Unmarshal([]byte(tc.expected), &expectedMap))
			require.NoError(t, json.Unmarshal(result, &resultMap))
			assert.Equal(t, expectedMap, resultMap)
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
	}{
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
			input:    `{"existing": "value"}`,
			setJSON:  []string{"deleted_at"},
			expected: `{"existing":"value","deleted_at":null}`,
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
		{
			name:     "infer_nested_object",
			input:    `{}`,
			setJSON:  []string{`config={"debug":true,"level":5}`},
			expected: `{"config":{"debug":true,"level":5}}`,
		},
		{
			name:       "combined_operations",
			input:      `{"old": "value", "keep": "this"}`,
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
		{
			name:     "nested_path_create",
			input:    `{}`,
			setJSON:  []string{"user.email=test@evil.com"},
			expected: `{"user":{"email":"test@evil.com"}}`,
		},
		{
			name:     "array_index_set",
			input:    `{"items":["a","b","c"]}`,
			setJSON:  []string{"items[1]=replaced"},
			expected: `{"items":["a","replaced","c"]}`,
		},
		{
			name:    "invalid_json_body",
			input:   `not valid json`,
			setJSON: []string{"key=value"},
			wantErr: true,
		},
		{
			name:     "no_modifications",
			input:    `{"unchanged": true}`,
			expected: `{"unchanged": true}`,
		},
		{
			name:     "empty_body_creates_object",
			input:    ``,
			setJSON:  []string{"key=value"},
			expected: `{"key":"value"}`,
		},
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := modifyJSONBody([]byte(tc.input), tc.setJSON, tc.removeJSON)

			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			var expectedMap, resultMap interface{}
			require.NoError(t, json.Unmarshal([]byte(tc.expected), &expectedMap))
			require.NoError(t, json.Unmarshal(result, &resultMap))
			assert.Equal(t, expectedMap, resultMap)
		})
	}
}

func TestSetEncodedJSONString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		path     string
		value    string
		expected string
		wantErr  bool
	}{
		{
			name:     "set_in_encoded_object",
			input:    `{"user": "{\"email\": \"old@test.com\"}"}`,
			path:     "user.email",
			value:    "new@test.com",
			expected: `{"user":"{\"email\":\"new@test.com\"}"}`,
		},
		{
			name:     "add_to_encoded_object",
			input:    `{"user": "{\"email\": \"a@test.com\"}"}`,
			path:     "user.name",
			value:    "Bob",
			expected: `{"user":"{\"email\":\"a@test.com\",\"name\":\"Bob\"}"}`,
		},
		{
			name:     "set_in_encoded_array",
			input:    `{"items": "[1,2,3]"}`,
			path:     "items[1]",
			value:    "99",
			expected: `{"items":"[1,99,3]"}`,
		},
		{
			name:     "double_encoded",
			input:    `{"outer": "{\"inner\": \"{\\\"deep\\\": \\\"old\\\"}\"}"}`,
			path:     "outer.inner.deep",
			value:    "new",
			expected: `{"outer":"{\"inner\":\"{\\\"deep\\\":\\\"new\\\"}\"}"}`,
		},
		{
			name:    "invalid_json_string",
			input:   `{"data": "{not valid}"}`,
			path:    "data.field",
			value:   "x",
			wantErr: true,
		},
		{
			name:    "plain_string_error",
			input:   `{"data": "just text"}`,
			path:    "data.field",
			value:   "x",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := modifyJSONBody([]byte(tc.input), []string{tc.path + "=" + tc.value}, nil)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.JSONEq(t, tc.expected, string(result))
		})
	}
}

func TestRemoveEncodedJSONString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		path     string
		expected string
	}{
		{
			name:     "remove_from_encoded_object",
			input:    `{"user": "{\"a\":1,\"b\":2}"}`,
			path:     "user.b",
			expected: `{"user":"{\"a\":1}"}`,
		},
		{
			name:     "remove_from_encoded_array",
			input:    `{"items": "[1,2,3]"}`,
			path:     "items[1]",
			expected: `{"items":"[1,3]"}`,
		},
		{
			name:     "remove_double_encoded",
			input:    `{"outer": "{\"inner\": \"{\\\"a\\\": 1, \\\"b\\\": 2}\"}"}`,
			path:     "outer.inner.b",
			expected: `{"outer":"{\"inner\":\"{\\\"a\\\":1}\"}"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := modifyJSONBody([]byte(tc.input), nil, []string{tc.path})
			require.NoError(t, err)
			assert.JSONEq(t, tc.expected, string(result))
		})
	}
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()

	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

package encoding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		typ    string
		expect string
	}{
		{name: "url_spaces", input: "a b", typ: "url", expect: "a+b"},
		{name: "url_special_chars", input: "a&b=c", typ: "url", expect: "a%26b%3Dc"},
		{name: "base64", input: "data", typ: "base64", expect: "ZGF0YQ=="},
		{name: "html", input: "<a>", typ: "html", expect: "&lt;a&gt;"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Encode(tt.input, tt.typ)
			require.NoError(t, err)
			assert.Equal(t, tt.expect, result)
		})
	}
}

func TestEncode_invalid_type(t *testing.T) {
	t.Parallel()

	_, err := Encode("test", "invalid")
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid type")
}

func TestDecode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		typ     string
		expect  string
		wantErr string
	}{
		{name: "url_plus_to_space", input: "a+b", typ: "url", expect: "a b"},
		{name: "url_percent_encoded", input: "a%26b", typ: "url", expect: "a&b"},
		{name: "url_invalid", input: "%ZZ", typ: "url", wantErr: "URL decode error"},
		{name: "base64_valid", input: "ZGF0YQ==", typ: "base64", expect: "data"},
		{name: "base64_invalid", input: "@@@", typ: "base64", wantErr: "base64 decode error"},
		{name: "html", input: "&lt;a&gt;", typ: "html", expect: "<a>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Decode(tt.input, tt.typ)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expect, result)
		})
	}
}

func TestDecode_invalid_type(t *testing.T) {
	t.Parallel()

	_, err := Decode("test", "invalid")
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid type")
}

package mcp

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/llm-security-toolbox/sectool/config"
)

func TestBurpClientClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)

	client := New(config.DefaultBurpMCPURL)
	require.NoError(t, client.Close())

	_, err := client.GetProxyHistory(ctx, 10, 0)
	require.ErrorIs(t, err, ErrClientClosed)

	_, err = client.GetProxyHistoryRaw(ctx, 10, 0)
	require.ErrorIs(t, err, ErrClientClosed)

	_, err = client.GetProxyHistoryRegex(ctx, "test", 10, 0)
	require.ErrorIs(t, err, ErrClientClosed)

	err = client.SetInterceptState(ctx, false)
	require.ErrorIs(t, err, ErrClientClosed)

	_, err = client.SendHTTP1Request(ctx, SendRequestParams{})
	require.ErrorIs(t, err, ErrClientClosed)

	err = client.CreateRepeaterTab(ctx, RepeaterTabParams{})
	require.ErrorIs(t, err, ErrClientClosed)
}

func TestSanitizeBurpJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "clean JSON",
			input: `{"request":"GET /","response":"HTTP/1.1 200","notes":""}`,
			want:  `{"request":"GET /","response":"HTTP/1.1 200","notes":""}`,
		},
		{
			name:  "invalid escape and truncated",
			input: `{"request":"binary\u00ZZdata","response":"HTTP`,
			want:  `{"request":"binary\\u00ZZdata","response":"HTTP","notes":""}`,
		},
		{
			name:  "only invalid escape",
			input: `{"request":"\u00XX","response":"","notes":""}`,
			want:  `{"request":"\\u00XX","response":"","notes":""}`,
		},
		{
			name:  "only truncated",
			input: `{"request":"GET /","response":"200","notes":"test`,
			want:  `{"request":"GET /","response":"200","notes":"test"}`,
		},
		{
			name:  "invalid non-unicode escape",
			input: `{"request":"path\.to\.file","response":"","notes":""}`,
			want:  `{"request":"path\\.to\\.file","response":"","notes":""}`,
		},
	}

	var bb bytes.Buffer // reuse to validate reset before used
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, []byte(tt.want), sanitizeBurpJSON(&bb, []byte(tt.input)))
		})
	}
}

func TestFixInvalidEscapes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "no escapes",
			input: `{"request":"GET / HTTP/1.1"}`,
			want:  `{"request":"GET / HTTP/1.1"}`,
		},
		{
			name:  "valid unicode escape",
			input: `{"request":"test\u0041test"}`,
			want:  `{"request":"test\u0041test"}`,
		},
		{
			name:  "invalid unicode escape - non-hex",
			input: `{"request":"test\u00GZtest"}`,
			want:  `{"request":"test\\u00GZtest"}`,
		},
		{
			name:  "invalid unicode escape - binary data",
			input: `{"request":"binary\u00\x01data"}`,
			want:  `{"request":"binary\\u00\\x01data"}`,
		},
		{
			name:  "mixed valid and invalid",
			input: `{"request":"\u0041\u00XX\u0042"}`,
			want:  `{"request":"\u0041\\u00XX\u0042"}`,
		},
		{
			name:  "multiple invalid",
			input: `{"request":"\u00ZZ\u00YY"}`,
			want:  `{"request":"\\u00ZZ\\u00YY"}`,
		},
		{
			name:  "escaped backslash before u - valid hex",
			input: `{"request":"test\\u0041end"}`,
			want:  `{"request":"test\\u0041end"}`,
		},
		{
			name:  "escaped backslash before u - invalid hex",
			input: string([]byte{'{', '"', 'r', '"', ':', '"', '\\', '\\', 'u', 0xC3, 0x9B, '"', '}'}),
			want:  string([]byte{'{', '"', 'r', '"', ':', '"', '\\', '\\', 'u', 0xC3, 0x9B, '"', '}'}),
		},
		{
			name:  "valid escape sequences preserved",
			input: `{"request":"line1\nline2\ttab\r\n\"quote\""}`,
			want:  `{"request":"line1\nline2\ttab\r\n\"quote\""}`,
		},
		{
			name:  "escape at end - truncated 2 chars",
			input: `{"request":"test\u00`,
			want:  `{"request":"test\\u00`,
		},
		{
			name:  "escape at end - truncated 3 chars",
			input: `{"request":"test\u001`,
			want:  `{"request":"test\\u001`,
		},
		{
			name:  "escape at very end",
			input: `{"request":"test\u`,
			want:  `{"request":"test\\u`,
		},
		{
			name:  "lowercase hex valid",
			input: `{"request":"\u00ab"}`,
			want:  `{"request":"\u00ab"}`,
		},
		{
			name:  "uppercase hex valid",
			input: `{"request":"\u00AB"}`,
			want:  `{"request":"\u00AB"}`,
		},
		{
			name:  "invalid escape - backslash dot",
			input: `{"request":"path\.file"}`,
			want:  `{"request":"path\\.file"}`,
		},
		{
			name:  "invalid escape - backslash a",
			input: `{"request":"test\avalue"}`,
			want:  `{"request":"test\\avalue"}`,
		},
		{
			name:  "invalid escape - backslash x",
			input: `{"request":"hex\x41test"}`,
			want:  `{"request":"hex\\x41test"}`,
		},
		{
			name:  "invalid escape - backslash e",
			input: `{"request":"escape\eseq"}`,
			want:  `{"request":"escape\\eseq"}`,
		},
		{
			name:  "multiple invalid escapes",
			input: `{"request":"path\.to\.file\x00"}`,
			want:  `{"request":"path\\.to\\.file\\x00"}`,
		},
		{
			name:  "mixed valid and invalid escapes",
			input: `{"request":"line\n\.path\ttab"}`,
			want:  `{"request":"line\n\\.path\ttab"}`,
		},
		{
			name:  "forward slash escape valid",
			input: `{"request":"test\/path"}`,
			want:  `{"request":"test\/path"}`,
		},
		{
			name:  "backspace and formfeed valid",
			input: `{"request":"back\bform\f"}`,
			want:  `{"request":"back\bform\f"}`,
		},
	}

	var bb bytes.Buffer // reuse to validate reset before used
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, []byte(tt.want), fixInvalidEscapes(&bb, []byte(tt.input)))
		})
	}
}

func TestParseHistoryNDJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{
			name:  "empty",
			input: "",
			want:  0,
		},
		{
			name:  "end marker only",
			input: "Reached end of items",
			want:  0,
		},
		{
			name:  "single entry",
			input: `{"request":"GET /","response":"HTTP/1.1 200","notes":""}`,
			want:  1,
		},
		{
			name: "multiple entries",
			input: `{"request":"GET /","response":"HTTP/1.1 200","notes":""}
{"request":"POST /","response":"HTTP/1.1 201","notes":"created"}`,
			want: 2,
		},
		{
			name: "with end marker",
			input: `{"request":"GET /","response":"HTTP/1.1 200","notes":""}
Reached end of items`,
			want: 1,
		},
		{
			name: "with empty lines",
			input: `{"request":"GET /","response":"HTTP/1.1 200","notes":""}

{"request":"POST /","response":"HTTP/1.1 201","notes":""}
`,
			want: 2,
		},
		{
			name: "with non-JSON prefix lines",
			input: `Some header text
{"request":"GET /","response":"HTTP/1.1 200","notes":""}`,
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, err := parseHistoryNDJSON(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, entries, tt.want)
		})
	}
}

func TestIsValidHexEscape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		{"0000", true},
		{"FFFF", true},
		{"ffff", true},
		{"0aF9", true},
		{"00GZ", false},
		{"GHIJ", false},
		{"00", false},
		{"000000", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, isValidHexEscape([]byte(tt.input)))
		})
	}
}

func TestRepairTruncatedJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "already complete",
			input: `{"request":"GET /","response":"HTTP/1.1 200","notes":""}`,
			want:  `{"request":"GET /","response":"HTTP/1.1 200","notes":""}`,
		},
		{
			name:  "truncated in notes",
			input: `{"request":"GET /","response":"HTTP/1.1 200","notes":"trunc`,
			want:  `{"request":"GET /","response":"HTTP/1.1 200","notes":"trunc"}`,
		},
		{
			name:  "truncated in response",
			input: `{"request":"GET /","response":"HTTP/1.1 200`,
			want:  `{"request":"GET /","response":"HTTP/1.1 200","notes":""}`,
		},
		{
			name:  "truncated in request",
			input: `{"request":"GET / HTTP/1.1`,
			want:  `{"request":"GET / HTTP/1.1","response":"","notes":""}`,
		},
		{
			name:  "truncated at start",
			input: `{"unknown":"val`,
			want:  `{"unknown":"val"}`,
		},
		{
			name:  "complete with trailing newline still ends with }",
			input: `{"request":"GET /","response":"HTTP/1.1 200","notes":""}`,
			want:  `{"request":"GET /","response":"HTTP/1.1 200","notes":""}`,
		},
	}

	var bb bytes.Buffer // reuse to validate reset before used
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, []byte(tt.want), repairTruncatedJSON(&bb, []byte(tt.input)))
		})
	}
}

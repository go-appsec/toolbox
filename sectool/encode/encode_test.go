package encode

import (
	"errors"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		raw     bool
		fn      func(string, bool) (string, error)
		expect  string
		wantErr error
	}{
		{
			name: "prints_with_newline",
			fn: func(input string, _ bool) (string, error) {
				return input + "-out", nil
			},
			expect: "value-out\n",
		},
		{
			name: "prints_raw",
			raw:  true,
			fn: func(input string, _ bool) (string, error) {
				return "raw-" + input, nil
			},
			expect: "raw-value",
		},
		{
			name: "propagates_error",
			fn: func(_ string, _ bool) (string, error) {
				return "", errors.New("fail")
			},
			wantErr: errors.New("fail"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r *os.File
			var w *os.File
			if tt.wantErr == nil {
				var err error
				r, w, err = os.Pipe()
				require.NoError(t, err)
				originalStdout := os.Stdout
				os.Stdout = w
				t.Cleanup(func() {
					os.Stdout = originalStdout
					_ = r.Close()
				})
			}

			err := run("value", false, tt.raw, tt.fn)
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.EqualError(t, err, tt.wantErr.Error())
				return
			}

			assert.NoError(t, err)
			require.NoError(t, w.Close())

			output, readErr := io.ReadAll(r)
			require.NoError(t, readErr)
			assert.Equal(t, tt.expect, string(output))
		})
	}
}

func TestEncodeURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		decode bool
		expect string
	}{
		{name: "encode", input: "a b", expect: "a+b"},
		{name: "decode", input: "a+b", decode: true, expect: "a b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := encodeURL(tt.input, tt.decode)
			require.NoError(t, err)
			assert.Equal(t, tt.expect, result)
		})
	}
}

func TestEncodeBase64(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		decode  bool
		expect  string
		wantErr string
	}{
		{name: "encode", input: "data", expect: "ZGF0YQ=="},
		{name: "decode", input: "ZGF0YQ==", decode: true, expect: "data"},
		{name: "decode_error", input: "@@@", decode: true, wantErr: "base64 decode error:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := encodeBase64(tt.input, tt.decode)
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

func TestEncodeHTML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		decode bool
		expect string
	}{
		{name: "encode", input: "<a>", expect: "&lt;a&gt;"},
		{name: "decode", input: "&lt;a&gt;", decode: true, expect: "<a>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := encodeHTML(tt.input, tt.decode)
			require.NoError(t, err)
			assert.Equal(t, tt.expect, result)
		})
	}
}

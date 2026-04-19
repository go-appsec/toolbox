package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"slices"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeEncoding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		encoding      string
		wantNorm      string
		wantSupported bool
	}{
		{"gzip", "gzip", "gzip", true},
		{"gzip_uppercase", "GZIP", "gzip", true},
		{"gzip_mixed_case", "GzIp", "gzip", true},
		{"gzip_whitespace", " gzip ", "gzip", true},
		{"x_gzip_alias", "x-gzip", "gzip", true},
		{"deflate", "deflate", "deflate", true},
		{"deflate_uppercase", "DEFLATE", "deflate", true},
		{"identity", "identity", "identity", false},
		{"brotli", "br", "br", true},
		{"brotli_uppercase", "BR", "br", true},
		{"empty", "", "", false},
		{"multiple_encodings", "gzip, br", "", false},
		{"x_gzip_uppercase", "X-GZIP", "gzip", true},
		{"x_gzip_mixed", "X-Gzip", "gzip", true},
		{"tabs_around_gzip", "\tgzip\t", "gzip", true},
		{"newline_in_encoding", "\ngzip\n", "gzip", true},
		{"encoding_with_numbers", "gzip123", "gzip123", false},
		{"encoding_with_special", "gzip-variant", "gzip-variant", false},
		{"zstd", "zstd", "zstd", true},
		{"zstd_uppercase", "ZSTD", "zstd", true},
		{"compress_unsupported", "compress", "compress", false},
		{"only_whitespace", "   ", "", false},
		{"leading_zeros", "0gzip", "0gzip", false},
		{"unicode_space", "\u00A0gzip", "gzip", true}, // non-breaking space trimmed by TrimSpace
		{"carriage_return", "gzip\r", "gzip", true},
		{"mixed_whitespace_tabs_spaces", "  \t gzip \t  ", "gzip", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNorm, gotSupported := NormalizeEncoding(tt.encoding)

			assert.Equal(t, tt.wantNorm, gotNorm)
			assert.Equal(t, tt.wantSupported, gotSupported)
		})
	}
}

func TestDecompress(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		tests := []struct {
			name           string
			data           []byte
			encoding       string
			wantData       []byte
			wantCompressed bool
		}{
			{
				name:           "gzip",
				data:           gzipBytes(t, []byte("Hello, World!")),
				encoding:       "gzip",
				wantData:       []byte("Hello, World!"),
				wantCompressed: true,
			},
			{
				name:           "deflate",
				data:           deflateBytes(t, []byte("Hello, World!")),
				encoding:       "deflate",
				wantData:       []byte("Hello, World!"),
				wantCompressed: true,
			},
			{
				name:           "gzip_empty_body",
				data:           gzipBytes(t, []byte("")),
				encoding:       "gzip",
				wantData:       []byte{},
				wantCompressed: true,
			},
			{
				name:           "deflate_empty_body",
				data:           deflateBytes(t, []byte("")),
				encoding:       "deflate",
				wantData:       []byte{},
				wantCompressed: true,
			},
			{
				name:           "gzip_uppercase",
				data:           gzipBytes(t, []byte("Upper Case")),
				encoding:       "GZIP",
				wantData:       []byte("Upper Case"),
				wantCompressed: true,
			},
			{
				name:           "gzip_mixed_case",
				data:           gzipBytes(t, []byte("Mixed Case")),
				encoding:       "GzIp",
				wantData:       []byte("Mixed Case"),
				wantCompressed: true,
			},
			{
				name:           "gzip_whitespace",
				data:           gzipBytes(t, []byte("Whitespace")),
				encoding:       " gzip ",
				wantData:       []byte("Whitespace"),
				wantCompressed: true,
			},
			{
				name:           "x_gzip_alias",
				data:           gzipBytes(t, []byte("X-Gzip")),
				encoding:       "x-gzip",
				wantData:       []byte("X-Gzip"),
				wantCompressed: true,
			},
			{
				name:           "deflate_uppercase",
				data:           deflateBytes(t, []byte("Upper Deflate")),
				encoding:       "DEFLATE",
				wantData:       []byte("Upper Deflate"),
				wantCompressed: true,
			},
			{
				name:           "zlib_wrapped_deflate",
				data:           zlibBytes(t, []byte("Zlib Wrapped")),
				encoding:       "deflate",
				wantData:       []byte("Zlib Wrapped"),
				wantCompressed: true,
			},
			{
				name:           "brotli",
				data:           brotliBytes(t, []byte("Hello, Brotli!")),
				encoding:       "br",
				wantData:       []byte("Hello, Brotli!"),
				wantCompressed: true,
			},
			{
				name:           "brotli_uppercase",
				data:           brotliBytes(t, []byte("Upper Brotli")),
				encoding:       "BR",
				wantData:       []byte("Upper Brotli"),
				wantCompressed: true,
			},
			{
				name:           "zstd",
				data:           zstdBytes(t, []byte("Hello, Zstandard!")),
				encoding:       "zstd",
				wantData:       []byte("Hello, Zstandard!"),
				wantCompressed: true,
			},
			{
				name:           "zstd_uppercase",
				data:           zstdBytes(t, []byte("Upper Zstd")),
				encoding:       "ZSTD",
				wantData:       []byte("Upper Zstd"),
				wantCompressed: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, wasCompressed := Decompress(tt.data, tt.encoding)

				assert.Equal(t, tt.wantCompressed, wasCompressed)
				assert.Equal(t, tt.wantData, got)
			})
		}
	})

	t.Run("unsupported_encoding", func(t *testing.T) {
		tests := []struct {
			name     string
			data     []byte
			encoding string
		}{
			{"empty", []byte("plain text"), ""},
			{"identity", []byte("plain text"), "identity"},
			{"multiple_encodings", gzipBytes(t, []byte("Multi")), "gzip, br"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, wasCompressed := Decompress(tt.data, tt.encoding)

				assert.False(t, wasCompressed)
				assert.Equal(t, tt.data, got)
			})
		}
	})

	t.Run("invalid_data", func(t *testing.T) {
		tests := []struct {
			name     string
			data     []byte
			encoding string
		}{
			{"gzip_invalid", []byte("not gzip data"), "gzip"},
			{"deflate_invalid", []byte{0xFF, 0xFE, 0xFD}, "deflate"},
			{"gzip_truncated", gzipBytes(t, []byte("Hello"))[:5], "gzip"},
			{"gzip_single_byte", []byte{0x1F}, "gzip"},
			{"gzip_partial_magic", []byte{0x1F, 0x8B}, "gzip"},
			{"deflate_single_byte", []byte{0x78}, "deflate"},
			{"gzip_empty_data", []byte{}, "gzip"},
			{"deflate_empty_data", []byte{}, "deflate"},
			{"gzip_corrupted_middle", append(gzipBytes(t, []byte("Hello"))[:8], []byte{0xFF, 0xFF, 0xFF}...), "gzip"},
			{"deflate_partial_zlib_header", []byte{0x78, 0x9C, 0xFF}, "deflate"},
			{"brotli_invalid", []byte("not brotli data"), "br"},
			{"brotli_empty_data", []byte{}, "br"},
			{"zstd_invalid", []byte("not zstd data"), "zstd"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, wasCompressed := Decompress(tt.data, tt.encoding)

				assert.True(t, wasCompressed)
				assert.Nil(t, got)
			})
		}
	})
}

func TestCompress(t *testing.T) {
	t.Parallel()

	t.Run("supported_encodings", func(t *testing.T) {
		tests := []struct {
			name     string
			data     []byte
			encoding string
		}{
			{"gzip", []byte("Hello, World!"), "gzip"},
			{"deflate", []byte("Hello, World!"), "deflate"},
			{"gzip_empty_body", []byte{}, "gzip"},
			{"deflate_empty_body", []byte{}, "deflate"},
			{"x_gzip", []byte("X-Gzip Test"), "x-gzip"},
			{"x_gzip_uppercase", []byte("X-GZIP Test"), "X-GZIP"},
			{"brotli", []byte("Hello, World!"), "br"},
			{"zstd", []byte("Hello, World!"), "zstd"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				compressed, err := Compress(tt.data, tt.encoding)

				require.NoError(t, err)
				assert.NotNil(t, compressed)
			})
		}
	})

	t.Run("unsupported_returns_original", func(t *testing.T) {
		tests := []struct {
			name     string
			data     []byte
			encoding string
		}{
			{"unknown", []byte("plain text data"), "unknown"},
			{"empty", []byte("plain text"), ""},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result, err := Compress(tt.data, tt.encoding)

				require.NoError(t, err)
				assert.Equal(t, tt.data, result)
			})
		}
	})

	t.Run("roundtrip", func(t *testing.T) {
		tests := []struct {
			name     string
			data     []byte
			encoding string
		}{
			{"gzip", []byte("Hello, World! This is test data for compression."), "gzip"},
			{"deflate", []byte("Hello, World! This is test data for compression."), "deflate"},
			{"gzip_binary_data", []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE}, "gzip"},
			{"deflate_binary_data", []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE}, "deflate"},
			{"gzip_large_data", bytes.Repeat([]byte("x"), 10000), "gzip"},
			{"deflate_large_data", bytes.Repeat([]byte("y"), 10000), "deflate"},
			{"brotli", []byte("Hello, World! This is test data for compression."), "br"},
			{"brotli_binary_data", []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE}, "br"},
			{"brotli_large_data", bytes.Repeat([]byte("b"), 10000), "br"},
			{"zstd", []byte("Hello, World! This is test data for compression."), "zstd"},
			{"zstd_binary_data", []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE}, "zstd"},
			{"zstd_large_data", bytes.Repeat([]byte("z"), 10000), "zstd"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				compressed, err := Compress(tt.data, tt.encoding)
				require.NoError(t, err)

				decompressed, wasCompressed := Decompress(compressed, tt.encoding)
				assert.True(t, wasCompressed)
				assert.Equal(t, tt.data, decompressed)
			})
		}
	})

	t.Run("roundtrip_mixed_case", func(t *testing.T) {
		// Test compress with one case, decompress with another
		data := []byte("Test data for case-insensitive round-trip")

		compressed, err := Compress(data, "GZIP")
		require.NoError(t, err)

		decompressed, wasCompressed := Decompress(compressed, "gzip")
		assert.True(t, wasCompressed)
		assert.Equal(t, data, decompressed)
	})

	t.Run("tiny_payloads", func(t *testing.T) {
		tests := []struct {
			name     string
			data     []byte
			encoding string
		}{
			{"gzip_single_byte", []byte{0x42}, "gzip"},
			{"deflate_single_byte", []byte{0x42}, "deflate"},
			{"gzip_two_bytes", []byte{0x42, 0x43}, "gzip"},
			{"deflate_two_bytes", []byte{0x42, 0x43}, "deflate"},
			{"gzip_three_bytes", []byte{0x42, 0x43, 0x44}, "gzip"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				compressed, err := Compress(tt.data, tt.encoding)
				require.NoError(t, err)

				decompressed, wasCompressed := Decompress(compressed, tt.encoding)
				assert.True(t, wasCompressed)
				assert.Equal(t, tt.data, decompressed)
			})
		}
	})

	t.Run("null_bytes_in_body", func(t *testing.T) {
		tests := []struct {
			name     string
			data     []byte
			encoding string
		}{
			{"gzip_null_bytes", []byte{0x00, 0x00, 0x00, 0x00}, "gzip"},
			{"deflate_null_bytes", []byte{0x00, 0x00, 0x00, 0x00}, "deflate"},
			{"gzip_mixed_nulls", []byte{'H', 0x00, 'e', 0x00, 'l', 0x00}, "gzip"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				compressed, err := Compress(tt.data, tt.encoding)
				require.NoError(t, err)

				decompressed, wasCompressed := Decompress(compressed, tt.encoding)
				assert.True(t, wasCompressed)
				assert.Equal(t, tt.data, decompressed)
			})
		}
	})
}

func TestDecompressCorruptedChecksum(t *testing.T) {
	t.Parallel()

	// Create valid gzip data
	validGzip := gzipBytes(t, []byte("Test data"))

	// Gzip trailer is last 8 bytes (4-byte CRC32 + 4-byte original size)
	// Corrupt the CRC32 checksum
	corruptedGzip := slices.Clone(validGzip)
	corruptedGzip[len(corruptedGzip)-5] ^= 0xFF // flip bits in CRC

	got, wasCompressed := Decompress(corruptedGzip, "gzip")

	// Should detect corruption and return nil
	assert.True(t, wasCompressed)
	assert.Nil(t, got)
}

func TestDecompressZlibFallback(t *testing.T) {
	t.Parallel()

	// Create zlib-wrapped data (deflate with zlib header)
	originalData := []byte("Zlib fallback test data")
	zlibData := zlibBytes(t, originalData)

	// Decompress as deflate - should try raw deflate first, fail, then try zlib
	got, wasCompressed := Decompress(zlibData, "deflate")

	assert.True(t, wasCompressed)
	assert.Equal(t, originalData, got)
}

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err := gw.Write(data)
	require.NoError(t, err)
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

func deflateBytes(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	require.NoError(t, err)
	_, err = fw.Write(data)
	require.NoError(t, err)
	require.NoError(t, fw.Close())
	return buf.Bytes()
}

func zlibBytes(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, err := zw.Write(data)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func brotliBytes(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	bw := brotli.NewWriter(&buf)
	_, err := bw.Write(data)
	require.NoError(t, err)
	require.NoError(t, bw.Close())
	return buf.Bytes()
}

func zstdBytes(t *testing.T, data []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	enc, err := zstd.NewWriter(&buf)
	require.NoError(t, err)
	_, err = enc.Write(data)
	require.NoError(t, err)
	require.NoError(t, enc.Close())
	return buf.Bytes()
}

func TestFilterSupportedEncodings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"all_supported", "gzip, deflate, br, zstd", "gzip, deflate, br, zstd"},
		{"strips_unknown", "gzip, snappy, br", "gzip, br"},
		{"only_unsupported", "snappy, lz4", "gzip, deflate, br, zstd"},
		{"with_quality", "br;q=1.0, gzip;q=0.8, snappy;q=0.5", "br;q=1.0, gzip;q=0.8"},
		{"single_supported", "gzip", "gzip"},
		{"single_unsupported", "snappy", "gzip, deflate, br, zstd"},
		{"identity_stripped", "gzip, identity", "gzip"},
		{"preserves_x_gzip", "x-gzip, br", "x-gzip, br"},
		{"empty_after_filter", "compress", "gzip, deflate, br, zstd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, FilterSupportedEncodings(tt.input))
		})
	}
}

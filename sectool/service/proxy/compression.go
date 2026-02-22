package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"
)

// Compression encoding constants
const (
	encodingGzip    = "gzip"
	encodingDeflate = "deflate"
)

// NormalizeEncoding normalizes a Content-Encoding header value.
// Returns the normalized encoding and whether it's a single supported encoding.
// Multiple encodings (e.g., "gzip, br") return ("", false) since we can't partially decode.
func NormalizeEncoding(encoding string) (string, bool) {
	encoding = strings.TrimSpace(strings.ToLower(encoding))

	// Check for multiple encodings (comma-separated)
	if strings.Contains(encoding, ",") {
		// Multiple encodings - we can't partially decode, so skip
		return "", false
	}

	// Normalize to canonical form
	switch encoding {
	case encodingGzip, "x-gzip":
		return encodingGzip, true
	case encodingDeflate:
		return encodingDeflate, true
	default:
		return encoding, false
	}
}

// Decompress decompresses data based on Content-Encoding.
// Returns (decompressed data, wasCompressed).
// If wasCompressed is true but returned data is nil, decompression failed.
// Unknown encodings return (original data, false).
//
// Handles:
// - Case variations: "GZIP", "Gzip" normalized to "gzip"
// - Whitespace: " gzip " trimmed
// - x-gzip alias: treated as gzip
// - deflate: tries raw DEFLATE first, then zlib-wrapped
// - Multiple encodings (e.g., "gzip, br"): skipped (can't partially decode)
func Decompress(data []byte, encoding string) ([]byte, bool) {
	normalized, supported := NormalizeEncoding(encoding)
	if !supported {
		return data, false // unknown or multiple encodings
	}

	switch normalized {
	case encodingGzip:
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, true // compressed but failed
		}
		defer func() { _ = gr.Close() }()
		decompressed, err := io.ReadAll(gr)
		if err != nil {
			return nil, true // compressed but failed
		}
		return decompressed, true

	case encodingDeflate:
		// deflate can be raw DEFLATE or zlib-wrapped - try raw first
		decompressed, err := decompressRawDeflate(data)
		if err == nil {
			return decompressed, true
		}
		decompressed, err = decompressZlib(data)
		if err == nil {
			return decompressed, true
		}
		return nil, true // compressed but failed

	default:
		return data, false // not compressed
	}
}

// decompressRawDeflate attempts raw DEFLATE decompression.
func decompressRawDeflate(data []byte) ([]byte, error) {
	fr := flate.NewReader(bytes.NewReader(data))
	defer func() { _ = fr.Close() }()
	return io.ReadAll(fr)
}

// decompressZlib attempts zlib-wrapped DEFLATE decompression.
func decompressZlib(data []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	return io.ReadAll(zr)
}

// Compress compresses data with the specified encoding.
// Returns (compressed data, error).
// Unknown encodings return the original data unchanged.
//
// Handles the same normalization as Decompress for consistency.
func Compress(data []byte, encoding string) ([]byte, error) {
	normalized, supported := NormalizeEncoding(encoding)
	if !supported {
		return data, nil // unknown encoding, return unchanged
	}

	var buf bytes.Buffer
	switch normalized {
	case encodingGzip:
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write(data); err != nil {
			_ = gw.Close()
			return nil, err
		} else if err := gw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil

	case encodingDeflate:
		// Use raw DEFLATE (most interoperable for recompression)
		if fw, err := flate.NewWriter(&buf, flate.DefaultCompression); err != nil {
			return nil, err
		} else if _, err := fw.Write(data); err != nil {
			_ = fw.Close()
			return nil, err
		} else if err := fw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil

	default:
		return data, nil
	}
}

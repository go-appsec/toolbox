package proxy

import (
	"bytes"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsWebSocketUpgrade(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  *RawHTTP1Request
		want bool
	}{
		{
			name: "valid_websocket_upgrade",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/socket",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Upgrade", Value: "websocket"},
					{Name: "Connection", Value: "Upgrade"},
				},
			},
			want: true,
		},
		{
			name: "case_insensitive_upgrade",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/socket",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Upgrade", Value: "WebSocket"},
					{Name: "Connection", Value: "upgrade"},
				},
			},
			want: true,
		},
		{
			name: "connection_keep_alive_upgrade",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/socket",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Upgrade", Value: "websocket"},
					{Name: "Connection", Value: "keep-alive, Upgrade"},
				},
			},
			want: true,
		},
		{
			name: "missing_upgrade_header",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/socket",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Connection", Value: "Upgrade"},
				},
			},
			want: false,
		},
		{
			name: "missing_connection_header",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/socket",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Upgrade", Value: "websocket"},
				},
			},
			want: false,
		},
		{
			name: "wrong_upgrade_value",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/socket",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Upgrade", Value: "h2c"},
					{Name: "Connection", Value: "Upgrade"},
				},
			},
			want: false,
		},
		{
			name: "connection_no_upgrade",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/socket",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Host", Value: "example.com"},
					{Name: "Upgrade", Value: "websocket"},
					{Name: "Connection", Value: "close"},
				},
			},
			want: false,
		},
		{
			name: "empty_request",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
			},
			want: false,
		},
		{
			name: "multiple_connection_tokens",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/ws",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Upgrade", Value: "websocket"},
					{Name: "Connection", Value: "keep-alive, Upgrade, close"},
				},
			},
			want: true,
		},
		{
			name: "whitespace_trimming",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/ws",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Upgrade", Value: "  websocket  "},
					{Name: "Connection", Value: "  Upgrade  "},
				},
			},
			want: false, // exact match required currently
		},
		{
			name: "h2c_upgrade_not_websocket",
			req: &RawHTTP1Request{
				Method:  "GET",
				Path:    "/",
				Version: "HTTP/1.1",
				Headers: []Header{
					{Name: "Upgrade", Value: "h2c"},
					{Name: "Connection", Value: "Upgrade, HTTP2-Settings"},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isWebSocketUpgrade(tt.req))
		})
	}
}

func TestReadWSFrame(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		frameBytes  []byte
		wantFin     bool
		wantRsv     byte
		wantOpcode  byte
		wantPayload []byte
		wantErr     bool
	}{
		{
			name:        "text_frame_unmasked",
			frameBytes:  []byte{0x81, 0x05, 'H', 'e', 'l', 'l', 'o'},
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  1,
			wantPayload: []byte("Hello"),
		},
		{
			name: "text_frame_masked",
			frameBytes: []byte{
				0x81, 0x85, // FIN=1, opcode=1, MASK=1, len=5
				0x37, 0xfa, 0x21, 0x3d, // mask key
				0x7f, 0x9f, 0x4d, 0x51, 0x58, // masked "Hello"
			},
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  1,
			wantPayload: []byte("Hello"),
		},
		{
			name:        "binary_frame",
			frameBytes:  []byte{0x82, 0x04, 0x00, 0x01, 0x02, 0x03},
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  2,
			wantPayload: []byte{0x00, 0x01, 0x02, 0x03},
		},
		{
			name:        "close_frame",
			frameBytes:  []byte{0x88, 0x02, 0x03, 0xe8}, // code 1000
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  8,
			wantPayload: []byte{0x03, 0xe8},
		},
		{
			name:        "ping_frame",
			frameBytes:  []byte{0x89, 0x04, 'p', 'i', 'n', 'g'},
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  9,
			wantPayload: []byte("ping"),
		},
		{
			name:        "pong_frame",
			frameBytes:  []byte{0x8A, 0x04, 'p', 'o', 'n', 'g'},
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  10,
			wantPayload: []byte("pong"),
		},
		{
			name:        "continuation_frame",
			frameBytes:  []byte{0x00, 0x03, 'a', 'b', 'c'},
			wantFin:     false,
			wantRsv:     0,
			wantOpcode:  0,
			wantPayload: []byte("abc"),
		},
		{
			name:        "fragment_first_part",
			frameBytes:  []byte{0x01, 0x03, 'H', 'e', 'l'}, // FIN=0, opcode=1
			wantFin:     false,
			wantRsv:     0,
			wantOpcode:  1,
			wantPayload: []byte("Hel"),
		},
		{
			name:        "empty_payload",
			frameBytes:  []byte{0x81, 0x00},
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  1,
			wantPayload: []byte{},
		},
		{
			name: "126_byte_length",
			frameBytes: append(
				[]byte{0x81, 126, 0x00, 200}, // len=200
				bytes.Repeat([]byte{'x'}, 200)...,
			),
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  1,
			wantPayload: bytes.Repeat([]byte{'x'}, 200),
		},
		{
			name:        "rsv_bits_set",
			frameBytes:  []byte{0xF1, 0x02, 'h', 'i'}, // RSV1,2,3 all set
			wantFin:     true,
			wantRsv:     0x07,
			wantOpcode:  1,
			wantPayload: []byte("hi"),
		},
		{
			name:       "error_empty_input",
			frameBytes: []byte{},
			wantErr:    true,
		},
		{
			name:       "error_truncated_header",
			frameBytes: []byte{0x81},
			wantErr:    true,
		},
		{
			name:       "error_truncated_length",
			frameBytes: []byte{0x81, 126, 0x00}, // missing second length byte
			wantErr:    true,
		},
		{
			name:       "error_truncated_payload",
			frameBytes: []byte{0x81, 0x05, 'H', 'e'}, // len says 5, only 2 bytes
			wantErr:    true,
		},
		{
			name:       "error_truncated_mask",
			frameBytes: []byte{0x81, 0x85, 0x37, 0xfa}, // mask flag set but only 2 mask bytes
			wantErr:    true,
		},
		{
			name:        "length_exactly_125",
			frameBytes:  append([]byte{0x81, 125}, bytes.Repeat([]byte{'x'}, 125)...),
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  1,
			wantPayload: bytes.Repeat([]byte{'x'}, 125),
		},
		{
			name:        "length_exactly_126",
			frameBytes:  append([]byte{0x81, 126, 0x00, 126}, bytes.Repeat([]byte{'y'}, 126)...),
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  1,
			wantPayload: bytes.Repeat([]byte{'y'}, 126),
		},
		{
			name:        "zero_length_close_frame",
			frameBytes:  []byte{0x88, 0x00},
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  8,
			wantPayload: []byte{},
		},
		{
			name:        "close_with_reason",
			frameBytes:  []byte{0x88, 0x09, 0x03, 0xe8, 'g', 'o', 'o', 'd', 'b', 'y', 'e'}, // code 1000 + "goodbye"
			wantFin:     true,
			wantRsv:     0,
			wantOpcode:  8,
			wantPayload: []byte{0x03, 0xe8, 'g', 'o', 'o', 'd', 'b', 'y', 'e'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame, err := readWSFrame(bytes.NewReader(tt.frameBytes))

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantFin, frame.fin)
			assert.Equal(t, tt.wantRsv, frame.rsv)
			assert.Equal(t, tt.wantOpcode, frame.opcode)
			assert.Equal(t, tt.wantPayload, frame.payload)
		})
	}
}

func TestEncodeWSFrame(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		frame      *wsFrame
		checkLen   int
		checkFirst byte
	}{
		{
			name: "text_unmasked",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  1,
				masked:  false,
				payload: []byte("Hello"),
			},
			checkLen:   7, // 2 header + 5 payload
			checkFirst: 0x81,
		},
		{
			name: "text_masked",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  1,
				masked:  true,
				mask:    [4]byte{0x37, 0xfa, 0x21, 0x3d},
				payload: []byte("Hello"),
			},
			checkLen:   11, // 2 header + 4 mask + 5 payload
			checkFirst: 0x81,
		},
		{
			name: "binary_frame",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  2,
				masked:  false,
				payload: []byte{0x00, 0x01, 0x02},
			},
			checkLen:   5, // 2 header + 3 payload
			checkFirst: 0x82,
		},
		{
			name: "close_frame",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  8,
				masked:  false,
				payload: []byte{0x03, 0xe8},
			},
			checkLen:   4,
			checkFirst: 0x88,
		},
		{
			name: "ping_frame",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  9,
				masked:  false,
				payload: []byte("ping"),
			},
			checkLen:   6,
			checkFirst: 0x89,
		},
		{
			name: "pong_frame",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  10,
				masked:  false,
				payload: []byte("pong"),
			},
			checkLen:   6,
			checkFirst: 0x8A,
		},
		{
			name: "empty_payload",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  1,
				masked:  false,
				payload: []byte{},
			},
			checkLen:   2,
			checkFirst: 0x81,
		},
		{
			name: "fin_false",
			frame: &wsFrame{
				fin:     false,
				rsv:     0,
				opcode:  1,
				masked:  false,
				payload: []byte("hi"),
			},
			checkLen:   4,
			checkFirst: 0x01, // FIN bit not set
		},
		{
			name: "rsv_bits",
			frame: &wsFrame{
				fin:     true,
				rsv:     0x07, // all RSV bits set
				opcode:  1,
				masked:  false,
				payload: []byte("hi"),
			},
			checkLen:   4,
			checkFirst: 0xF1, // FIN + RSV1,2,3 + opcode 1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeWSFrame(tt.frame)

			assert.Len(t, encoded, tt.checkLen)
			assert.Equal(t, tt.checkFirst, encoded[0])
		})
	}
}

func TestEncodeWSFrame_roundtrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		frame *wsFrame
	}{
		{
			name: "text_unmasked",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  1,
				masked:  false,
				payload: []byte("Hello, World!"),
			},
		},
		{
			name: "binary_data",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  2,
				masked:  false,
				payload: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE},
			},
		},
		{
			name: "medium_payload",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  1,
				masked:  false,
				payload: bytes.Repeat([]byte("x"), 200), // > 125 bytes
			},
		},
		{
			name: "large_payload",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  1,
				masked:  false,
				payload: bytes.Repeat([]byte("y"), 70000), // > 65535 bytes
			},
		},
		{
			name: "masked_frame",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  1,
				masked:  true,
				mask:    [4]byte{0x12, 0x34, 0x56, 0x78},
				payload: []byte("Hello, masked frame!"),
			},
		},
		{
			name: "continuation_frame",
			frame: &wsFrame{
				fin:     false,
				rsv:     0,
				opcode:  0,
				masked:  false,
				payload: []byte("cont"),
			},
		},
		{
			name: "empty_payload",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  1,
				masked:  false,
				payload: []byte{},
			},
		},
		{
			name: "close_frame",
			frame: &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  8,
				masked:  false,
				payload: []byte{0x03, 0xe8},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeWSFrame(tt.frame)
			decoded, err := readWSFrame(bytes.NewReader(encoded))
			require.NoError(t, err)

			assert.Equal(t, tt.frame.fin, decoded.fin)
			assert.Equal(t, tt.frame.rsv, decoded.rsv)
			assert.Equal(t, tt.frame.opcode, decoded.opcode)
			assert.Equal(t, tt.frame.payload, decoded.payload)
		})
	}
}

func TestReadWSFrame_ControlFramePayloadLimits(t *testing.T) {
	t.Parallel()

	t.Run("ping_max_125_bytes", func(t *testing.T) {
		payload := bytes.Repeat([]byte{'x'}, 125)
		frameBytes := append([]byte{0x89, 125}, payload...)
		frame, err := readWSFrame(bytes.NewReader(frameBytes))

		require.NoError(t, err)
		assert.Equal(t, byte(9), frame.opcode)
		assert.Len(t, frame.payload, 125)
	})

	t.Run("pong_max_125_bytes", func(t *testing.T) {
		payload := bytes.Repeat([]byte{'x'}, 125)
		frameBytes := append([]byte{0x8A, 125}, payload...)
		frame, err := readWSFrame(bytes.NewReader(frameBytes))

		require.NoError(t, err)
		assert.Equal(t, byte(10), frame.opcode)
		assert.Len(t, frame.payload, 125)
	})

	t.Run("close_max_125_bytes", func(t *testing.T) {
		// Close frame: 2 bytes code + 123 bytes reason = 125 bytes total
		payload := append([]byte{0x03, 0xe8}, bytes.Repeat([]byte{'x'}, 123)...)
		frameBytes := append([]byte{0x88, 125}, payload...)
		frame, err := readWSFrame(bytes.NewReader(frameBytes))

		require.NoError(t, err)
		assert.Equal(t, byte(8), frame.opcode)
		assert.Len(t, frame.payload, 125)
	})
}

func TestEncodeWSFrame_LargePayloadLengthEncoding(t *testing.T) {
	t.Parallel()

	t.Run("16bit_length_boundary", func(t *testing.T) {
		// Test payload length at 16-bit boundary (65535)
		payload := bytes.Repeat([]byte{'x'}, 65535)
		frame := &wsFrame{
			fin:     true,
			opcode:  2,
			masked:  false,
			payload: payload,
		}

		encoded := encodeWSFrame(frame)

		// Should use 16-bit length encoding (len byte = 126)
		assert.Equal(t, byte(126), encoded[1])

		// Verify round-trip
		decoded, err := readWSFrame(bytes.NewReader(encoded))
		require.NoError(t, err)
		assert.Equal(t, payload, decoded.payload)
	})

	t.Run("64bit_length_encoding", func(t *testing.T) {
		// Test payload length requiring 64-bit encoding (> 65535)
		payload := bytes.Repeat([]byte{'x'}, 65536)
		frame := &wsFrame{
			fin:     true,
			opcode:  2,
			masked:  false,
			payload: payload,
		}

		encoded := encodeWSFrame(frame)

		// Should use 64-bit length encoding (len byte = 127)
		assert.Equal(t, byte(127), encoded[1])

		// Verify round-trip
		decoded, err := readWSFrame(bytes.NewReader(encoded))
		require.NoError(t, err)
		assert.Len(t, decoded.payload, len(payload))
	})
}

func TestEncodeWSFramePayloadLengths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		payloadLen   int
		expectedSize int
	}{
		{"tiny_0", 0, 2},
		{"small_125", 125, 127},
		{"medium_126", 126, 130},
		{"medium_1000", 1000, 1004},
		{"large_65535", 65535, 65539},
		{"very_large_65536", 65536, 65546},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := make([]byte, tt.payloadLen)
			frame := &wsFrame{
				fin:     true,
				rsv:     0,
				opcode:  1,
				payload: payload,
			}
			encoded := encodeWSFrame(frame)
			assert.Len(t, encoded, tt.expectedSize)
		})
	}
}

func TestStripExtensions(t *testing.T) {
	t.Parallel()

	h := &webSocketHandler{}

	tests := []struct {
		name          string
		inputHeaders  []Header
		expectRemoved bool
	}{
		{
			name: "removes_extensions_header",
			inputHeaders: []Header{
				{Name: "Upgrade", Value: "websocket"},
				{Name: "Connection", Value: "Upgrade"},
				{Name: "Sec-WebSocket-Extensions", Value: "permessage-deflate"},
				{Name: "Sec-WebSocket-Key", Value: "abc123"},
			},
			expectRemoved: true,
		},
		{
			name: "no_extensions_header",
			inputHeaders: []Header{
				{Name: "Upgrade", Value: "websocket"},
				{Name: "Connection", Value: "Upgrade"},
				{Name: "Sec-WebSocket-Key", Value: "abc123"},
			},
			expectRemoved: false,
		},
		{
			name: "multiple_extensions",
			inputHeaders: []Header{
				{Name: "Sec-WebSocket-Extensions", Value: "permessage-deflate; client_max_window_bits"},
				{Name: "Upgrade", Value: "websocket"},
			},
			expectRemoved: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &RawHTTP1Request{
				Method:  "GET",
				Path:    "/ws",
				Version: "HTTP/1.1",
				Headers: slices.Clone(tt.inputHeaders),
			}

			h.stripExtensions(req)

			// Check that Sec-WebSocket-Extensions is removed
			hasExtensions := false
			for _, hdr := range req.Headers {
				if hdr.Name == "Sec-WebSocket-Extensions" {
					hasExtensions = true
					break
				}
			}

			assert.False(t, hasExtensions)
		})
	}
}

func TestStripResponseExtensions(t *testing.T) {
	t.Parallel()

	h := &webSocketHandler{}

	tests := []struct {
		name          string
		inputHeaders  []Header
		expectRemoved bool
	}{
		{
			name: "removes_extensions_from_response",
			inputHeaders: []Header{
				{Name: "Upgrade", Value: "websocket"},
				{Name: "Connection", Value: "Upgrade"},
				{Name: "Sec-WebSocket-Extensions", Value: "permessage-deflate"},
				{Name: "Sec-WebSocket-Accept", Value: "hash123"},
			},
			expectRemoved: true,
		},
		{
			name: "no_extensions_in_response",
			inputHeaders: []Header{
				{Name: "Upgrade", Value: "websocket"},
				{Name: "Sec-WebSocket-Accept", Value: "hash123"},
			},
			expectRemoved: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &RawHTTP1Response{
				Version:    "HTTP/1.1",
				StatusCode: 101,
				StatusText: "Switching Protocols",
				Headers:    slices.Clone(tt.inputHeaders),
			}

			h.stripResponseExtensions(resp)

			hasExtensions := false
			for _, hdr := range resp.Headers {
				if hdr.Name == "Sec-WebSocket-Extensions" {
					hasExtensions = true
					break
				}
			}

			assert.False(t, hasExtensions)
		})
	}
}

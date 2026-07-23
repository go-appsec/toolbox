package proxy

import (
	"context"
	"net"
	"testing"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func TestDecodeHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		pseudos         map[string]string
		headers         []types.Header
		wantErr         bool
		invalidBlock    []byte
		expectedPseudos map[string]string
		expectedHeaders []types.Header
	}{
		{
			name: "request_headers",
			pseudos: map[string]string{
				":method":    "GET",
				":scheme":    "https",
				":authority": "example.com",
				":path":      "/test",
			},
			headers: []types.Header{
				{Name: "user-agent", Value: "test/1.0"},
				{Name: "accept", Value: "*/*"},
			},
			expectedPseudos: map[string]string{
				":method":    "GET",
				":scheme":    "https",
				":authority": "example.com",
				":path":      "/test",
			},
			expectedHeaders: []types.Header{
				{Name: "user-agent", Value: "test/1.0"},
				{Name: "accept", Value: "*/*"},
			},
		},
		{
			name:         "invalid_block",
			invalidBlock: []byte{0xff, 0xff, 0xff},
			wantErr:      true,
		},
		{
			name:            "empty_block",
			invalidBlock:    []byte{},
			expectedPseudos: map[string]string{},
			expectedHeaders: []types.Header{},
		},
		{
			name:         "truncated_block",
			invalidBlock: []byte{0x40, 0x05},
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				_ = clientConn.Close()
				_ = serverConn.Close()
			})

			h := newH2Conn(serverConn)

			var block []byte
			var err error

			if tt.invalidBlock != nil {
				block = tt.invalidBlock
			} else {
				block, err = h.encodeHeaders(tt.pseudos, tt.headers)
				require.NoError(t, err)
				require.NotEmpty(t, block)
			}

			h2 := newH2Conn(clientConn)
			decodedPseudos, decodedHeaders, err := h2.decodeHeaders(block)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			for k, v := range tt.expectedPseudos {
				assert.Equal(t, v, decodedPseudos[k])
			}
			assert.Len(t, decodedHeaders, len(tt.expectedHeaders))
			for i, h := range tt.expectedHeaders {
				assert.Equal(t, h.Name, decodedHeaders[i].Name)
				assert.Equal(t, h.Value, decodedHeaders[i].Value)
			}
		})
	}
}

func TestEncodeHeaders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		pseudos         map[string]string
		headers         []types.Header
		expectedPseudos map[string]string
		expectedCount   int
	}{
		{
			name: "response_status",
			pseudos: map[string]string{
				":status": "200",
			},
			headers: []types.Header{
				{Name: "content-type", Value: "text/plain"},
			},
			expectedPseudos: map[string]string{
				":status": "200",
			},
			expectedCount: 1,
		},
		{
			name: "empty_headers",
			pseudos: map[string]string{
				":status": "204",
			},
			headers:         nil,
			expectedPseudos: map[string]string{":status": "204"},
			expectedCount:   0,
		},
		{
			name: "multiple_values",
			pseudos: map[string]string{
				":method": "GET",
				":path":   "/",
			},
			headers: []types.Header{
				{Name: "accept", Value: "text/html"},
				{Name: "accept", Value: "application/json"},
				{Name: "accept-encoding", Value: "gzip, deflate"},
			},
			expectedPseudos: map[string]string{
				":method": "GET",
				":path":   "/",
			},
			expectedCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				_ = clientConn.Close()
				_ = serverConn.Close()
			})

			h := newH2Conn(serverConn)

			encoded, err := h.encodeHeaders(tt.pseudos, tt.headers)
			require.NoError(t, err)
			require.NotEmpty(t, encoded)

			h2 := newH2Conn(clientConn)
			decodedPseudos, decodedHeaders, err := h2.decodeHeaders(encoded)
			require.NoError(t, err)

			for k, v := range tt.expectedPseudos {
				assert.Equal(t, v, decodedPseudos[k])
			}
			assert.Len(t, decodedHeaders, tt.expectedCount)
		})
	}
}

func TestEncodeHeadersForbiddenFiltering(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	// Include forbidden HTTP/2 headers
	pseudos := map[string]string{":status": "200"}
	headers := []types.Header{
		{Name: "connection", Value: "keep-alive"},
		{Name: "keep-alive", Value: "timeout=5"},
		{Name: "transfer-encoding", Value: "chunked"},
		{Name: "proxy-connection", Value: "keep-alive"},
		{Name: "content-type", Value: "text/plain"}, // survives filtering
	}

	encoded, err := h.encodeHeaders(pseudos, headers)
	require.NoError(t, err)

	h2 := newH2Conn(clientConn)
	decodedPseudos, decodedHeaders, err := h2.decodeHeaders(encoded)
	require.NoError(t, err)

	assert.Equal(t, "200", decodedPseudos[":status"])
	// Only content-type should survive, forbidden headers filtered
	assert.Len(t, decodedHeaders, 1)
	assert.Equal(t, "content-type", decodedHeaders[0].Name)
	assert.Equal(t, "text/plain", decodedHeaders[0].Value)
}

func TestEncodeHeadersEmptyBlock(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	// Only status pseudo-header, no regular headers
	pseudos := map[string]string{":status": "204"}
	var headers []types.Header

	encoded, err := h.encodeHeaders(pseudos, headers)
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	h2 := newH2Conn(clientConn)
	decodedPseudos, decodedHeaders, err := h2.decodeHeaders(encoded)
	require.NoError(t, err)

	assert.Equal(t, "204", decodedPseudos[":status"])
	assert.Empty(t, decodedHeaders)
}

func TestNewH2Conn(t *testing.T) {
	t.Parallel()

	t.Run("independent_hpack_state", func(t *testing.T) {
		c1a, c1b := net.Pipe()
		c2a, c2b := net.Pipe()
		t.Cleanup(func() {
			_ = c1a.Close()
			_ = c1b.Close()
			_ = c2a.Close()
			_ = c2b.Close()
		})

		h1 := newH2Conn(c1a)
		h2 := newH2Conn(c2a)

		pseudos1 := map[string]string{":method": "POST"}
		headers1 := []types.Header{{Name: "x-custom", Value: "value1"}}
		encoded1, err := h1.encodeHeaders(pseudos1, headers1)
		require.NoError(t, err)

		pseudos2 := map[string]string{":method": "GET"}
		headers2 := []types.Header{{Name: "x-other", Value: "value2"}}
		encoded2, err := h2.encodeHeaders(pseudos2, headers2)
		require.NoError(t, err)

		assert.NotEmpty(t, encoded1)
		assert.NotEmpty(t, encoded2)
	})
}

func TestUpdateSettings(t *testing.T) {
	t.Parallel()

	t.Run("max_frame_size", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)

		assert.Equal(t, uint32(16384), h.getMaxFrameSize())

		h.updateSettings([]http2.Setting{
			{ID: http2.SettingMaxFrameSize, Val: 32768},
		})

		assert.Equal(t, uint32(32768), h.getMaxFrameSize())
	})

	t.Run("initial_window_size", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)

		h.initStreamSendWindow(1)
		h.consumeSendWindow(1, 1000)
		assert.Equal(t, int32(65535-1000), h.sendWindowStream[1])

		newInitial := uint32(131070)

		h.updateSendWindowFromSettings(newInitial)

		h.updateSettings([]http2.Setting{
			{ID: http2.SettingInitialWindowSize, Val: newInitial},
		})
		assert.Equal(t, newInitial, h.initialWindowSize)

		// old=65535, new=131070, delta=65535
		// stream was at 64535, should now be at 64535+65535=130070
		assert.Equal(t, int32(130070), h.sendWindowStream[1])
	})
}

func TestHeaderListSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pseudos  map[string]string
		headers  []types.Header
		expected int
	}{
		{
			name:     "empty",
			pseudos:  nil,
			headers:  nil,
			expected: 0,
		},
		{
			name: "pseudos_only",
			pseudos: map[string]string{
				":method": "GET",
			},
			headers:  nil,
			expected: len(":method") + len("GET") + 32,
		},
		{
			name:    "headers_only",
			pseudos: nil,
			headers: []types.Header{
				{Name: "content-type", Value: "text/plain"},
			},
			expected: len("content-type") + len("text/plain") + 32,
		},
		{
			name: "mixed",
			pseudos: map[string]string{
				":status": "200",
			},
			headers: []types.Header{
				{Name: "content-type", Value: "text/plain"},
			},
			expected: len(":status") + len("200") + 32 + len("content-type") + len("text/plain") + 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, headerListSize(tt.pseudos, tt.headers))
		})
	}
}

func TestConsumeSendWindow(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.initStreamSendWindow(1)

		ok := h.consumeSendWindow(1, 1000)
		assert.True(t, ok)
		assert.Equal(t, int32(65535-1000), h.sendWindowConn)
		assert.Equal(t, int32(65535-1000), h.sendWindowStream[1])
	})

	t.Run("blocked_connection", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.sendWindowConn = 100
		h.initStreamSendWindow(1)

		ok := h.consumeSendWindow(1, 200)
		assert.False(t, ok)
	})

	t.Run("blocked_stream", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.sendWindowStream[1] = 100

		ok := h.consumeSendWindow(1, 200)
		assert.False(t, ok)
	})
}

func TestUpdateSendWindow(t *testing.T) {
	t.Parallel()

	t.Run("connection_level", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		initial := h.sendWindowConn

		h.updateSendWindow(0, 1000)
		assert.Equal(t, initial+1000, h.sendWindowConn)
	})

	t.Run("stream_level", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.initStreamSendWindow(1)
		initial := h.sendWindowStream[1]

		h.updateSendWindow(1, 1000)
		assert.Equal(t, initial+1000, h.sendWindowStream[1])
	})
}

func TestGetAvailableSendWindow(t *testing.T) {
	t.Parallel()

	t.Run("min_of_both", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.sendWindowConn = 1000
		h.sendWindowStream[1] = 500

		available := h.getAvailableSendWindow(1)
		assert.Equal(t, 500, available)
	})

	t.Run("negative_clamped", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		h.sendWindowConn = -100
		h.sendWindowStream[1] = 500

		available := h.getAvailableSendWindow(1)
		assert.Equal(t, 0, available)
	})
}

func TestRemoveStreamWindow(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)
	h.recvWindowStream[1] = 1000
	h.sendWindowStream[1] = 1000

	h.removeStreamWindow(1)

	_, recvOk := h.recvWindowStream[1]
	_, sendOk := h.sendWindowStream[1]
	assert.False(t, recvOk)
	assert.False(t, sendOk)
}

func TestEnqueueWrite(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)

		ok := h.enqueueWrite(t.Context(), []byte("test"))
		assert.True(t, ok)
	})

	t.Run("context_cancelled", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		// Fill the write buffer so select must choose between ctx.Done and blocked write
		for range 256 {
			h.writeCh <- []byte{}
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		ok := h.enqueueWrite(ctx, []byte("test"))
		assert.False(t, ok)
	})

	t.Run("closed_connection", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		t.Cleanup(func() {
			_ = clientConn.Close()
			_ = serverConn.Close()
		})

		h := newH2Conn(serverConn)
		// Fill the write buffer so select must choose between closeCh and blocked write
		for range 256 {
			h.writeCh <- []byte{}
		}
		h.close()

		ok := h.enqueueWrite(t.Context(), []byte("test"))
		assert.False(t, ok)
	})
}

func TestEncodeDecodeHeaders_LargeValues(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	// Test with a large header value (8KB)
	largeValue := string(make([]byte, 8192))
	for i := range largeValue {
		largeValue = largeValue[:i] + string(byte('a'+i%26)) + largeValue[i+1:]
	}

	pseudos := map[string]string{":status": "200"}
	headers := []types.Header{
		{Name: "x-large-header", Value: largeValue},
	}

	encoded, err := h.encodeHeaders(pseudos, headers)
	require.NoError(t, err)
	require.NotEmpty(t, encoded)

	h2 := newH2Conn(clientConn)
	decodedPseudos, decodedHeaders, err := h2.decodeHeaders(encoded)
	require.NoError(t, err)

	assert.Equal(t, "200", decodedPseudos[":status"])
	require.Len(t, decodedHeaders, 1)
	assert.Equal(t, "x-large-header", decodedHeaders[0].Name)
	assert.Equal(t, largeValue, decodedHeaders[0].Value)
}

func TestEncodeDecodeHeaders_ManyHeaders(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	// Create 100 headers
	headers := make([]types.Header, 100)
	for i := 0; i < 100; i++ {
		headers[i] = types.Header{
			Name:  "x-header-" + string(rune('0'+i/10)) + string(rune('0'+i%10)),
			Value: "value-" + string(rune('0'+i/10)) + string(rune('0'+i%10)),
		}
	}

	pseudos := map[string]string{":status": "200"}

	encoded, err := h.encodeHeaders(pseudos, headers)
	require.NoError(t, err)

	h2 := newH2Conn(clientConn)
	decodedPseudos, decodedHeaders, err := h2.decodeHeaders(encoded)
	require.NoError(t, err)

	assert.Equal(t, "200", decodedPseudos[":status"])
	assert.Len(t, decodedHeaders, 100)
}

func TestEncodeDecodeHeaders_BinaryValues(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	// Test with non-ASCII characters (should be encoded as-is for HPACK)
	pseudos := map[string]string{":status": "200"}
	headers := []types.Header{
		{Name: "x-custom", Value: "value-with-unicode-ñ-€"},
	}

	encoded, err := h.encodeHeaders(pseudos, headers)
	require.NoError(t, err)

	h2 := newH2Conn(clientConn)
	decodedPseudos, decodedHeaders, err := h2.decodeHeaders(encoded)
	require.NoError(t, err)

	assert.Equal(t, "200", decodedPseudos[":status"])
	require.Len(t, decodedHeaders, 1)
	assert.Equal(t, "value-with-unicode-ñ-€", decodedHeaders[0].Value)
}

func TestInitStreamSendWindow(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	// Initialize send window for stream 1
	h.initStreamSendWindow(1)
	assert.Equal(t, int32(h.initialWindowSize), h.sendWindowStream[1])

	// Initialize send window for stream 3
	h.initStreamSendWindow(3)
	assert.Equal(t, int32(h.initialWindowSize), h.sendWindowStream[3])

	// Verify both streams exist independently
	assert.Len(t, h.sendWindowStream, 2)
}

func TestRemoveStreamWindowNonexistent(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	// Remove window for stream that was never initialized - should not panic
	h.removeStreamWindow(999)

	// Initialize one stream, remove a different non-existent one
	h.initStreamSendWindow(1)
	h.removeStreamWindow(999)

	// Original stream should still exist
	_, exists := h.sendWindowStream[1]
	assert.True(t, exists)
}

func TestGetAvailableSendWindowUnknownStream(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	// Get window for unknown stream - should return connection window
	available := h.getAvailableSendWindow(999)
	assert.Equal(t, int(localInitialWindow), available)
}

func TestEncodeHeadersTEFiltering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		teValue      string
		wantFiltered bool
	}{
		{
			name:         "te_trailers_kept",
			teValue:      "trailers",
			wantFiltered: false,
		},
		{
			name:         "te_gzip_filtered",
			teValue:      "gzip",
			wantFiltered: true,
		},
		{
			name:         "te_chunked_filtered",
			teValue:      "chunked",
			wantFiltered: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Each test needs its own connections to avoid HPACK state pollution
			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() {
				_ = clientConn.Close()
				_ = serverConn.Close()
			})

			encoder := newH2Conn(serverConn)
			decoder := newH2Conn(clientConn)

			pseudos := map[string]string{":method": "GET", ":path": "/"}
			headers := []types.Header{
				{Name: "te", Value: tt.teValue},
				{Name: "accept", Value: "*/*"},
			}

			encoded, err := encoder.encodeHeaders(pseudos, headers)
			require.NoError(t, err)

			_, decodedHeaders, err := decoder.decodeHeaders(encoded)
			require.NoError(t, err)

			hasTE := false
			for _, hdr := range decodedHeaders {
				if hdr.Name == "te" {
					hasTE = true
					break
				}
			}

			if tt.wantFiltered {
				assert.False(t, hasTE, "TE header should be filtered")
			} else {
				assert.True(t, hasTE, "TE header should be kept")
			}
		})
	}
}

func TestNeedsWindowUpdateNonExistentStream(t *testing.T) {
	t.Parallel()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	h := newH2Conn(serverConn)

	// Call needsWindowUpdate for a stream that doesn't exist
	connUpdate, streamUpdate := h.needsWindowUpdate(999)

	// Should return 0 for both since stream doesn't exist
	assert.Equal(t, uint32(0), connUpdate)
	assert.Equal(t, uint32(0), streamUpdate)
}

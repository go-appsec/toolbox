package wire

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteFrame(t *testing.T) {
	t.Parallel()

	t.Run("round_trip", func(t *testing.T) {
		var buf bytes.Buffer
		payload := []byte(`{"jsonrpc":"2.0"}`)
		require.NoError(t, WriteFrame(&buf, payload))

		got, err := ReadFrame(&buf)
		require.NoError(t, err)
		assert.Equal(t, payload, got)
	})

	t.Run("length_prefix_big_endian", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, WriteFrame(&buf, []byte("abc")))
		assert.Equal(t, uint32(3), binary.BigEndian.Uint32(buf.Bytes()[:4]))
	})

	t.Run("empty_payload", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, WriteFrame(&buf, nil))
		got, err := ReadFrame(&buf)
		require.NoError(t, err)
		assert.Empty(t, got)
	})
}

func TestReadFrame(t *testing.T) {
	t.Parallel()

	t.Run("eof_on_empty", func(t *testing.T) {
		_, err := ReadFrame(bytes.NewReader(nil))
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("truncated_body", func(t *testing.T) {
		var buf bytes.Buffer
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], 10)
		buf.Write(hdr[:])
		buf.WriteString("abc") // claims 10, only 3 present
		_, err := ReadFrame(&buf)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
}

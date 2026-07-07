package sidecar

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lengthPrefixed splits a [2B BE length][payload] frame, the common framing a
// reassembler must recover across arbitrary chunk boundaries.
func lengthPrefixed(buf []byte) (int, bool) {
	if len(buf) < 2 {
		return 0, false
	}
	n := int(binary.BigEndian.Uint16(buf))
	if len(buf) < 2+n {
		return 0, false
	}
	return 2 + n, true
}

func frame(payload string) []byte {
	b := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(b, uint16(len(payload)))
	copy(b[2:], payload)
	return b
}

func TestReassemblerNext(t *testing.T) {
	t.Parallel()

	drain := func(r *Reassembler) []string {
		var out []string
		for {
			f, ok := r.Next(lengthPrefixed)
			if !ok {
				return out
			}
			out = append(out, string(f[2:]))
		}
	}

	t.Run("frame_split_across_chunks", func(t *testing.T) {
		full := frame("hello")
		var r Reassembler
		r.Append(full[:3]) // partial: length + 1 payload byte
		assert.Empty(t, drain(&r))
		r.Append(full[3:])
		assert.Equal(t, []string{"hello"}, drain(&r))
		assert.Zero(t, r.Buffered())
	})

	t.Run("multiple_frames_one_chunk", func(t *testing.T) {
		var r Reassembler
		r.Append(append(frame("a"), append(frame("bb"), frame("ccc")...)...))
		assert.Equal(t, []string{"a", "bb", "ccc"}, drain(&r))
	})

	t.Run("trailing_partial_retained", func(t *testing.T) {
		var r Reassembler
		next := frame("two")
		r.Append(append(frame("one"), next[:1]...)) // one full frame + 1 byte of the next
		assert.Equal(t, []string{"one"}, drain(&r))
		assert.Equal(t, 1, r.Buffered())
		r.Append(next[1:])
		assert.Equal(t, []string{"two"}, drain(&r))
	})

	t.Run("copies_are_independent", func(t *testing.T) {
		var r Reassembler
		r.Append(frame("xyz"))
		f, ok := r.Next(lengthPrefixed)
		require.True(t, ok)
		r.Append(frame("later")) // must not alias the returned frame's backing array
		assert.Equal(t, "xyz", string(f[2:]))
	})
}

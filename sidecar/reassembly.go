package sidecar

import "bytes"

// Reassembler accumulates stream_deliver chunks until a complete protocol frame
// is buffered.
type Reassembler struct {
	buf []byte
}

// Append adds a delivered chunk to the buffer.
func (r *Reassembler) Append(data []byte) { r.buf = append(r.buf, data...) }

// Buffered reports the number of bytes held but not yet drained.
func (r *Reassembler) Buffered() int { return len(r.buf) }

// Next returns the leading complete frame and true, or nil and false when no
// whole frame is buffered. split reports the leading frame's length and whether a
// whole frame is present.
func (r *Reassembler) Next(split func(buf []byte) (n int, ok bool)) ([]byte, bool) {
	n, ok := split(r.buf)
	if !ok || n <= 0 || n > len(r.buf) {
		return nil, false
	}
	frame := bytes.Clone(r.buf[:n])
	r.buf = append(r.buf[:0], r.buf[n:]...)
	return frame, true
}

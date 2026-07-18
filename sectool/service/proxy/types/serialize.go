package types

import (
	"bytes"
	"strconv"
	"strings"
)

// SerializeHeaders reconstructs the status line and headers only (no body).
// Useful for SendRequestResult where headers and body are returned separately.
func (r *RawHTTP1Response) SerializeHeaders(buf *bytes.Buffer) []byte {
	buf.Reset()
	// Status line
	buf.WriteString(r.Version)
	buf.WriteByte(' ')
	buf.WriteString(strconv.Itoa(r.StatusCode))
	if r.StatusText != "" {
		buf.WriteByte(' ')
		buf.WriteString(r.StatusText)
	}
	buf.WriteString("\r\n")

	// Build headers list, filtering chunked TE and Content-Length
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, "Transfer-Encoding") &&
			strings.Contains(strings.ToLower(h.Value), "chunked") {
			continue // Skip Transfer-Encoding: chunked (we use Content-Length instead)
		} else if strings.EqualFold(h.Name, "Content-Length") {
			continue // skip Content-Length, added below
		}

		buf.WriteString(h.Name)
		buf.WriteString(": ")
		buf.WriteString(h.Value)
		buf.WriteString("\r\n")
	}
	if len(r.Body) > 0 {
		buf.WriteString("Content-Length: ")
		buf.WriteString(strconv.Itoa(len(r.Body)))
		buf.WriteString("\r\n")
	}

	buf.WriteString("\r\n") // Header terminator
	return buf.Bytes()
}

// summaryLineEnd returns the line terminator for injected lines. Picks the most desync-relevant
// terminator seen so injected lines match the ambiguity of the original: bare CR > bare LF > CRLF.
func summaryLineEnd(w *WireFormat) string {
	if w == nil {
		return "\r\n"
	} else if w.UsedBareCR {
		return "\r"
	} else if w.UsedBareLF {
		return "\n"
	}
	return "\r\n"
}

// SerializeRaw returns wire bytes reconstructed from the parsed request.
// Emits headers and body exactly as parsed; no auto-cleanup.
func (r *RawHTTP1Request) SerializeRaw(buf *bytes.Buffer) []byte {
	buf.Reset()

	// Request line
	buf.WriteString(r.Method)
	buf.WriteByte(' ')
	buf.WriteString(r.Path)
	if r.Query != "" {
		buf.WriteByte('?')
		buf.WriteString(r.Query)
	}
	buf.WriteByte(' ')
	buf.WriteString(r.Version)
	buf.WriteString(r.RequestLineEnding.Bytes())

	writeRawHTTP1Body(buf, r.Headers, r.Body, r.Trailers, r.Chunks, r.Wire, r.HeaderBlockEnding)
	return buf.Bytes()
}

// SerializeRaw returns wire bytes reconstructed from the parsed response.
// Emits headers and body exactly as parsed; no auto-cleanup.
func (r *RawHTTP1Response) SerializeRaw(buf *bytes.Buffer) []byte {
	buf.Reset()
	r.writeStatusLine(buf)
	writeRawHTTP1Body(buf, r.Headers, r.Body, r.Trailers, r.Chunks, r.Wire, r.HeaderBlockEnding)
	return buf.Bytes()
}

// SerializeHead returns the status line, headers, and header-block terminator in
// wire form, without the body. Used to forward a streaming response's head
// before its body units arrive; preserves original endings and headers verbatim
// (unlike the lossy SerializeHeaders).
func (r *RawHTTP1Response) SerializeHead(buf *bytes.Buffer) []byte {
	buf.Reset()
	r.writeStatusLine(buf)
	writeRawHTTP1HeaderBlock(buf, r.Headers, r.HeaderBlockEnding)
	return buf.Bytes()
}

// writeStatusLine writes the response status line and its terminator.
func (r *RawHTTP1Response) writeStatusLine(buf *bytes.Buffer) {
	buf.WriteString(r.Version)
	buf.WriteByte(' ')
	buf.WriteString(strconv.Itoa(r.StatusCode))
	if r.StatusText != "" {
		buf.WriteByte(' ')
		buf.WriteString(r.StatusText)
	}
	buf.WriteString(r.StatusLineEnding.Bytes())
}

// writeRawHTTP1Body writes headers, header-block terminator, and body for an
// HTTP/1 message whose start line has already been written. Headers and body
// are emitted verbatim; chunked re-framing fires only when Wire.WasChunked
// is set. Callers are responsible for setting Content-Length when appropriate.
func writeRawHTTP1Body(buf *bytes.Buffer, headers Headers, body, trailers []byte, chunks []ChunkFrame, wire *WireFormat, blockEnding LineEnding) {
	writeRawHTTP1HeaderBlock(buf, headers, blockEnding)

	if wire != nil && wire.WasChunked {
		writeChunkedBody(buf, body, trailers, chunks, summaryLineEnd(wire))
	} else {
		buf.Write(body)
	}
}

// writeRawHTTP1HeaderBlock writes headers verbatim followed by the header-block terminator.
func writeRawHTTP1HeaderBlock(buf *bytes.Buffer, headers Headers, blockEnding LineEnding) {
	for _, h := range headers {
		writeHeaderRaw(buf, h)
	}
	buf.WriteString(blockEnding.Bytes())
}

// writeHeaderRaw writes a header preserving wire fidelity.
func writeHeaderRaw(buf *bytes.Buffer, h Header) {
	if len(h.RawLine) > 0 {
		buf.Write(h.RawLine)
	} else {
		buf.WriteString(h.Name)
		buf.WriteString(": ")
		buf.WriteString(h.Value)
	}
	buf.WriteString(h.LineEnding.Bytes())
}

// EncodeStandardChunkedBody writes body + trailers into buf as an HTTP/1.1 chunked body
// using CRLF terminators. trailers is written verbatim after the 0-chunk.
func EncodeStandardChunkedBody(buf *bytes.Buffer, body, trailers []byte) {
	writeChunkedBody(buf, body, trailers, nil, "\r\n")
}

// writeChunkedBody writes body in chunked transfer encoding format.
func writeChunkedBody(buf *bytes.Buffer, body, trailers []byte, chunks []ChunkFrame, lineEnd string) {
	if canReuseChunks(chunks, len(body)) {
		var off int
		var trailerBlockEnd string
		for _, c := range chunks {
			buf.Write(c.SizeLine)
			buf.WriteString(c.SizeEnding.Bytes())
			if c.Malformed {
				return // Stop at the malformed frame
			}
			if c.Size == 0 {
				// Final 0-chunk: DataEnding carries the terminator of the blank
				// line that closes the trailer block (empty when truncated at EOF)
				trailerBlockEnd = c.DataEnding.Bytes()
				continue
			}
			buf.Write(body[off : off+c.Size])
			buf.WriteString(c.DataEnding.Bytes())
			off += c.Size
		}
		if len(trailers) > 0 {
			buf.Write(trailers)
		}
		buf.WriteString(trailerBlockEnd)
		return
	}

	WriteChunk(buf, body, lineEnd)
	WriteLastChunk(buf, trailers, lineEnd)
}

// WriteChunk writes one chunked-encoding frame: hex size, data, and terminators.
// Empty data writes nothing, since a zero-length frame would end the body early.
// Used to forward one streaming body unit whose length may differ from the origin.
func WriteChunk(buf *bytes.Buffer, data []byte, lineEnd string) {
	if len(data) == 0 {
		return
	}
	buf.WriteString(strconv.FormatInt(int64(len(data)), 16))
	buf.WriteString(lineEnd)
	buf.Write(data)
	buf.WriteString(lineEnd)
}

// WriteLastChunk writes the terminal 0-size frame and any trailer bytes.
func WriteLastChunk(buf *bytes.Buffer, trailers []byte, lineEnd string) {
	buf.WriteByte('0')
	buf.WriteString(lineEnd)
	if len(trailers) > 0 {
		buf.Write(trailers)
	}
	buf.WriteString(lineEnd)
}

// canReuseChunks reports whether recorded chunk frames still describe the current body.
// A trailing malformed frame always reuses: the wire framing is preserved verbatim.
func canReuseChunks(chunks []ChunkFrame, bodyLen int) bool {
	if len(chunks) == 0 {
		return false
	} else if chunks[len(chunks)-1].Malformed {
		return true
	}
	var sum int
	for _, c := range chunks {
		sum += c.Size
	}
	return sum == bodyLen
}

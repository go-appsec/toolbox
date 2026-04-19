package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
)

var (
	ErrEmptyRequest    = errors.New("empty request")
	ErrEmptyResponse   = errors.New("empty response")
	ErrInvalidRequest  = errors.New("invalid request line")
	ErrInvalidResponse = errors.New("invalid status line")
)

// ParseRequest parses an HTTP/1.1 request from the reader.
// Returns error only for truly unparseable input.
func ParseRequest(r io.Reader) (*RawHTTP1Request, error) {
	br := bufio.NewReader(r)

	line, requestLineEnding, err := readLineWithEnding(br)
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return nil, ErrEmptyRequest
		} else if !errors.Is(err, io.EOF) {
			// return as-is instead of trying to parse partial data as a request line
			return nil, err
		}
		// EOF with partial data: continue parsing (line without trailing newline)
	}

	method, path, query, version, err := ParseRequestLine(line)
	if err != nil {
		return nil, err
	}

	req := &RawHTTP1Request{
		Method:            method,
		Path:              path,
		Query:             query,
		Version:           version,
		Protocol:          strings.ToLower(version),
		RequestLineEnding: requestLineEnding,
	}

	var headersBareLF, headersBareCR bool
	if req.Headers, headersBareLF, headersBareCR, req.HeaderBlockEnding, err = readHeadersWithWire(br); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	// Determine body handling
	var wasChunked, trailersBareLF, trailersBareCR bool
	if req.Body, req.Trailers, wasChunked, req.Chunks, trailersBareLF, trailersBareCR, err = readRequestBodyWithWire(br, req); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	// Track wire format, headersBare* already cover HeaderBlockEnding's terminator
	// Chunked framing terminators are derived from req.Chunks
	// Trailer-line terminators are reported separately since they are preserved verbatim in req.Trailers
	chunksBareLF, chunksBareCR := chunksBareFlags(req.Chunks)
	usedBareLF := requestLineEnding == EndingBareLF || headersBareLF || chunksBareLF || trailersBareLF
	usedBareCR := requestLineEnding == EndingBareCR || headersBareCR || chunksBareCR || trailersBareCR
	if usedBareLF || usedBareCR || wasChunked {
		req.Wire = &WireFormat{
			WasChunked: wasChunked,
			UsedBareLF: usedBareLF,
			UsedBareCR: usedBareCR,
		}
	}

	return req, nil
}

// chunksBareFlags returns whether any chunk framing line used bare LF or bare CR.
func chunksBareFlags(chunks []ChunkFrame) (bareLF, bareCR bool) {
	for _, c := range chunks {
		switch c.SizeEnding {
		case EndingBareLF:
			bareLF = true
		case EndingBareCR:
			bareCR = true
		}
		switch c.DataEnding {
		case EndingBareLF:
			bareLF = true
		case EndingBareCR:
			bareCR = true
		}
	}
	return bareLF, bareCR
}

// parseResponse parses an HTTP/1.1 response from the reader.
// The request method is needed to determine body handling for HEAD responses.
func parseResponse(r io.Reader, requestMethod string) (*RawHTTP1Response, error) {
	br := bufio.NewReader(r)

	// Read status line
	line, statusLineEnding, err := readLineWithEnding(br)
	if err != nil {
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return nil, ErrEmptyResponse
		} else if len(line) == 0 {
			return nil, err
		}
	}

	version, code, text, err := parseStatusLine(line)
	if err != nil {
		return nil, err
	}

	resp := &RawHTTP1Response{
		Version:          version,
		StatusCode:       code,
		StatusText:       text,
		StatusLineEnding: statusLineEnding,
	}

	var headersBareLF, headersBareCR bool
	if resp.Headers, headersBareLF, headersBareCR, resp.HeaderBlockEnding, err = readHeadersWithWire(br); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	// headersBare* already cover HeaderBlockEnding's terminator
	usedBareLF := statusLineEnding == EndingBareLF || headersBareLF
	usedBareCR := statusLineEnding == EndingBareCR || headersBareCR

	var wasChunked bool
	// HEAD and 1xx/204/304 responses have no body
	if requestMethod != "HEAD" && code >= 200 && code != 204 && code != 304 {
		var trailersBareLF, trailersBareCR bool
		if resp.Body, resp.Trailers, wasChunked, resp.Chunks, trailersBareLF, trailersBareCR, err = readResponseBodyWithWire(br, resp); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		chunksBareLF, chunksBareCR := chunksBareFlags(resp.Chunks)
		usedBareLF = usedBareLF || chunksBareLF || trailersBareLF
		usedBareCR = usedBareCR || chunksBareCR || trailersBareCR
	}

	if usedBareLF || usedBareCR || wasChunked {
		resp.Wire = &WireFormat{
			WasChunked: wasChunked,
			UsedBareLF: usedBareLF,
			UsedBareCR: usedBareCR,
		}
	}

	return resp, nil
}

func readLineWithEnding(br *bufio.Reader) (content []byte, ending LineEnding, err error) {
	var buf []byte
	for {
		b, readErr := br.ReadByte()
		if readErr != nil {
			return buf, EndingNone, readErr
		}
		switch b {
		case '\n':
			return buf, EndingBareLF, nil
		case '\r':
			next, peekErr := br.Peek(1)
			if peekErr == nil && next[0] == '\n' {
				_, _ = br.ReadByte()
				return buf, EndingCRLF, nil
			}
			return buf, EndingBareCR, nil
		default:
			buf = append(buf, b)
		}
	}
}

// ParseRequestLine extracts method, path, query, version from request line.
// Accepts malformed lines if method and path are extractable.
func ParseRequestLine(line []byte) (method, path, query, version string, err error) {
	s := string(line)
	parts := strings.SplitN(s, " ", 3)
	if len(parts) < 2 {
		return "", "", "", "", ErrInvalidRequest
	}

	method = parts[0]
	fullPath := parts[1]
	if len(parts) >= 3 {
		version = strings.TrimSpace(parts[2])
	} else {
		version = "HTTP/1.1" // Default if missing
	}

	// Handle proxy-form URLs (absolute URIs like http://host/path)
	if strings.HasPrefix(fullPath, "http://") || strings.HasPrefix(fullPath, "https://") {
		// Keep full URL as path for proxy-form requests
		if idx := strings.Index(fullPath, "?"); idx >= 0 {
			path = fullPath[:idx]
			query = fullPath[idx+1:]
		} else {
			path = fullPath
		}
		return method, path, query, version, nil
	}

	// Origin-form: split path and query
	if idx := strings.Index(fullPath, "?"); idx >= 0 {
		path = fullPath[:idx]
		query = fullPath[idx+1:]
	} else {
		path = fullPath
	}

	return method, path, query, version, nil
}

// parseStatusLine extracts version, status code, status text from status line.
func parseStatusLine(line []byte) (version string, code int, text string, err error) {
	s := string(line)
	parts := strings.SplitN(s, " ", 3)
	if len(parts) < 2 {
		return "", 0, "", ErrInvalidResponse
	}

	version = parts[0]
	code, err = strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, "", ErrInvalidResponse
	}

	if len(parts) >= 3 {
		text = parts[2]
	}

	return version, code, text, nil
}

// readHeadersWithWire reads headers and returns headers plus wire info including the
// terminator of the blank line that ends the header block. Each header's RawLine holds
// original wire bytes (including obs-fold continuations and their inter-line terminators).
func readHeadersWithWire(br *bufio.Reader) (headers Headers, usedBareLF, usedBareCR bool, blockEnding LineEnding, err error) {
	blockEnding = EndingNone  // stays None if loop exits without a blank-line terminator
	var rawAccum []byte       // raw bytes for current header including obs-fold lines
	var prevEnding LineEnding // ending of the most recent physical line, used as obs-fold separator

	aggregate := func(e LineEnding) {
		switch e {
		case EndingBareLF:
			usedBareLF = true
		case EndingBareCR:
			usedBareCR = true
		}
	}

	for {
		line, ending, readErr := readLineWithEnding(br)
		aggregate(ending)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return headers, usedBareLF, usedBareCR, blockEnding, readErr
		}

		// Empty line signals end of headers, its terminator is the block ending
		if len(line) == 0 {
			blockEnding = ending
			return headers, usedBareLF, usedBareCR, blockEnding, nil
		}

		// Check for obs-fold (continuation line)
		if line[0] == ' ' || line[0] == '\t' {
			if len(headers) > 0 {
				// Terminator between prior physical line and this continuation
				rawAccum = append(rawAccum, prevEnding.Bytes()...)
				rawAccum = append(rawAccum, line...)
				headers[len(headers)-1].RawLine = slices.Clone(rawAccum)
				headers[len(headers)-1].LineEnding = ending
				// Join with a single space, trimming the leading whitespace
				headers[len(headers)-1].Value += " " + strings.TrimLeft(string(line), " \t")
			}
			prevEnding = ending
			if errors.Is(readErr, io.EOF) {
				return headers, usedBareLF, usedBareCR, blockEnding, nil
			}
			continue
		}

		// Start new header - store raw bytes
		rawAccum = slices.Clone(line)

		header := parseHeaderLine(line)
		header.RawLine = rawAccum
		header.LineEnding = ending
		headers = append(headers, header)
		prevEnding = ending

		if errors.Is(readErr, io.EOF) {
			return headers, usedBareLF, usedBareCR, blockEnding, nil
		}
	}
}

// parseHeaderLine parses "Name: Value" into Header struct. Preserves whitespace anomalies in header name.
func parseHeaderLine(line []byte) Header {
	idx := bytes.IndexByte(line, ':')
	if idx < 0 {
		// No colon - treat entire line as name with empty value
		return Header{Name: string(line), Value: ""}
	}

	// Name includes everything before colon (preserving whitespace anomalies)
	name := string(line[:idx])

	// Value is everything after colon, with leading/trailing whitespace trimmed
	value := strings.TrimSpace(string(line[idx+1:]))

	return Header{Name: name, Value: value}
}

// readRequestBodyWithWire reads the request body and returns wasChunked, per-chunk
// framing, and bare-LF/CR flags observed inside trailer lines.
func readRequestBodyWithWire(br *bufio.Reader, req *RawHTTP1Request) (body, trailers []byte, wasChunked bool, chunks []ChunkFrame, trailersBareLF, trailersBareCR bool, err error) {
	// Check for chunked encoding first (takes precedence over Content-Length)
	te := req.GetHeader("Transfer-Encoding")
	if strings.Contains(strings.ToLower(te), "chunked") {
		body, trailers, chunks, trailersBareLF, trailersBareCR, err = readChunkedBody(br)
		return body, trailers, true, chunks, trailersBareLF, trailersBareCR, err
	}

	clStr := req.GetHeader("Content-Length")
	if clStr != "" {
		cl, err := strconv.ParseInt(clStr, 10, 64)
		if err != nil || cl <= 0 {
			return nil, nil, false, nil, false, false, nil
		}
		body = make([]byte, cl)
		_, err = io.ReadFull(br, body)
		return body, nil, false, nil, false, false, err
	}

	// No body indicator for requests
	return nil, nil, false, nil, false, false, nil
}

// readResponseBodyWithWire reads the response body and returns wasChunked, per-chunk
// framing, and bare-LF/CR flags observed inside trailer lines.
func readResponseBodyWithWire(br *bufio.Reader, resp *RawHTTP1Response) (body, trailers []byte, wasChunked bool, chunks []ChunkFrame, trailersBareLF, trailersBareCR bool, err error) {
	te := resp.GetHeader("Transfer-Encoding")
	if strings.Contains(strings.ToLower(te), "chunked") {
		body, trailers, chunks, trailersBareLF, trailersBareCR, err = readChunkedBody(br)
		return body, trailers, true, chunks, trailersBareLF, trailersBareCR, err
	}

	clStr := resp.GetHeader("Content-Length")
	if clStr != "" {
		cl, err := strconv.ParseInt(clStr, 10, 64)
		if err != nil || cl < 0 {
			// Invalid CL, try reading to EOF
			body, err := io.ReadAll(br)
			return body, nil, false, nil, false, false, err
		} else if cl == 0 {
			return nil, nil, false, nil, false, false, nil
		}
		body = make([]byte, cl)
		_, err = io.ReadFull(br, body)
		return body, nil, false, nil, false, false, err
	}

	// No Content-Length or chunked: read until EOF
	body, err = io.ReadAll(br)
	return body, nil, false, nil, false, false, err
}

// readChunkedBody reads chunked transfer encoding, returning the decoded body,
// trailers, per-chunk framing, and bare-LF/CR flags observed in trailer lines.
func readChunkedBody(br *bufio.Reader) (body, trailers []byte, chunks []ChunkFrame, trailersBareLF, trailersBareCR bool, err error) {
	var bodyBuf bytes.Buffer

	for {
		sizeLine, sizeEnding, readErr := readLineWithEnding(br)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return bodyBuf.Bytes(), nil, chunks, trailersBareLF, trailersBareCR, readErr
		}

		// Parse chunk size (may have chunk extensions after ;)
		sizeStr := string(sizeLine)
		if idx := strings.IndexByte(sizeStr, ';'); idx >= 0 {
			sizeStr = sizeStr[:idx]
		}
		sizeStr = strings.TrimSpace(sizeStr)

		size, parseErr := strconv.ParseInt(sizeStr, 16, 64)
		if parseErr != nil {
			// Preserve the bad size line; do not drain further so any pipelined request remains
			chunks = append(chunks, ChunkFrame{
				SizeLine:   slices.Clone(sizeLine),
				SizeEnding: sizeEnding,
				Malformed:  true,
			})
			return bodyBuf.Bytes(), nil, chunks, trailersBareLF, trailersBareCR, nil
		}

		// Preserve original size-line bytes (including chunk extensions)
		sizeLineCopy := slices.Clone(sizeLine)

		if size == 0 {
			// Final chunk terminator; read trailers next
			// DataEnding of the 0-chunk records the blank-line terminator that closes the trailer block
			var trailerBlockEnd LineEnding
			trailers, trailerBlockEnd, trailersBareLF, trailersBareCR, _ = readTrailers(br)
			chunks = append(chunks, ChunkFrame{
				SizeLine:   sizeLineCopy,
				SizeEnding: sizeEnding,
				Size:       0,
				DataEnding: trailerBlockEnd,
			})
			return bodyBuf.Bytes(), trailers, chunks, trailersBareLF, trailersBareCR, nil
		}

		chunk := make([]byte, size)
		if _, err = io.ReadFull(br, chunk); err != nil {
			return bodyBuf.Bytes(), nil, chunks, trailersBareLF, trailersBareCR, err
		}
		bodyBuf.Write(chunk)

		// Trailing terminator after chunk data
		_, dataEnding, _ := readLineWithEnding(br)

		chunks = append(chunks, ChunkFrame{
			SizeLine:   sizeLineCopy,
			SizeEnding: sizeEnding,
			Size:       int(size),
			DataEnding: dataEnding,
		})
	}
}

// readTrailers reads trailer headers after the last chunk, preserving each line's terminator.
// Returns the trailer bytes, the terminator of the blank line that ends the trailer block,
// and whether any trailer content line used bare LF or bare CR.
func readTrailers(br *bufio.Reader) (body []byte, blockEnding LineEnding, usedBareLF, usedBareCR bool, err error) {
	var buf bytes.Buffer
	for {
		line, ending, readErr := readLineWithEnding(br)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return buf.Bytes(), EndingNone, usedBareLF, usedBareCR, readErr
		}

		if len(line) == 0 {
			return buf.Bytes(), ending, usedBareLF, usedBareCR, nil
		}

		switch ending {
		case EndingBareLF:
			usedBareLF = true
		case EndingBareCR:
			usedBareCR = true
		}

		buf.Write(line)
		buf.WriteString(ending.Bytes())

		if errors.Is(readErr, io.EOF) {
			return buf.Bytes(), EndingNone, usedBareLF, usedBareCR, nil
		}
	}
}

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
	}
	if w.UsedBareCR {
		return "\r"
	}
	if w.UsedBareLF {
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

	// Status line
	buf.WriteString(r.Version)
	buf.WriteByte(' ')
	buf.WriteString(strconv.Itoa(r.StatusCode))
	if r.StatusText != "" {
		buf.WriteByte(' ')
		buf.WriteString(r.StatusText)
	}
	buf.WriteString(r.StatusLineEnding.Bytes())

	writeRawHTTP1Body(buf, r.Headers, r.Body, r.Trailers, r.Chunks, r.Wire, r.HeaderBlockEnding)
	return buf.Bytes()
}

// writeRawHTTP1Body writes headers, header-block terminator, and body for an
// HTTP/1 message whose start line has already been written. Headers and body
// are emitted verbatim; chunked re-framing fires only when Wire.WasChunked
// is set. Callers are responsible for setting Content-Length when appropriate.
func writeRawHTTP1Body(buf *bytes.Buffer, headers Headers, body, trailers []byte, chunks []ChunkFrame, wire *WireFormat, blockEnding LineEnding) {
	for _, h := range headers {
		writeHeaderRaw(buf, h)
	}

	buf.WriteString(blockEnding.Bytes()) // Header terminator

	if wire != nil && wire.WasChunked {
		writeChunkedBody(buf, body, trailers, chunks, summaryLineEnd(wire))
	} else {
		buf.Write(body)
	}
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

	if len(body) > 0 {
		buf.WriteString(strconv.FormatInt(int64(len(body)), 16))
		buf.WriteString(lineEnd)
		buf.Write(body)
		buf.WriteString(lineEnd)
	}
	// Final chunk
	buf.WriteByte('0')
	buf.WriteString(lineEnd)
	// Trailers if present
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

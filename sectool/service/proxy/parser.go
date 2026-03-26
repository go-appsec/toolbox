package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
)

var (
	ErrEmptyRequest    = errors.New("empty request")
	ErrEmptyResponse   = errors.New("empty response")
	ErrInvalidRequest  = errors.New("invalid request line")
	ErrInvalidResponse = errors.New("invalid status line")
)

// parseRequest parses an HTTP/1.1 request from the reader.
// Returns error only for truly unparseable input.
// Tolerant of malformed input to support security testing.
func parseRequest(r io.Reader) (*RawHTTP1Request, error) {
	br := bufio.NewReader(r)

	line, requestLineBareLF, err := readLineWithEnding(br)
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
		Method:   method,
		Path:     path,
		Query:    query,
		Version:  version,
		Protocol: strings.ToLower(version),
	}

	var headersBareLF bool
	if req.Headers, headersBareLF, err = readHeadersWithWire(br); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	// Determine body handling
	var wasChunked bool
	if req.Body, req.Trailers, wasChunked, err = readRequestBodyWithWire(br, req); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	// Track wire format if any non-standard encoding was detected
	if requestLineBareLF || headersBareLF || wasChunked {
		req.Wire = &WireFormat{
			WasChunked: wasChunked,
			UsedBareLF: requestLineBareLF || headersBareLF,
		}
	}

	return req, nil
}

// parseResponse parses an HTTP/1.1 response from the reader.
// The request method is needed to determine body handling for HEAD responses.
func parseResponse(r io.Reader, requestMethod string) (*RawHTTP1Response, error) {
	br := bufio.NewReader(r)

	// Read status line
	line, statusLineBareLF, err := readLineWithEnding(br)
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
		Version:    version,
		StatusCode: code,
		StatusText: text,
	}

	var headersBareLF bool
	if resp.Headers, headersBareLF, err = readHeadersWithWire(br); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	// Track bare LF usage in headers
	usedBareLF := statusLineBareLF || headersBareLF

	// Determine body handling - HEAD responses have no body
	if requestMethod == "HEAD" {
		if usedBareLF {
			resp.Wire = &WireFormat{UsedBareLF: true}
		}
		return resp, nil
	}

	// 1xx, 204, 304 responses have no body
	if code < 200 || code == 204 || code == 304 {
		if usedBareLF {
			resp.Wire = &WireFormat{UsedBareLF: true}
		}
		return resp, nil
	}

	var wasChunked bool
	if resp.Body, resp.Trailers, wasChunked, err = readResponseBodyWithWire(br, resp); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	// Track wire format if any non-standard encoding was detected
	if usedBareLF || wasChunked {
		resp.Wire = &WireFormat{
			WasChunked: wasChunked,
			UsedBareLF: usedBareLF,
		}
	}

	return resp, nil
}

// readLine reads a line from the reader, handling both CRLF and bare LF.
// Returns the line without the line ending.
func readLine(br *bufio.Reader) ([]byte, error) {
	line, _, err := readLineWithEnding(br)
	return line, err
}

// readLineWithEnding reads a line and returns (content, usedBareLF, error).
// content excludes the line ending; usedBareLF is true if \n was used without \r.
func readLineWithEnding(br *bufio.Reader) (content []byte, usedBareLF bool, err error) {
	// TODO - Consider handling bare CR (\r without \n) as line ending per HTTP spec edge case
	line, err := br.ReadBytes('\n')
	if err != nil {
		// No \n found - trim any trailing CR and return
		line = bytes.TrimSuffix(line, []byte("\r"))
		return line, false, err
	}
	line = line[:len(line)-1] // remove \n
	if bytes.HasSuffix(line, []byte("\r")) {
		line = line[:len(line)-1] // remove \r
		return line, false, nil   // CRLF
	}
	return line, true, nil // bare LF
}

// ParseRequestLine extracts method, path, query, version from request line.
// Tolerant: accepts malformed lines if method and path are extractable.
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

// readHeadersWithWire reads headers and returns (headers, usedBareLF, error).
// Each header's RawLine is populated with the original wire bytes (including obs-fold).
func readHeadersWithWire(br *bufio.Reader) (Headers, bool, error) {
	var headers Headers
	var sawBareLF bool
	var rawAccum []byte // accumulates raw bytes for current header (including obs-fold lines)

	for {
		line, bareLF, err := readLineWithEnding(br)
		if bareLF {
			sawBareLF = true
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return headers, sawBareLF, err
		}

		// Empty line signals end of headers
		if len(line) == 0 {
			return headers, sawBareLF, nil
		}

		// Check for obs-fold (continuation line)
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			// Append to previous header's raw bytes and value
			if len(headers) > 0 {
				// Append continuation to RawLine with line ending
				if bareLF {
					rawAccum = append(rawAccum, '\n')
				} else {
					rawAccum = append(rawAccum, '\r', '\n')
				}
				rawAccum = append(rawAccum, line...)
				headers[len(headers)-1].RawLine = make([]byte, len(rawAccum))
				copy(headers[len(headers)-1].RawLine, rawAccum)
				// Join with a single space, trimming the leading whitespace
				headers[len(headers)-1].Value += " " + strings.TrimLeft(string(line), " \t")
			}
			if errors.Is(err, io.EOF) {
				return headers, sawBareLF, nil
			}
			continue
		}

		// Start new header - store raw bytes
		rawAccum = make([]byte, len(line))
		copy(rawAccum, line)

		header := parseHeaderLine(line)
		header.RawLine = rawAccum
		headers = append(headers, header)

		if errors.Is(err, io.EOF) {
			return headers, sawBareLF, nil
		}
	}
}

// parseHeaderLine parses "Name: Value" into Header struct.
// Preserves whitespace anomalies in header name (e.g., "Header " with trailing space).
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

// readRequestBodyWithWire reads the request body and returns wasChunked flag.
func readRequestBodyWithWire(br *bufio.Reader, req *RawHTTP1Request) (body, trailers []byte, wasChunked bool, err error) {
	// Check for chunked encoding first (takes precedence over Content-Length)
	te := req.GetHeader("Transfer-Encoding")
	if strings.Contains(strings.ToLower(te), "chunked") {
		body, trailers, err = readChunkedBody(br)
		return body, trailers, true, err
	}

	clStr := req.GetHeader("Content-Length")
	if clStr != "" {
		cl, err := strconv.ParseInt(clStr, 10, 64)
		if err != nil || cl <= 0 {
			return nil, nil, false, nil
		}
		body = make([]byte, cl)
		_, err = io.ReadFull(br, body)
		return body, nil, false, err
	}

	// No body indicator for requests
	return nil, nil, false, nil
}

// readResponseBodyWithWire reads the response body and returns wasChunked flag.
func readResponseBodyWithWire(br *bufio.Reader, resp *RawHTTP1Response) (body, trailers []byte, wasChunked bool, err error) {
	// Check for chunked encoding first
	te := resp.GetHeader("Transfer-Encoding")
	if strings.Contains(strings.ToLower(te), "chunked") {
		body, trailers, err = readChunkedBody(br)
		return body, trailers, true, err
	}

	clStr := resp.GetHeader("Content-Length")
	if clStr != "" {
		cl, err := strconv.ParseInt(clStr, 10, 64)
		if err != nil || cl < 0 {
			// Invalid CL, try reading to EOF
			body, err := io.ReadAll(br)
			return body, nil, false, err
		} else if cl == 0 {
			return nil, nil, false, nil
		}
		body = make([]byte, cl)
		_, err = io.ReadFull(br, body)
		return body, nil, false, err
	}

	// No Content-Length or chunked: read until EOF
	body, err = io.ReadAll(br)
	return body, nil, false, err
}

// readChunkedBody reads chunked transfer encoding.
// Returns decoded body and any trailing headers as raw bytes.
func readChunkedBody(br *bufio.Reader) (body, trailers []byte, err error) {
	var bodyBuf bytes.Buffer
	for {
		sizeLine, err := readLine(br)
		if err != nil && !errors.Is(err, io.EOF) {
			return bodyBuf.Bytes(), nil, err
		}

		// Parse chunk size (may have chunk extensions after ;)
		sizeStr := string(sizeLine)
		if idx := strings.IndexByte(sizeStr, ';'); idx >= 0 {
			sizeStr = sizeStr[:idx]
		}
		sizeStr = strings.TrimSpace(sizeStr)

		size, parseErr := strconv.ParseInt(sizeStr, 16, 64)
		if parseErr != nil {
			// Invalid chunk size - return what we have
			return bodyBuf.Bytes(), nil, nil
		}

		if size == 0 {
			// Last chunk - read trailers
			trailers, _ = readTrailers(br)
			return bodyBuf.Bytes(), trailers, nil
		}

		// Read chunk data
		chunk := make([]byte, size)
		if _, err = io.ReadFull(br, chunk); err != nil {
			return bodyBuf.Bytes(), nil, err
		}
		bodyBuf.Write(chunk)

		// Read trailing CRLF after chunk data
		_, _ = readLine(br)
	}
}

// readTrailers reads trailer headers after the last chunk.
func readTrailers(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := readLine(br)
		if err != nil && !errors.Is(err, io.EOF) {
			return buf.Bytes(), err
		}

		if len(line) == 0 {
			// Empty line ends trailers
			return buf.Bytes(), nil
		}

		buf.Write(line)
		buf.WriteString("\r\n")

		if errors.Is(err, io.EOF) {
			return buf.Bytes(), nil
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

// SerializeRaw reconstructs wire bytes preserving original formatting when available.
// If preserveChunked is true and Wire.WasChunked is true, emits chunked encoding.
// Uses Header.RawLine when available to preserve exact original bytes including obs-fold.
// Uses bare LF line endings when Wire.UsedBareLF is true.
// Falls back to standard formatting when Wire is nil or RawLine is not available.
func (r *RawHTTP1Request) SerializeRaw(buf *bytes.Buffer, preserveChunked bool) []byte {
	buf.Reset()

	lineEnd := "\r\n"
	if r.Wire != nil && r.Wire.UsedBareLF {
		lineEnd = "\n"
	}

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
	buf.WriteString(lineEnd)

	useChunked := preserveChunked && r.Wire != nil && r.Wire.WasChunked
	convertingFromChunked := !useChunked && r.Wire != nil && r.Wire.WasChunked // stale CL must be replaced

	// Write headers preserving raw bytes when available
	for _, h := range r.Headers {
		// Skip Transfer-Encoding: chunked if not using chunked mode
		if strings.EqualFold(h.Name, "Transfer-Encoding") &&
			strings.Contains(strings.ToLower(h.Value), "chunked") {
			if useChunked {
				writeHeaderRaw(buf, h, lineEnd)
			}
			continue
		}
		// Skip Content-Length if chunked mode or converting (correct value added below)
		if strings.EqualFold(h.Name, "Content-Length") && (useChunked || convertingFromChunked) {
			continue
		}
		writeHeaderRaw(buf, h, lineEnd)
	}

	// Add Content-Length when not using chunked and body present
	if !useChunked && len(r.Body) > 0 {
		if convertingFromChunked || r.GetHeader("Content-Length") == "" {
			buf.WriteString("Content-Length: ")
			buf.WriteString(strconv.Itoa(len(r.Body)))
			buf.WriteString(lineEnd)
		}
	}

	buf.WriteString(lineEnd) // Header terminator

	if useChunked {
		writeChunkedBody(buf, r.Body, r.Trailers, lineEnd)
	} else {
		buf.Write(r.Body)
	}

	return buf.Bytes()
}

// SerializeRaw reconstructs wire bytes preserving original formatting when available.
// If preserveChunked is true and Wire.WasChunked is true, emits chunked encoding.
// Uses Header.RawLine when available to preserve exact original bytes including obs-fold.
// Uses bare LF line endings when Wire.UsedBareLF is true.
// Falls back to standard formatting when Wire is nil or RawLine is not available.
func (r *RawHTTP1Response) SerializeRaw(buf *bytes.Buffer, preserveChunked bool) []byte {
	buf.Reset()

	lineEnd := "\r\n"
	if r.Wire != nil && r.Wire.UsedBareLF {
		lineEnd = "\n"
	}

	// Status line
	buf.WriteString(r.Version)
	buf.WriteByte(' ')
	buf.WriteString(strconv.Itoa(r.StatusCode))
	if r.StatusText != "" {
		buf.WriteByte(' ')
		buf.WriteString(r.StatusText)
	}
	buf.WriteString(lineEnd)

	useChunked := preserveChunked && r.Wire != nil && r.Wire.WasChunked
	convertingFromChunked := !useChunked && r.Wire != nil && r.Wire.WasChunked // stale CL must be replaced

	// Write headers preserving raw bytes when available
	for _, h := range r.Headers {
		// Skip Transfer-Encoding: chunked if not using chunked mode
		if strings.EqualFold(h.Name, "Transfer-Encoding") &&
			strings.Contains(strings.ToLower(h.Value), "chunked") {
			if useChunked {
				writeHeaderRaw(buf, h, lineEnd)
			}
			continue
		}
		// Skip Content-Length if chunked mode or converting (correct value added below)
		if strings.EqualFold(h.Name, "Content-Length") && (useChunked || convertingFromChunked) {
			continue
		}
		writeHeaderRaw(buf, h, lineEnd)
	}

	// Add Content-Length when not using chunked and body present
	if !useChunked && len(r.Body) > 0 {
		if convertingFromChunked || r.GetHeader("Content-Length") == "" {
			buf.WriteString("Content-Length: ")
			buf.WriteString(strconv.Itoa(len(r.Body)))
			buf.WriteString(lineEnd)
		}
	}

	buf.WriteString(lineEnd) // Header terminator

	if useChunked {
		writeChunkedBody(buf, r.Body, r.Trailers, lineEnd)
	} else {
		buf.Write(r.Body)
	}

	return buf.Bytes()
}

// writeHeaderRaw writes a header using RawLine if available, else standard format.
func writeHeaderRaw(buf *bytes.Buffer, h Header, lineEnd string) {
	if len(h.RawLine) > 0 {
		buf.Write(h.RawLine)
	} else {
		buf.WriteString(h.Name)
		buf.WriteString(": ")
		buf.WriteString(h.Value)
	}
	buf.WriteString(lineEnd)
}

// writeChunkedBody writes body in chunked transfer encoding format.
func writeChunkedBody(buf *bytes.Buffer, body, trailers []byte, lineEnd string) {
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

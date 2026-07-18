package proxy

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
)

var (
	ErrEmptyRequest    = errors.New("empty request")
	ErrEmptyResponse   = errors.New("empty response")
	ErrInvalidRequest  = errors.New("invalid request line")
	ErrInvalidResponse = errors.New("invalid status line")
)

// initialBodyAlloc caps the up-front buffer reserved before reading a body of
// declared length; the buffer grows on demand as bytes arrive.
const initialBodyAlloc = 8192

// streamReadChunk is the per-read buffer size used while streaming a body.
const streamReadChunk = 32 << 10

// ParseRequest parses an HTTP/1.1 request from the reader.
// Returns error only for truly unparseable input.
func ParseRequest(r io.Reader) (*types.RawHTTP1Request, error) {
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

	req := &types.RawHTTP1Request{
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
	usedBareLF := requestLineEnding == types.EndingBareLF || headersBareLF || chunksBareLF || trailersBareLF
	usedBareCR := requestLineEnding == types.EndingBareCR || headersBareCR || chunksBareCR || trailersBareCR
	if usedBareLF || usedBareCR || wasChunked {
		req.Wire = &types.WireFormat{
			WasChunked: wasChunked,
			UsedBareLF: usedBareLF,
			UsedBareCR: usedBareCR,
		}
	}

	return req, nil
}

// chunksBareFlags returns whether any chunk framing line used bare LF or bare CR.
func chunksBareFlags(chunks []types.ChunkFrame) (bareLF, bareCR bool) {
	for _, c := range chunks {
		switch c.SizeEnding {
		case types.EndingBareLF:
			bareLF = true
		case types.EndingBareCR:
			bareCR = true
		}
		switch c.DataEnding {
		case types.EndingBareLF:
			bareLF = true
		case types.EndingBareCR:
			bareCR = true
		}
	}
	return bareLF, bareCR
}

// bodyUnitFunc receives one streamed body unit: decoded holds the logical bytes
// (chunk data or raw read), wire holds the bytes to forward verbatim (a
// reconstructed chunk frame, or the same as decoded for unframed bodies). Both
// slices are valid only for the duration of the call. A non-nil return aborts.
type bodyUnitFunc func(decoded, wire []byte) error

// parseResponse parses an HTTP/1.1 response from the reader.
// The request method is needed to determine body handling for HEAD responses.
func parseResponse(r io.Reader, requestMethod string) (*types.RawHTTP1Response, error) {
	br := bufio.NewReader(r)

	resp, bodyExpected, usedBareLF, usedBareCR, err := parseResponseHead(br, requestMethod)
	if err != nil {
		return nil, err
	}

	var wasChunked bool
	if bodyExpected {
		var trailersBareLF, trailersBareCR bool
		if resp.Body, resp.Trailers, wasChunked, resp.Chunks, trailersBareLF, trailersBareCR, err = readResponseBodyWithWire(br, resp, nil); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		chunksBareLF, chunksBareCR := chunksBareFlags(resp.Chunks)
		usedBareLF = usedBareLF || chunksBareLF || trailersBareLF
		usedBareCR = usedBareCR || chunksBareCR || trailersBareCR
	}

	if usedBareLF || usedBareCR || wasChunked {
		resp.Wire = &types.WireFormat{
			WasChunked: wasChunked,
			UsedBareLF: usedBareLF,
			UsedBareCR: usedBareCR,
		}
	}

	return resp, nil
}

// parseResponseHead parses the status line and headers of an HTTP/1.1 response,
// leaving the body unread on br. bodyExpected is false for HEAD, 1xx, 204, and
// 304 (no message body). headBareLF/headBareCR report bare terminators seen in
// the status line or header block. On success err is nil even if the header
// block ended at EOF.
func parseResponseHead(br *bufio.Reader, requestMethod string) (resp *types.RawHTTP1Response, bodyExpected, headBareLF, headBareCR bool, err error) {
	line, statusLineEnding, lerr := readLineWithEnding(br)
	if lerr != nil {
		if errors.Is(lerr, io.EOF) && len(line) == 0 {
			return nil, false, false, false, ErrEmptyResponse
		} else if len(line) == 0 {
			return nil, false, false, false, lerr
		}
	}

	version, code, text, perr := parseStatusLine(line)
	if perr != nil {
		return nil, false, false, false, perr
	}

	resp = &types.RawHTTP1Response{
		Version:          version,
		StatusCode:       code,
		StatusText:       text,
		StatusLineEnding: statusLineEnding,
	}

	if resp.Headers, headBareLF, headBareCR, resp.HeaderBlockEnding, err = readHeadersWithWire(br); err != nil && !errors.Is(err, io.EOF) {
		return nil, false, false, false, err
	}

	// status-line terminator folds into the head bare flags
	headBareLF = headBareLF || statusLineEnding == types.EndingBareLF
	headBareCR = headBareCR || statusLineEnding == types.EndingBareCR
	// HEAD and 1xx/204/304 responses have no body
	bodyExpected = requestMethod != "HEAD" && code >= 200 && code != 204 && code != 304
	return resp, bodyExpected, headBareLF, headBareCR, nil
}

// readFinalResponse reads responses from br until a final (>=200) one, returning any
// preceding interim 1xx responses and the final response. 101 is treated as final.
// onInterim, when non-nil, is called for each interim response as it is read.
// The same *bufio.Reader must be reused across calls so buffered bytes are not dropped.
func readFinalResponse(br *bufio.Reader, requestMethod string, onInterim func(*types.RawHTTP1Response) error) (interim []*types.RawHTTP1Response, final *types.RawHTTP1Response, err error) {
	for {
		resp, perr := parseResponse(br, requestMethod)
		if perr != nil {
			return interim, nil, perr
		} else if resp.StatusCode < 100 || resp.StatusCode >= 200 || resp.StatusCode == 101 {
			return interim, resp, nil
		}
		if onInterim != nil {
			if werr := onInterim(resp); werr != nil {
				return interim, nil, werr
			}
		}
		interim = append(interim, resp)
	}
}

// readFinalResponseHead reads responses from br until a final (non-1xx, or 101)
// one, returning any preceding interim 1xx responses and the final response's
// head with its body left unread on br. bodyExpected reports whether the final
// response has a body to stream; headBareLF/headBareCR report bare terminators
// in the final head so the caller can assemble Wire after streaming the body.
// onInterim, when non-nil, is called for each interim response.
func readFinalResponseHead(br *bufio.Reader, requestMethod string, onInterim func(*types.RawHTTP1Response) error) (interim []*types.RawHTTP1Response, final *types.RawHTTP1Response, bodyExpected, headBareLF, headBareCR bool, err error) {
	for {
		resp, be, hlf, hcr, perr := parseResponseHead(br, requestMethod)
		if perr != nil {
			return interim, nil, false, false, false, perr
		} else if resp.StatusCode < 100 || resp.StatusCode >= 200 || resp.StatusCode == 101 {
			return interim, resp, be, hlf, hcr, nil
		}
		// interim 1xx has no body; preserve its bare-ending fidelity before forwarding
		if hlf || hcr {
			resp.Wire = &types.WireFormat{UsedBareLF: hlf, UsedBareCR: hcr}
		}
		if onInterim != nil {
			if werr := onInterim(resp); werr != nil {
				return interim, nil, false, false, false, werr
			}
		}
		interim = append(interim, resp)
	}
}

func readLineWithEnding(br *bufio.Reader) (content []byte, ending types.LineEnding, err error) {
	var buf []byte
	for {
		b, readErr := br.ReadByte()
		if readErr != nil {
			return buf, types.EndingNone, readErr
		}
		switch b {
		case '\n':
			return buf, types.EndingBareLF, nil
		case '\r':
			next, peekErr := br.Peek(1)
			if peekErr == nil && next[0] == '\n' {
				_, _ = br.ReadByte()
				return buf, types.EndingCRLF, nil
			}
			return buf, types.EndingBareCR, nil
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
func readHeadersWithWire(br *bufio.Reader) (headers types.Headers, usedBareLF, usedBareCR bool, blockEnding types.LineEnding, err error) {
	blockEnding = types.EndingNone  // stays None if loop exits without a blank-line terminator
	var rawAccum []byte             // raw bytes for current header including obs-fold lines
	var prevEnding types.LineEnding // ending of the most recent physical line, used as obs-fold separator

	aggregate := func(e types.LineEnding) {
		switch e {
		case types.EndingBareLF:
			usedBareLF = true
		case types.EndingBareCR:
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
func parseHeaderLine(line []byte) types.Header {
	idx := bytes.IndexByte(line, ':')
	if idx < 0 {
		// No colon - treat entire line as name with empty value
		return types.Header{Name: string(line), Value: ""}
	}

	// Name includes everything before colon (preserving whitespace anomalies)
	name := string(line[:idx])

	// Value is everything after colon, with leading/trailing whitespace trimmed
	value := strings.TrimSpace(string(line[idx+1:]))

	return types.Header{Name: name, Value: value}
}

// readRequestBodyWithWire reads the request body and returns wasChunked, per-chunk
// framing, and bare-LF/CR flags observed inside trailer lines.
func readRequestBodyWithWire(br *bufio.Reader, req *types.RawHTTP1Request) (body, trailers []byte, wasChunked bool, chunks []types.ChunkFrame, trailersBareLF, trailersBareCR bool, err error) {
	// Check for chunked encoding first (takes precedence over Content-Length)
	te := req.GetHeader("Transfer-Encoding")
	if strings.Contains(strings.ToLower(te), "chunked") {
		body, trailers, chunks, trailersBareLF, trailersBareCR, err = readChunkedBody(br, nil)
		return body, trailers, true, chunks, trailersBareLF, trailersBareCR, err
	}

	clStr := req.GetHeader("Content-Length")
	if clStr != "" {
		cl, err := strconv.ParseInt(clStr, 10, 64)
		if err != nil || cl <= 0 {
			return nil, nil, false, nil, false, false, nil
		}
		buf := bytes.NewBuffer(make([]byte, 0, min(cl, int64(initialBodyAlloc))))
		_, err = io.Copy(buf, io.LimitReader(br, cl))
		return buf.Bytes(), nil, false, nil, false, false, err
	}

	// No body indicator for requests
	return nil, nil, false, nil, false, false, nil
}

// readResponseBodyWithWire reads the response body and returns wasChunked, per-chunk
// framing, and bare-LF/CR flags observed inside trailer lines. It sets
// resp.CloseDelimited when the body is framed by connection close.
func readResponseBodyWithWire(br *bufio.Reader, resp *types.RawHTTP1Response, onUnit bodyUnitFunc) (body, trailers []byte, wasChunked bool, chunks []types.ChunkFrame, trailersBareLF, trailersBareCR bool, err error) {
	te := resp.GetHeader("Transfer-Encoding")
	if strings.Contains(strings.ToLower(te), "chunked") {
		body, trailers, chunks, trailersBareLF, trailersBareCR, err = readChunkedBody(br, onUnit)
		return body, trailers, true, chunks, trailersBareLF, trailersBareCR, err
	}

	clStr := resp.GetHeader("Content-Length")
	if clStr != "" {
		cl, perr := strconv.ParseInt(clStr, 10, 64)
		if perr != nil || cl < 0 {
			// Invalid CL, try reading to EOF
			resp.CloseDelimited = true
			body, err = streamBody(br, -1, onUnit)
			return body, nil, false, nil, false, false, err
		} else if cl == 0 {
			return nil, nil, false, nil, false, false, nil
		}
		body, err = streamBody(br, cl, onUnit)
		return body, nil, false, nil, false, false, err
	}

	// No Content-Length or chunked: read until EOF (body delimited by connection close)
	resp.CloseDelimited = true
	body, err = streamBody(br, -1, onUnit)
	return body, nil, false, nil, false, false, err
}

// streamBody reads the body from br: exactly limit bytes, or to EOF when limit < 0.
// When onUnit is nil it accumulates and returns the whole body; otherwise it
// invokes onUnit per read (decoded == wire for an unframed body) and returns a
// nil body, leaving accumulation to the caller. EOF ends the read cleanly; any
// other read error is returned.
func streamBody(br *bufio.Reader, limit int64, onUnit bodyUnitFunc) ([]byte, error) {
	var out *bytes.Buffer
	if onUnit == nil {
		if limit > 0 {
			// int64 cap is bounded by the initialBodyAlloc constant; no narrowing conversion
			out = bytes.NewBuffer(make([]byte, 0, min(limit, int64(initialBodyAlloc))))
		} else {
			out = &bytes.Buffer{}
		}
	}

	buf := make([]byte, streamReadChunk)
	remaining := limit
	for limit < 0 || remaining > 0 {
		readLen := int64(streamReadChunk)
		if limit >= 0 && remaining < readLen {
			readLen = remaining
		}
		rn, rerr := br.Read(buf[:readLen])
		if rn > 0 {
			if out != nil {
				out.Write(buf[:rn])
			}
			if onUnit != nil {
				if cerr := onUnit(buf[:rn], buf[:rn]); cerr != nil {
					return nil, cerr
				}
			}
			remaining -= int64(rn)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			if out != nil {
				return out.Bytes(), rerr
			}
			return nil, rerr
		}
	}

	if out != nil {
		return out.Bytes(), nil
	}
	return nil, nil
}

// readChunkedBody reads chunked transfer encoding, returning the decoded body,
// trailers, per-chunk framing, and bare-LF/CR flags observed in trailer lines.
// When onUnit is non-nil each data chunk is emitted (decoded data plus its
// reconstructed wire frame) instead of accumulated, so the returned body and
// data-chunk frames are empty; the terminal 0-chunk frame and trailers still return.
func readChunkedBody(br *bufio.Reader, onUnit bodyUnitFunc) (body, trailers []byte, chunks []types.ChunkFrame, trailersBareLF, trailersBareCR bool, err error) {
	var bodyBuf bytes.Buffer
	// reused across chunks in streaming mode; onUnit consumes synchronously
	var dataBuf []byte
	var wireBuf bytes.Buffer

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
		if parseErr != nil || size < 0 || size > math.MaxInt {
			// Preserve the bad size line; do not drain further so any pipelined request remains
			chunks = append(chunks, types.ChunkFrame{
				SizeLine:   slices.Clone(sizeLine),
				SizeEnding: sizeEnding,
				Malformed:  true,
			})
			return bodyBuf.Bytes(), nil, chunks, trailersBareLF, trailersBareCR, nil
		}

		if size == 0 {
			// Final chunk terminator; read trailers next
			// DataEnding of the 0-chunk records the blank-line terminator that closes the trailer block
			var trailerBlockEnd types.LineEnding
			trailers, trailerBlockEnd, trailersBareLF, trailersBareCR, _ = readTrailers(br)
			chunks = append(chunks, types.ChunkFrame{
				SizeLine:   slices.Clone(sizeLine),
				SizeEnding: sizeEnding,
				Size:       0,
				DataEnding: trailerBlockEnd,
			})
			return bodyBuf.Bytes(), trailers, chunks, trailersBareLF, trailersBareCR, nil
		}

		if onUnit != nil {
			// Streaming: read the data out, emit its wire frame, don't accumulate
			if cap(dataBuf) < int(size) {
				dataBuf = make([]byte, size)
			}
			dataBuf = dataBuf[:size]
			if _, err = io.ReadFull(br, dataBuf); err != nil {
				return nil, nil, chunks, trailersBareLF, trailersBareCR, err
			}
			_, dataEnding, _ := readLineWithEnding(br)
			wireBuf.Reset()
			wireBuf.Write(sizeLine)
			wireBuf.WriteString(sizeEnding.Bytes())
			wireBuf.Write(dataBuf)
			wireBuf.WriteString(dataEnding.Bytes())
			if cerr := onUnit(dataBuf, wireBuf.Bytes()); cerr != nil {
				return nil, nil, chunks, trailersBareLF, trailersBareCR, cerr
			}
			continue
		}

		if _, err = io.CopyN(&bodyBuf, br, size); err != nil {
			return bodyBuf.Bytes(), nil, chunks, trailersBareLF, trailersBareCR, err
		}

		// Trailing terminator after chunk data
		_, dataEnding, _ := readLineWithEnding(br)

		chunks = append(chunks, types.ChunkFrame{
			SizeLine:   slices.Clone(sizeLine),
			SizeEnding: sizeEnding,
			Size:       int(size),
			DataEnding: dataEnding,
		})
	}
}

// readTrailers reads trailer headers after the last chunk, preserving each line's terminator.
// Returns the trailer bytes, the terminator of the blank line that ends the trailer block,
// and whether any trailer content line used bare LF or bare CR.
func readTrailers(br *bufio.Reader) (body []byte, blockEnding types.LineEnding, usedBareLF, usedBareCR bool, err error) {
	var buf bytes.Buffer
	for {
		line, ending, readErr := readLineWithEnding(br)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return buf.Bytes(), types.EndingNone, usedBareLF, usedBareCR, readErr
		}

		if len(line) == 0 {
			return buf.Bytes(), ending, usedBareLF, usedBareCR, nil
		}

		switch ending {
		case types.EndingBareLF:
			usedBareLF = true
		case types.EndingBareCR:
			usedBareCR = true
		}

		buf.Write(line)
		buf.WriteString(ending.Bytes())

		if errors.Is(readErr, io.EOF) {
			return buf.Bytes(), types.EndingNone, usedBareLF, usedBareCR, nil
		}
	}
}

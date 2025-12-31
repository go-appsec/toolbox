package service

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jentfoo/llm-security-toolbox/sectool/service/ids"
	"github.com/jentfoo/llm-security-toolbox/sectool/service/store"
)

// updateContentLength updates or adds Content-Length header.
func updateContentLength(headers []byte, length int) []byte {
	// Match Content-Length header line (case-insensitive)
	re := regexp.MustCompile(`(?im)^Content-Length:\s*\d+\r?\n`)
	newHeader := fmt.Sprintf("Content-Length: %d\r\n", length)

	if re.Match(headers) {
		return re.ReplaceAll(headers, []byte(newHeader))
	}

	// Insert before blank line if not present and length > 0
	if length > 0 {
		return bytes.Replace(headers, []byte("\r\n\r\n"), []byte("\r\n"+newHeader+"\r\n"), 1)
	}
	return headers
}

// setHeader adds or replaces a header.
func setHeader(headers []byte, name, value string) []byte {
	re := regexp.MustCompile(`(?im)^` + regexp.QuoteMeta(name) + `:\s*.+\r?\n`)
	newHeader := []byte(name + ": " + value + "\r\n")

	if re.Match(headers) {
		return re.ReplaceAll(headers, newHeader)
	}

	// Insert before the blank line (preserve the first \r\n, which ends the previous header)
	return bytes.Replace(headers, []byte("\r\n\r\n"),
		append([]byte("\r\n"), append(newHeader, []byte("\r\n")...)...), 1)
}

// removeHeader removes a header.
func removeHeader(headers []byte, name string) []byte {
	re := regexp.MustCompile(`(?im)^` + regexp.QuoteMeta(name) + `:\s*.+\r?\n`)
	return re.ReplaceAll(headers, nil)
}

// applyHeaderModifications applies header modifications (--header, --remove-header, --target).
// Does NOT update Content-Length - that is handled separately based on body modification detection.
func applyHeaderModifications(headers []byte, req *ReplaySendRequest) []byte {
	for _, name := range req.RemoveHeaders {
		headers = removeHeader(headers, name)
	}
	for _, h := range req.AddHeaders {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			headers = setHeader(headers, strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	// Handle --target (update Host header)
	if req.Target != "" {
		if u, err := url.Parse(req.Target); err == nil && u.Host != "" {
			headers = setHeader(headers, "Host", u.Host)
		}
	}

	return headers
}

// checkLineEndings detects line ending issues in HTTP headers.
// Returns an issue description or empty string if OK.
func checkLineEndings(headers []byte) string {
	hasCRLF := bytes.Contains(headers, []byte("\r\n"))
	var hasBareLF bool
	// Check for bare LF (LF not preceded by CR)
	for i := 0; i < len(headers); i++ {
		if headers[i] == '\n' {
			if i == 0 || headers[i-1] != '\r' {
				hasBareLF = true
				break
			}
		}
	}

	if hasBareLF && hasCRLF {
		return "mixed line endings (some CRLF, some bare LF)"
	} else if hasBareLF {
		return "using LF instead of CRLF line endings"
	}
	return ""
}

// validationIssue represents a single validation problem.
type validationIssue struct {
	Check    string
	Severity string // "error" or "warning"
	Detail   string
}

// validateRequest checks request for common issues.
func validateRequest(raw []byte) []validationIssue {
	var issues []validationIssue

	headers, body := splitHeadersBody(raw)

	// Check line endings FIRST - this is the most common issue with hand-edited files
	// HTTP requires CRLF (\r\n), not LF (\n)
	if issue := checkLineEndings(headers); issue != "" {
		issues = append(issues, validationIssue{
			Check:    "crlf",
			Severity: "error",
			Detail:   issue + "; HTTP requires CRLF (\\r\\n) line endings, use --force to send anyway",
		})
		// Skip further validation since parse will fail due to line endings
		return issues
	}

	// Transform for validation only (HTTP/2 -> HTTP/1.1 for Go's parser)
	validationRaw := transformRequestForValidation(raw)

	// Use Go's parser to check structure
	_, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(validationRaw)))
	if err != nil {
		issues = append(issues, validationIssue{
			Check:    "parse",
			Severity: "error",
			Detail:   err.Error(),
		})
	}

	// Check Content-Length matches body
	clMatch := regexp.MustCompile(`(?im)^Content-Length:\s*(\d+)`).FindSubmatch(headers)
	if clMatch != nil {
		cl, _ := strconv.Atoi(string(clMatch[1]))
		if cl != len(body) {
			issues = append(issues, validationIssue{
				Check:    "content_length",
				Severity: "error",
				Detail:   fmt.Sprintf("header says %d, body is %d bytes", cl, len(body)),
			})
		}
	}

	// Check Host header (warning only)
	if !regexp.MustCompile(`(?im)^Host:`).Match(headers) {
		issues = append(issues, validationIssue{
			Check:    "host",
			Severity: "warning",
			Detail:   "missing Host header",
		})
	}

	return issues
}

// formatIssues formats validation issues as markdown.
func formatIssues(issues []validationIssue) string {
	var sb strings.Builder
	sb.WriteString("| Issue | Severity | Detail |\n")
	sb.WriteString("|-------|----------|--------|\n")
	for _, i := range issues {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", i.Check, i.Severity, i.Detail))
	}
	return sb.String()
}

// parseTarget determines host, port, and HTTPS from request or --target override.
func parseTarget(raw []byte, targetOverride string) (host string, port int, usesHTTPS bool) {
	if targetOverride != "" {
		u, err := url.Parse(targetOverride)
		if err == nil {
			host = u.Hostname()
			port = 443
			if u.Port() != "" {
				port, _ = strconv.Atoi(u.Port())
			} else if u.Scheme == schemeHTTP {
				port = 80
			}
			usesHTTPS = u.Scheme == schemeHTTPS
			return
		}
	}

	// Extract from Host header
	_, host, _ = extractRequestMeta(string(raw))

	// Parse port from host
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		if p, err := strconv.Atoi(host[idx+1:]); err == nil {
			port = p
			host = host[:idx]
			usesHTTPS = port != 80
			return
		}
	}

	// Default to HTTPS
	port = 443
	usesHTTPS = true
	return
}

// handleReplaySend handles POST /replay/send
func (s *Server) handleReplaySend(w http.ResponseWriter, r *http.Request) {
	var req ReplaySendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	}

	ctx := r.Context()

	// Resolve input, tracking original body size for bundles to detect modifications
	var rawRequest []byte
	var bundlePath, inputSource string
	originalBodySize := -1 // -1 means not from bundle (always update Content-Length)
	switch {
	case req.FlowID != "":
		inputSource = "flow:" + req.FlowID
		// Fetch from HttpBackend via flow_id
		entry, ok := s.flowStore.Lookup(req.FlowID)
		if !ok {
			s.writeError(w, http.StatusNotFound, ErrCodeNotFound,
				"flow_id not found", "run 'sectool proxy list' to see available flows")
			return
		}
		proxyEntries, err := s.httpBackend.GetProxyHistory(ctx, 1, entry.Offset)
		if err != nil {
			if IsTimeoutError(err) {
				s.writeError(w, http.StatusGatewayTimeout, ErrCodeTimeout, "request timed out fetching flow", err.Error())
			} else {
				s.writeError(w, http.StatusBadGateway, ErrCodeBackendError, "failed to fetch flow", err.Error())
			}
			return
		} else if len(proxyEntries) == 0 {
			s.writeError(w, http.StatusNotFound, ErrCodeNotFound, "flow not found in proxy history", "")
			return
		}
		rawRequest = []byte(proxyEntries[0].Request)

	case req.BundlePath != "":
		inputSource = "bundle:" + req.BundlePath
		// Resolve path relative to working directory
		bundlePath = s.paths.ResolvePath(req.BundlePath)
		headers, body, meta, err := readBundle(bundlePath)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "failed to read bundle", err.Error())
			return
		}
		rawRequest = reconstructRequest(headers, body)
		if meta != nil {
			originalBodySize = meta.BodySize
		}

	case req.FilePath != "":
		inputSource = "file:" + req.FilePath
		// Resolve path relative to working directory
		filePath := s.paths.ResolvePath(req.FilePath)
		fileContent, err := os.ReadFile(filePath)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "failed to read file", err.Error())
			return
		}

		if req.BodyPath != "" {
			// Body provided separately - merge headers from file with body from --body
			bodyPath := s.paths.ResolvePath(req.BodyPath)
			body, err := os.ReadFile(bodyPath)
			if err != nil {
				s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest,
					"failed to read body file", err.Error())
				return
			}
			rawRequest = reconstructRequest(fileContent, body)
		} else {
			// No separate body - file contains complete request, use as-is
			rawRequest = fileContent
		}

	default:
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest,
			"no input specified", "use --flow, --bundle, or --file")
		return
	}

	// Apply path/query modifications first (modifies request line)
	rawRequest = modifyRequestLine(rawRequest, &PathQueryOpts{
		Path:        req.Path,
		Query:       req.Query,
		SetQuery:    req.SetQuery,
		RemoveQuery: req.RemoveQuery,
	})

	// Apply header modifications (--header, --remove-header, --target) regardless of --force
	headers, body := splitHeadersBody(rawRequest)
	headers = applyHeaderModifications(headers, &req)

	// Apply JSON body modifications if any
	if len(req.SetJSON) > 0 || len(req.RemoveJSON) > 0 {
		modifiedBody, err := modifyJSONBody(body, req.SetJSON, req.RemoveJSON)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest,
				"JSON body modification failed", err.Error())
			return
		}
		body = modifiedBody
	}

	// Update Content-Length if body was modified (or not from bundle)
	// For bundles: only update if body size differs from original (body was edited)
	// For non-bundles: always update to ensure correctness
	bodyModified := originalBodySize < 0 || len(body) != originalBodySize
	if bodyModified {
		headers = updateContentLength(headers, len(body))
	}

	rawRequest = append(headers, body...)

	// Validate unless --force is set (for testing malformed requests)
	if !req.Force {
		issues := validateRequest(rawRequest)
		if slices.ContainsFunc(issues, func(i validationIssue) bool { return i.Severity == "error" }) {
			s.writeError(w, http.StatusBadRequest, ErrCodeValidation, "validation failed", formatIssues(issues))
			return
		}
	}

	// Determine target
	host, port, usesHTTPS := parseTarget(rawRequest, req.Target)

	replayID := ids.Generate(ids.DefaultLength)

	scheme := schemeHTTP
	if usesHTTPS {
		scheme = schemeHTTPS
	}
	log.Printf("replay/send: %s sending to %s://%s:%d (source=%s)", replayID, scheme, host, port, inputSource)

	// Parse timeout if specified
	var timeout time.Duration
	if req.Timeout != "" {
		if parsed, err := time.ParseDuration(req.Timeout); err == nil {
			timeout = parsed
		}
	}

	sendInput := SendRequestInput{
		RawRequest: rawRequest,
		Target: Target{
			Hostname:  host,
			Port:      port,
			UsesHTTPS: usesHTTPS,
		},
		FollowRedirects: req.FollowRedirects,
		Timeout:         timeout,
	}

	result, err := s.httpBackend.SendRequest(ctx, "sectool-"+replayID, sendInput)
	if err != nil {
		if IsTimeoutError(err) {
			s.writeError(w, http.StatusGatewayTimeout, ErrCodeTimeout, "request timed out", err.Error())
		} else {
			s.writeError(w, http.StatusBadGateway, ErrCodeBackendError, "request failed", err.Error())
		}
		return
	}

	respHeaders := result.Headers
	respBody := result.Body

	var status int
	var statusLine string
	if resp, err := readResponseBytes(respHeaders); err == nil {
		_ = resp.Body.Close()
		status = resp.StatusCode
		statusLine = resp.Proto + " " + resp.Status
	} else {
		log.Printf("replay/send: failed to parse response headers: %v", err)
	}
	log.Printf("replay/send: %s completed in %v (status=%d, size=%d)", replayID, result.Duration, status, len(respBody))

	// Store replay result for later retrieval
	s.requestStore.Store(replayID, &store.RequestEntry{
		Headers:  respHeaders,
		Body:     respBody,
		Duration: result.Duration,
	})

	// Write response to bundle if applicable
	if bundlePath != "" {
		_ = writeResponseToBundle(bundlePath, respHeaders, respBody)
	}

	// Build response
	s.writeJSON(w, http.StatusOK, ReplaySendResponse{
		ReplayID: replayID,
		Duration: result.Duration.String(),
		ResponseDetails: ResponseDetails{
			Status:      status,
			StatusLine:  statusLine,
			RespHeaders: string(respHeaders),
			RespSize:    len(respBody),
			RespPreview: previewBody(respBody, responsePreviewSize),
		},
	})
}

// handleReplayGet handles POST /replay/get
func (s *Server) handleReplayGet(w http.ResponseWriter, r *http.Request) {
	var req ReplayGetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "invalid request body", err.Error())
		return
	} else if req.ReplayID == "" {
		s.writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "replay_id is required", "")
		return
	}

	log.Printf("replay/get: retrieving %s", req.ReplayID)
	result, ok := s.requestStore.Get(req.ReplayID)
	if !ok {
		s.writeError(w, http.StatusNotFound, ErrCodeNotFound,
			"replay not found", "replay results are ephemeral and cleared on service restart")
		return
	}

	var status int
	var statusLine string
	if resp, err := readResponseBytes(result.Headers); err == nil {
		_ = resp.Body.Close()
		status = resp.StatusCode
		statusLine = resp.Proto + " " + resp.Status
	} else {
		log.Printf("replay/get: failed to parse response headers: %v", err)
	}

	s.writeJSON(w, http.StatusOK, ReplayGetResponse{
		ReplayID:    req.ReplayID,
		Duration:    result.Duration.String(),
		Status:      status,
		StatusLine:  statusLine,
		RespHeaders: string(result.Headers),
		RespBody:    base64.StdEncoding.EncodeToString(result.Body),
		RespSize:    len(result.Body),
	})
}

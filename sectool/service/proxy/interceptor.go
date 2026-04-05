package proxy

import (
	"net"
	"net/http"
	"strconv"
	"strings"
)

// InterceptedResponse is a canned response to serve for an intercepted request.
type InterceptedResponse struct {
	StatusCode int
	Headers    Headers
	Body       []byte
}

// ResponseInterceptor checks if a request should be intercepted with a canned response.
// Implementations must be safe for concurrent use and fast (no I/O on the hot path).
type ResponseInterceptor interface {
	// InterceptRequest checks if a request matches a registered responder.
	// host is the target hostname (lowercase), port is the target port,
	// path is the URL path (query string stripped), method is the HTTP method.
	// Returns the response to serve, or nil if no match.
	InterceptRequest(host string, port int, path string, method string) *InterceptedResponse
}

// BuildInterceptedH1Response converts an InterceptedResponse to a wire-serializable RawHTTP1Response.
func BuildInterceptedH1Response(intercepted *InterceptedResponse) *RawHTTP1Response {
	resp := &RawHTTP1Response{
		Version:    "HTTP/1.1",
		StatusCode: intercepted.StatusCode,
		StatusText: http.StatusText(intercepted.StatusCode),
		Headers:    make(Headers, len(intercepted.Headers)),
		Body:       intercepted.Body,
	}
	copy(resp.Headers, intercepted.Headers)
	return resp
}

// ParseAuthority extracts host and port from an HTTP/2 :authority pseudo-header.
// Handles forms like "example.com", "example.com:8443", "[::1]:8080".
// scheme is used to determine default port ("https" -> 443, else 80).
func ParseAuthority(authority, scheme string) (string, int) {
	defaultPort := 80
	if scheme == "https" {
		defaultPort = 443
	}

	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		// No port in authority
		return strings.ToLower(authority), defaultPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return strings.ToLower(host), defaultPort
	}
	return strings.ToLower(host), port
}

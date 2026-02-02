package replay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-appsec/llm-security-toolbox/sectool/bundle"
	"github.com/go-appsec/llm-security-toolbox/sectool/mcpclient"
	"github.com/go-appsec/llm-security-toolbox/sectool/protocol"
	"github.com/go-appsec/llm-security-toolbox/sectool/service"
)

func send(mcpURL string, timeout time.Duration, flow, bundleArg, file, body, target string, headers, removeHeaders []string,
	path, query string, setQuery, removeQuery []string,
	setJSON, removeJSON []string,
	followRedirects bool, requestTimeout time.Duration, force bool) error {
	if flow == "" && bundleArg == "" && file == "" {
		return errors.New("one of --flow, --bundle, or --file is required")
	}

	if file == "-" && body == "-" {
		return errors.New("cannot use --file - with --body - (both read from stdin)")
	}

	// read in customized body content if specified
	var hasBodyOverride bool
	var bodyOverride []byte
	if body != "" {
		var err error
		if body == "-" {
			bodyOverride, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read body from stdin: %w", err)
			}
		} else {
			bodyOverride, err = os.ReadFile(body)
			if err != nil {
				return fmt.Errorf("failed to read body file: %w", err)
			}
		}
		hasBodyOverride = true
	}

	// Build setJSON map
	var setJSONMap map[string]interface{}
	if len(setJSON) > 0 {
		setJSONMap = make(map[string]interface{})
		for _, kv := range setJSON {
			if idx := strings.Index(kv, "="); idx > 0 {
				key := kv[:idx]
				value := kv[idx+1:]
				setJSONMap[key] = value
			} else {
				// key without = means set to null
				setJSONMap[kv] = nil
			}
		}
	}

	if bundleArg != "" {
		return sendFromBundle(mcpURL, timeout, bundleArg, target, headers, removeHeaders, path, query, setQuery, removeQuery, setJSONMap, removeJSON, bodyOverride, hasBodyOverride, followRedirects, requestTimeout)
	}

	if file != "" {
		return sendFromFile(mcpURL, timeout, file, target, headers, removeHeaders, path, query, setQuery, removeQuery, setJSONMap, removeJSON, bodyOverride, hasBodyOverride, followRedirects, requestTimeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	var timeoutStr string
	if requestTimeout > 0 {
		timeoutStr = requestTimeout.String()
	}

	var bodyContent string
	if hasBodyOverride {
		bodyContent = string(bodyOverride)
	}

	resp, err := client.ReplaySend(ctx, mcpclient.ReplaySendOpts{
		FlowID:          flow,
		Body:            bodyContent,
		Target:          target,
		AddHeaders:      headers,
		RemoveHeaders:   removeHeaders,
		Path:            path,
		Query:           query,
		SetQuery:        setQuery,
		RemoveQuery:     removeQuery,
		SetJSON:         setJSONMap,
		RemoveJSON:      removeJSON,
		FollowRedirects: followRedirects,
		Timeout:         timeoutStr,
		Force:           force,
	})
	if err != nil {
		return fmt.Errorf("replay send failed: %w", err)
	}

	fmt.Printf("## Replay Result\n\n")
	fmt.Printf("Replay ID: `%s`\n", resp.ReplayID)
	fmt.Printf("Duration: %s\n\n", resp.Duration)

	fmt.Printf("### Response\n\n")
	fmt.Printf("Status: %d %s\n", resp.Status, resp.StatusLine)
	fmt.Printf("Size: %d bytes\n\n", resp.RespSize)
	if resp.RespHeaders != "" {
		fmt.Printf("Headers:\n```\n%s```\n\n", resp.RespHeaders)
	}
	if resp.RespPreview != "" {
		fmt.Printf("Body Preview:\n```\n%s\n```\n", resp.RespPreview)
	}

	return nil
}

func get(mcpURL string, timeout time.Duration, replayID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.ReplayGet(ctx, replayID)
	if err != nil {
		return fmt.Errorf("replay get failed: %w", err)
	}

	fmt.Printf("## Replay Details\n\n")
	fmt.Printf("Replay ID: `%s`\n", resp.ReplayID)
	fmt.Printf("Duration: %s\n", resp.Duration)
	fmt.Printf("Status: %d %s\n", resp.Status, resp.StatusLine)
	fmt.Printf("Size: %d bytes\n\n", resp.RespSize)
	if resp.RespHeaders != "" {
		fmt.Printf("Headers:\n```\n%s```\n\n", resp.RespHeaders)
	}

	if resp.RespBody != "" {
		body, err := base64.StdEncoding.DecodeString(resp.RespBody)
		if err != nil {
			fmt.Printf("Body: (failed to decode: %v)\n", err)
		} else {
			fmt.Printf("Body:\n```\n%s\n```\n", string(body))
		}
	}

	return nil
}

func create(_ string, _ time.Duration, urlArg, method string, headers []string, bodyPath string) error {
	// Parse and normalize URL
	if !strings.Contains(urlArg, "://") {
		urlArg = "https://" + urlArg
	}

	// Read body if specified
	var bodyBytes []byte
	if bodyPath != "" {
		var err error
		if bodyPath == "-" {
			bodyBytes, err = io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read body from stdin: %w", err)
			}
		} else {
			bodyBytes, err = os.ReadFile(bodyPath)
			if err != nil {
				return fmt.Errorf("failed to read body file: %w", err)
			}
		}
	}

	// Build raw HTTP request headers
	var reqBuilder strings.Builder
	reqBuilder.WriteString(method + " " + urlArg + " HTTP/1.1\r\n")

	// Extract host from URL for Host header
	if idx := strings.Index(urlArg, "://"); idx >= 0 {
		hostPart := urlArg[idx+3:]
		if pathIdx := strings.Index(hostPart, "/"); pathIdx > 0 {
			hostPart = hostPart[:pathIdx]
		}
		reqBuilder.WriteString("Host: " + hostPart + "\r\n")
	}

	// Add user headers
	for _, h := range headers {
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			return fmt.Errorf("invalid header format (missing ':'): %q", h)
		}
		reqBuilder.WriteString(strings.TrimSpace(name) + ": " + strings.TrimSpace(value) + "\r\n")
	}

	// Add Content-Length if body present
	if len(bodyBytes) > 0 {
		reqBuilder.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(bodyBytes)))
	}

	// Generate a bundle ID
	bundleID := fmt.Sprintf("new_%d", time.Now().UnixNano()%1000000)

	// Write bundle to disk
	bundlePath, err := bundle.Write(bundleID,
		urlArg, method, reqBuilder.String(),
		bodyBytes, "", nil)
	if err != nil {
		return fmt.Errorf("write bundle: %w", err)
	}

	fmt.Printf("## Bundle Created\n\n")
	fmt.Printf("Bundle ID: `%s`\n", bundleID)
	fmt.Printf("Path: `%s`\n\n", bundlePath)
	fmt.Printf("Files created:\n")
	fmt.Printf("- `%s/request.http` - HTTP headers (edit this)\n", bundlePath)
	fmt.Printf("- `%s/body` - Request body (edit this)\n", bundlePath)
	fmt.Printf("- `%s/request.meta.json` - Metadata\n\n", bundlePath)
	fmt.Printf("To send: `sectool replay send --bundle %s`\n", bundleID)

	return nil
}

func sendFromBundle(mcpURL string, timeout time.Duration, bundleArg, target string, addHeaders, removeHeaders []string,
	path, query string, setQuery, removeQuery []string,
	setJSON map[string]interface{}, removeJSON []string,
	bodyOverride []byte, hasBodyOverride bool,
	followRedirects bool, requestTimeout time.Duration) error {
	bundlePath, err := bundle.ResolvePath(bundleArg)
	if err != nil {
		return err
	}

	rawHeaders, body, meta, err := bundle.Read(bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}

	if hasBodyOverride {
		body = bodyOverride
	}
	if len(setJSON) > 0 || len(removeJSON) > 0 {
		body, err = service.ModifyJSONBodyMap(body, setJSON, removeJSON)
		if err != nil {
			return err
		}
	}

	// Parse headers from bundle request.http content
	headerMap, err := parseHeaders(rawHeaders)
	if err != nil {
		return fmt.Errorf("parse headers: %w", err)
	}

	headerMap = applyHeaderModifications(headerMap, addHeaders, removeHeaders)
	deleteHeaderCaseInsensitive(headerMap, "Content-Length")

	urlStr, err := applyURLModifications(meta.URL, target, path, query, setQuery, removeQuery)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	var timeoutStr string
	if requestTimeout > 0 {
		timeoutStr = requestTimeout.String()
	}

	resp, err := client.RequestSend(ctx, mcpclient.RequestSendOpts{
		URL:             urlStr,
		Method:          meta.Method,
		Headers:         headerMap,
		Body:            string(body),
		FollowRedirects: followRedirects,
		Timeout:         timeoutStr,
	})
	if err != nil {
		return fmt.Errorf("request send: %w", err)
	}

	printReplayResult(resp)
	return nil
}

func sendFromFile(mcpURL string, timeout time.Duration, file, target string, addHeaders, removeHeaders []string,
	path, query string, setQuery, removeQuery []string,
	setJSON map[string]interface{}, removeJSON []string,
	bodyOverride []byte, hasBodyOverride bool,
	followRedirects bool, requestTimeout time.Duration) error {
	data, err := readRequestData(file)
	if err != nil {
		return err
	}

	// Parse raw HTTP request
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return fmt.Errorf("parse HTTP request: %w", err)
	}
	defer func() { _ = req.Body.Close() }()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	if hasBodyOverride {
		body = bodyOverride
	}
	if len(setJSON) > 0 || len(removeJSON) > 0 {
		body, err = service.ModifyJSONBodyMap(body, setJSON, removeJSON)
		if err != nil {
			return err
		}
	}

	// Build headers map
	headerMap := make(map[string]string)
	for name, values := range req.Header {
		if len(values) > 0 {
			headerMap[name] = values[0]
		}
	}

	headerMap = applyHeaderModifications(headerMap, addHeaders, removeHeaders)
	deleteHeaderCaseInsensitive(headerMap, "Content-Length")

	baseURL, err := buildURLFromHTTPRequest(req, target)
	if err != nil {
		return err
	}
	urlStr, err := applyURLModifications(baseURL, "", path, query, setQuery, removeQuery)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	var timeoutStr string
	if requestTimeout > 0 {
		timeoutStr = requestTimeout.String()
	}

	resp, err := client.RequestSend(ctx, mcpclient.RequestSendOpts{
		URL:             urlStr,
		Method:          req.Method,
		Headers:         headerMap,
		Body:            string(body),
		FollowRedirects: followRedirects,
		Timeout:         timeoutStr,
	})
	if err != nil {
		return fmt.Errorf("request send: %w", err)
	}

	printReplayResult(resp)
	return nil
}

func readRequestData(file string) ([]byte, error) {
	if file == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("read request from stdin: %w", err)
		}
		return data, nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return data, nil
}

func applyHeaderModifications(headers map[string]string, addHeaders, removeHeaders []string) map[string]string {
	result := make(map[string]string, len(headers))
	for k, v := range headers {
		result[k] = v
	}

	for _, name := range removeHeaders {
		deleteHeaderCaseInsensitive(result, name)
	}
	for _, h := range addHeaders {
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		result[textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(name))] = strings.TrimSpace(value)
	}

	return result
}

func deleteHeaderCaseInsensitive(headers map[string]string, name string) {
	name = strings.TrimSpace(name)
	for k := range headers {
		if strings.EqualFold(k, name) {
			delete(headers, k)
		}
	}
}

func applyURLModifications(baseURL, target, path, query string, setQuery, removeQuery []string) (string, error) {
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	result := parsedBase
	if target != "" {
		parsedTarget, err := url.Parse(target)
		if err != nil {
			return "", fmt.Errorf("invalid target URL: %w", err)
		}
		parsedTarget.Path = parsedBase.Path
		parsedTarget.RawQuery = parsedBase.RawQuery
		result = parsedTarget
	}

	if path != "" {
		result.Path = path
	}

	if query != "" {
		result.RawQuery = query
	} else if len(setQuery) > 0 || len(removeQuery) > 0 {
		values, _ := url.ParseQuery(result.RawQuery)
		for _, key := range removeQuery {
			values.Del(key)
		}
		for _, kv := range setQuery {
			if key, val, ok := strings.Cut(kv, "="); ok {
				values.Set(key, val)
			}
		}
		result.RawQuery = values.Encode()
	}

	return result.String(), nil
}

func buildURLFromHTTPRequest(req *http.Request, target string) (string, error) {
	if target != "" {
		parsedTarget, err := url.Parse(target)
		if err != nil {
			return "", fmt.Errorf("invalid target URL: %w", err)
		}
		parsedTarget.Path = req.URL.Path
		parsedTarget.RawQuery = req.URL.RawQuery
		return parsedTarget.String(), nil
	}

	host := req.Host
	if host == "" {
		host = req.Header.Get("Host")
	}
	if host == "" {
		return "", errors.New("no Host header and no --target specified")
	}

	scheme := "https"
	if strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.") {
		scheme = "http"
	}

	return scheme + "://" + host + req.URL.RequestURI(), nil
}

// parseHeaders extracts headers from bundle request.http content.
// Handles body placeholder removal, request line skipping, and MIME parsing.
func parseHeaders(raw []byte) (map[string]string, error) {
	raw = bytes.Replace(raw, []byte(bundle.BodyPlaceholder+"\n"), nil, 1)

	// Find end of headers
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx == -1 {
		idx = bytes.Index(raw, []byte("\n\n"))
	}
	if idx > 0 {
		raw = raw[:idx]
	}

	// Skip request line
	lineEnd := bytes.Index(raw, []byte("\r\n"))
	if lineEnd == -1 {
		lineEnd = bytes.Index(raw, []byte("\n"))
	}
	if lineEnd > 0 {
		raw = raw[lineEnd+1:]
		if len(raw) > 0 && raw[0] == '\n' {
			raw = raw[1:]
		}
	}

	reader := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw)))
	mimeHeaders, err := reader.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	headerMap := make(map[string]string)
	for name, values := range mimeHeaders {
		if len(values) > 0 {
			headerMap[name] = values[0]
		}
	}
	return headerMap, nil
}

func printReplayResult(resp *protocol.ReplaySendResponse) {
	fmt.Printf("## Replay Result\n\n")
	fmt.Printf("Replay ID: `%s`\n", resp.ReplayID)
	fmt.Printf("Duration: %s\n\n", resp.Duration)

	fmt.Printf("### Response\n\n")
	fmt.Printf("Status: %d %s\n", resp.Status, resp.StatusLine)
	fmt.Printf("Size: %d bytes\n\n", resp.RespSize)
	if resp.RespHeaders != "" {
		fmt.Printf("Headers:\n```\n%s```\n\n", resp.RespHeaders)
	}
	if resp.RespPreview != "" {
		fmt.Printf("Body Preview:\n```\n%s\n```\n", resp.RespPreview)
	}
}

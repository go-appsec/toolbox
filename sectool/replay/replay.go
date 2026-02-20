package replay

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-appsec/toolbox/sectool/bundle"
	"github.com/go-appsec/toolbox/sectool/cliutil"
	"github.com/go-appsec/toolbox/sectool/mcpclient"
	"github.com/go-appsec/toolbox/sectool/protocol"
)

// rejectModificationFlags returns an error if any modification-only flags are
// set. These flags only apply to --flow; --bundle and --file should be edited directly.
func rejectModificationFlags(target string, headers, removeHeaders []string,
	path, query string, setQuery, removeQuery []string,
	setJSON, removeJSON []string) error {
	var offending []string
	if target != "" {
		offending = append(offending, "--target")
	}
	if len(headers) > 0 {
		offending = append(offending, "--set-header")
	}
	if len(removeHeaders) > 0 {
		offending = append(offending, "--remove-header")
	}
	if path != "" {
		offending = append(offending, "--path")
	}
	if query != "" {
		offending = append(offending, "--query")
	}
	if len(setQuery) > 0 {
		offending = append(offending, "--set-query")
	}
	if len(removeQuery) > 0 {
		offending = append(offending, "--remove-query")
	}
	if len(setJSON) > 0 {
		offending = append(offending, "--set-json")
	}
	if len(removeJSON) > 0 {
		offending = append(offending, "--remove-json")
	}
	if len(offending) == 0 {
		return nil
	}
	return fmt.Errorf("modification flags (%s) are only supported with --flow; edit the source files directly for --bundle or --file",
		strings.Join(offending, ", "))
}

func send(mcpURL string, flow, bundleArg, file, body, target string, headers, removeHeaders []string,
	path, query string, setQuery, removeQuery []string,
	setJSON, removeJSON []string,
	followRedirects bool, force bool) error {
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
		if err := rejectModificationFlags(target, headers, removeHeaders, path, query, setQuery, removeQuery, setJSON, removeJSON); err != nil {
			return err
		}
		return sendFromBundle(mcpURL, bundleArg, bodyOverride, hasBodyOverride, followRedirects, force)
	}

	if file != "" {
		if err := rejectModificationFlags(target, headers, removeHeaders, path, query, setQuery, removeQuery, setJSON, removeJSON); err != nil {
			return err
		}
		return sendFromFile(mcpURL, file, bodyOverride, hasBodyOverride, followRedirects, force)
	}

	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	var bodyContent string
	if hasBodyOverride {
		bodyContent = string(bodyOverride)
	}

	resp, err := client.ReplaySend(ctx, mcpclient.ReplaySendOpts{
		FlowID:          flow,
		Body:            bodyContent,
		Target:          target,
		SetHeaders:      headers,
		RemoveHeaders:   removeHeaders,
		Path:            path,
		Query:           query,
		SetQuery:        setQuery,
		RemoveQuery:     removeQuery,
		SetJSON:         setJSONMap,
		RemoveJSON:      removeJSON,
		FollowRedirects: followRedirects,
		Force:           force,
	})
	if err != nil {
		return fmt.Errorf("replay send failed: %w", err)
	}

	fmt.Printf("%s\n\n", cliutil.Bold("Replay Result"))
	fmt.Printf("Flow ID: %s\n", cliutil.ID(resp.FlowID))
	fmt.Printf("Duration: %s\n\n", resp.Duration)

	fmt.Printf("%s\n\n", cliutil.Bold("Response"))
	fmt.Printf("Status: %s %s\n", cliutil.FormatStatus(resp.Status), resp.StatusLine)
	fmt.Printf("Size: %d bytes\n\n", resp.RespSize)
	if resp.RespHeaders != "" {
		fmt.Printf("Headers:\n%s\n", resp.RespHeaders)
	}
	if resp.RespPreview != "" {
		fmt.Printf("Body Preview:\n%s\n", resp.RespPreview)
	}

	return nil
}

func get(mcpURL string, flowID string) error {
	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.FlowGet(ctx, flowID, mcpclient.FlowGetOpts{
		Scope: "response_headers,response_body",
	})
	if err != nil {
		return fmt.Errorf("replay get failed: %w", err)
	}

	fmt.Printf("%s\n\n", cliutil.Bold("Replay Details"))
	fmt.Printf("Flow ID: %s\n", cliutil.ID(resp.FlowID))
	if resp.Duration != "" {
		fmt.Printf("Duration: %s\n", resp.Duration)
	}
	fmt.Printf("Status: %s %s\n", cliutil.FormatStatus(resp.Status), resp.StatusLine)
	fmt.Printf("Size: %d bytes\n\n", resp.RespSize)
	if resp.RespHeaders != "" {
		fmt.Printf("Headers:\n%s\n", resp.RespHeaders)
	}

	if resp.RespBody != "" {
		fmt.Printf("Body:\n%s\n", resp.RespBody)
	}

	return nil
}

func create(urlArg, method string, headers []string, bodyPath string) error {
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

	fmt.Printf("%s\n\n", cliutil.Bold("Bundle Created"))
	fmt.Printf("Bundle ID: %s\n", cliutil.ID(bundleID))
	fmt.Printf("Path: %s\n\n", cliutil.ID(bundlePath))
	fmt.Printf("Files created:\n")
	fmt.Printf("  %s/request.http - HTTP headers (edit this)\n", bundlePath)
	fmt.Printf("  %s/body - Request body (edit this)\n", bundlePath)
	fmt.Printf("  %s/request.meta.json - Metadata\n\n", bundlePath)
	cliutil.HintCommand(os.Stdout, "To send", "sectool replay send --bundle "+bundleID)

	return nil
}

func sendFromBundle(mcpURL string, bundleArg string,
	bodyOverride []byte, hasBodyOverride bool,
	followRedirects, force bool) error {
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

	headers, err := parseHeaders(rawHeaders)
	if err != nil {
		return fmt.Errorf("parse headers: %w", err)
	}

	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.RequestSend(ctx, mcpclient.RequestSendOpts{
		URL:             meta.URL,
		Method:          meta.Method,
		Headers:         headers,
		Body:            string(body),
		FollowRedirects: followRedirects,
		Force:           force,
	})
	if err != nil {
		return fmt.Errorf("request send: %w", err)
	}

	printReplayResult(resp)
	return nil
}

func sendFromFile(mcpURL string, file string,
	bodyOverride []byte, hasBodyOverride bool,
	followRedirects, force bool) error {
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

	// Build headers preserving all values
	var headers []string
	for name, values := range req.Header {
		for _, v := range values {
			headers = append(headers, name+": "+v)
		}
	}

	baseURL, err := buildURLFromHTTPRequest(req)
	if err != nil {
		return err
	}

	ctx := context.Background()

	client, err := mcpclient.Connect(ctx, mcpURL)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	resp, err := client.RequestSend(ctx, mcpclient.RequestSendOpts{
		URL:             baseURL,
		Method:          req.Method,
		Headers:         headers,
		Body:            string(body),
		FollowRedirects: followRedirects,
		Force:           force,
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

func buildURLFromHTTPRequest(req *http.Request) (string, error) {
	host := req.Host
	if host == "" {
		host = req.Header.Get("Host")
	}
	if host == "" {
		return "", errors.New("no Host header found in request")
	}

	scheme := "https"
	if strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.") {
		scheme = "http"
	} else if _, port, err := net.SplitHostPort(host); err == nil && port == "80" {
		scheme = "http"
	}

	return scheme + "://" + host + req.URL.RequestURI(), nil
}

// parseHeaders extracts headers from bundle request.http content as "Name: Value" strings.
// Handles body placeholder removal, request line skipping, and obs-fold continuation lines.
func parseHeaders(raw []byte) ([]string, error) {
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

	var headers []string
	for _, line := range bytes.Split(raw, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}
		// obs-fold: continuation line starting with space or tab
		if (line[0] == ' ' || line[0] == '\t') && len(headers) > 0 {
			headers[len(headers)-1] += " " + strings.TrimLeft(string(line), " \t")
			continue
		}
		if bytes.Contains(line, []byte(":")) {
			headers = append(headers, string(line))
		}
	}
	return headers, nil
}

func printReplayResult(resp *protocol.ReplaySendResponse) {
	fmt.Printf("%s\n\n", cliutil.Bold("Replay Result"))
	fmt.Printf("Flow ID: %s\n", cliutil.ID(resp.FlowID))
	fmt.Printf("Duration: %s\n\n", resp.Duration)

	fmt.Printf("%s\n\n", cliutil.Bold("Response"))
	fmt.Printf("Status: %s %s\n", cliutil.FormatStatus(resp.Status), resp.StatusLine)
	fmt.Printf("Size: %d bytes\n\n", resp.RespSize)
	if resp.RespHeaders != "" {
		fmt.Printf("Headers:\n%s\n", resp.RespHeaders)
	}
	if resp.RespPreview != "" {
		fmt.Printf("Body Preview:\n%s\n", resp.RespPreview)
	}
}

package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

const bodyPlaceholder = "[[SECTOOL_BODY_FILE: body.bin]]"

// bundleMeta contains metadata for a request bundle.
type bundleMeta struct {
	BundleID     string `json:"bundle_id"`
	SourceFlowID string `json:"source_flow_id,omitempty"`
	CapturedAt   string `json:"captured_at"`
	URL          string `json:"url"`
	Method       string `json:"method"`
	BodyIsUTF8   bool   `json:"body_is_utf8"`
	BodySize     int    `json:"body_size"`
	Notes        string `json:"notes,omitempty"`
}

func writeBundle(dir string, headers, body []byte, meta *bundleMeta) error {
	log.Printf("bundle: writing to %s (body_size=%d)", dir, len(body))
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create bundle directory: %w", err)
	}

	// Set captured_at if not already set
	if meta.CapturedAt == "" {
		meta.CapturedAt = time.Now().UTC().Format(time.RFC3339)
	}

	// Write request.http with placeholder
	// Remove the existing body (everything after \r\n\r\n) and add placeholder
	headerPart := headers
	if idx := bytes.Index(headerPart, []byte("\r\n\r\n")); idx >= 0 {
		headerPart = headerPart[:idx+4]
	}

	// Clone to break shared memory with body slice (both may reference same underlying array)
	headerPart = bytes.Clone(headerPart)
	requestContent := append(headerPart, []byte(bodyPlaceholder+"\n")...)
	if err := os.WriteFile(filepath.Join(dir, "request.http"), requestContent, 0644); err != nil {
		return fmt.Errorf("failed to write request.http: %w", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "body.bin"), body, 0644); err != nil {
		return fmt.Errorf("failed to write body.bin: %w", err)
	}

	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal meta: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "request.meta.json"), metaBytes, 0644); err != nil {
		return fmt.Errorf("failed to write request.meta.json: %w", err)
	}

	return nil
}

// readBundle reads a request bundle from disk.
func readBundle(dir string) (headers, body []byte, meta *bundleMeta, err error) {
	log.Printf("bundle: reading from %s", dir)
	metaBytes, err := os.ReadFile(filepath.Join(dir, "request.meta.json"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read meta: %w", err)
	}
	meta = &bundleMeta{}
	if err := json.Unmarshal(metaBytes, meta); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse meta: %w", err)
	}

	headers, err = os.ReadFile(filepath.Join(dir, "request.http"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read request: %w", err)
	}

	body, err = os.ReadFile(filepath.Join(dir, "body.bin"))
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, nil, fmt.Errorf("failed to read body: %w", err)
	}
	if body == nil {
		body = []byte{}
	}

	return headers, body, meta, nil
}

// reconstructRequest replaces the body placeholder and rebuilds the request.
func reconstructRequest(headers, body []byte) []byte {
	// Remove placeholder line
	placeholder := []byte(bodyPlaceholder + "\n")
	headers = bytes.Replace(headers, placeholder, nil, 1)

	// Ensure headers end with \r\n\r\n
	if !bytes.HasSuffix(headers, []byte("\r\n\r\n")) {
		if bytes.HasSuffix(headers, []byte("\r\n")) {
			headers = append(headers, []byte("\r\n")...)
		} else {
			headers = append(headers, []byte("\r\n\r\n")...)
		}
	}

	return append(headers, body...)
}

// writeResponseToBundle writes response files to an existing bundle directory.
func writeResponseToBundle(dir string, respHeaders, respBody []byte) error {
	if err := os.WriteFile(filepath.Join(dir, "response.http"), respHeaders, 0644); err != nil {
		return fmt.Errorf("failed to write response.http: %w", err)
	} else if err := os.WriteFile(filepath.Join(dir, "response.body.bin"), respBody, 0644); err != nil {
		return fmt.Errorf("failed to write response.body.bin: %w", err)
	}
	return nil
}

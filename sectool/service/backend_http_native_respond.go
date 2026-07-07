package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/go-appsec/toolbox/sectool/protocol"
	"github.com/go-appsec/toolbox/sectool/service/ids"
	"github.com/go-appsec/toolbox/sectool/service/proxy"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sectool/service/store"
)

const responderKey = "responders"

// nativeStoredResponder is the persistent format for responders.
type nativeStoredResponder struct {
	ID         string            `msgpack:"id"`
	Label      string            `msgpack:"l,omitempty"`
	Host       string            `msgpack:"h"`
	Port       int               `msgpack:"p"`
	Scheme     string            `msgpack:"s"`
	Path       string            `msgpack:"pa"`
	Method     string            `msgpack:"m,omitempty"`
	StatusCode int               `msgpack:"sc"`
	Headers    map[string]string `msgpack:"hd,omitempty"`
	Body       string            `msgpack:"b,omitempty"`
}

func (r *nativeStoredResponder) toEntry() protocol.ResponderEntry {
	origin := r.Scheme + "://" + r.Host
	if (r.Scheme == schemeHTTPS && r.Port != 443) || (r.Scheme == schemeHTTP && r.Port != 80) {
		origin += ":" + strconv.Itoa(r.Port)
	}
	return protocol.ResponderEntry{
		ResponderID: r.ID,
		Origin:      origin,
		Path:        r.Path,
		Method:      r.Method,
		StatusCode:  r.StatusCode,
		Headers:     r.Headers,
		Body:        r.Body,
		Label:       r.Label,
	}
}

// InterceptRequest checks if a request matches a registered responder.
func (b *NativeProxyBackend) InterceptRequest(host string, port int, path string, method string) *proxy.InterceptedResponse {
	b.respondersMu.RLock()
	defer b.respondersMu.RUnlock()

	for _, r := range b.responders {
		if r.Host != host || r.Port != port || r.Path != path {
			continue
		}
		if r.Method != "" && !strings.EqualFold(r.Method, method) {
			continue
		}
		headers := make(types.Headers, 0, len(r.Headers))
		for name, value := range r.Headers {
			headers = append(headers, types.Header{Name: name, Value: value})
		}
		return &proxy.InterceptedResponse{
			StatusCode: r.StatusCode,
			Headers:    headers,
			Body:       []byte(r.Body),
		}
	}
	return nil
}

// AddResponder registers a custom response for a specific origin and path.
func (b *NativeProxyBackend) AddResponder(ctx context.Context, input protocol.ResponderEntry) (*protocol.ResponderEntry, error) {
	host, port, scheme, err := parseOrigin(input.Origin)
	if err != nil {
		return nil, err
	}

	statusCode := input.StatusCode
	if statusCode == 0 {
		statusCode = 200
	}

	b.respondersMu.Lock()
	defer b.respondersMu.Unlock()

	if input.Label != "" {
		if b.responderLabelExists(input.Label) {
			return nil, fmt.Errorf("%w: %s", ErrLabelExists, input.Label)
		}
	}

	r := nativeStoredResponder{
		ID:         ids.Generate(0),
		Label:      input.Label,
		Host:       host,
		Port:       port,
		Scheme:     scheme,
		Path:       input.Path,
		Method:     strings.ToUpper(input.Method),
		StatusCode: statusCode,
		Headers:    input.Headers,
		Body:       input.Body,
	}

	updated := append(slices.Clone(b.responders), r)
	if err := b.saveResponders(updated); err != nil {
		return nil, fmt.Errorf("persist responder: %w", err)
	}
	b.responders = updated

	entry := r.toEntry()
	return &entry, nil
}

// DeleteResponder removes a responder by ID or label.
func (b *NativeProxyBackend) DeleteResponder(ctx context.Context, idOrLabel string) error {
	b.respondersMu.Lock()
	defer b.respondersMu.Unlock()

	for i, r := range b.responders {
		if r.ID == idOrLabel || r.Label == idOrLabel {
			updated := slices.Delete(slices.Clone(b.responders), i, i+1)
			if err := b.saveResponders(updated); err != nil {
				return fmt.Errorf("persist responder: %w", err)
			}
			b.responders = updated
			return nil
		}
	}
	return ErrNotFound
}

// ListResponders returns all registered responders.
func (b *NativeProxyBackend) ListResponders(ctx context.Context) ([]protocol.ResponderEntry, error) {
	b.respondersMu.RLock()
	defer b.respondersMu.RUnlock()

	result := make([]protocol.ResponderEntry, len(b.responders))
	for i, r := range b.responders {
		result[i] = r.toEntry()
	}
	return result, nil
}

// responderLabelExists checks if a label is in use by any responder.
// Caller must hold respondersMu.
func (b *NativeProxyBackend) responderLabelExists(label string) bool {
	for _, r := range b.responders {
		if r.Label == label {
			return true
		}
	}
	return false
}

func (b *NativeProxyBackend) loadResponders() ([]nativeStoredResponder, error) {
	data, found, err := b.responderStorage.Get(responderKey)
	if err != nil {
		return nil, fmt.Errorf("load responders: %w", err)
	} else if !found {
		return nil, nil
	}
	var responders []nativeStoredResponder
	if err := store.Deserialize(data, &responders); err != nil {
		return nil, fmt.Errorf("deserialize responders: %w", err)
	}
	return responders, nil
}

func (b *NativeProxyBackend) saveResponders(responders []nativeStoredResponder) error {
	if len(responders) == 0 {
		return b.responderStorage.Delete(responderKey)
	}
	data, err := store.Serialize(responders)
	if err != nil {
		return fmt.Errorf("serialize responders: %w", err)
	}
	return b.responderStorage.Set(responderKey, data)
}

// parseOrigin parses a scheme://host[:port] origin into components.
func parseOrigin(origin string) (host string, port int, scheme string, err error) {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS) {
		return "", 0, "", errors.New("invalid origin: must be http:// or https://")
	}
	scheme = u.Scheme
	host = u.Hostname()
	if host == "" {
		return "", 0, "", errors.New("invalid origin: missing hostname")
	}
	portStr := u.Port()
	if portStr != "" {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return "", 0, "", fmt.Errorf("invalid origin port: %s", portStr)
		}
	} else if scheme == schemeHTTPS {
		port = 443
	} else {
		port = 80
	}
	return strings.ToLower(host), port, scheme, nil
}

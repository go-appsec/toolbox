package encoding

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"net/url"
)

const (
	typeURL    = "url"
	typeBase64 = "base64"
	typeHTML   = "html"
)

var errInvalidType = errors.New("invalid type: use 'url', 'base64', or 'html'")

// Encode encodes input using the specified type (url, base64, html).
func Encode(input, typ string) (string, error) {
	switch typ {
	case typeURL:
		return url.QueryEscape(input), nil
	case typeBase64:
		return base64.StdEncoding.EncodeToString([]byte(input)), nil
	case typeHTML:
		return html.EscapeString(input), nil
	default:
		return "", errInvalidType
	}
}

// Decode decodes input using the specified type (url, base64, html).
func Decode(input, typ string) (string, error) {
	switch typ {
	case typeURL:
		decoded, err := url.QueryUnescape(input)
		if err != nil {
			return "", fmt.Errorf("URL decode error: %w", err)
		}
		return decoded, nil
	case typeBase64:
		decoded, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			return "", fmt.Errorf("base64 decode error: %w", err)
		}
		return string(decoded), nil
	case typeHTML:
		return html.UnescapeString(input), nil
	default:
		return "", errInvalidType
	}
}

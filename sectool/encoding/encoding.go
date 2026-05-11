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
		// accept padded/unpadded, standard and URL-safe alphabets
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding, base64.RawStdEncoding,
			base64.URLEncoding, base64.RawURLEncoding,
		} {
			if decoded, err := enc.DecodeString(input); err == nil {
				return string(decoded), nil
			}
		}
		return "", errors.New("base64 decode error: invalid input")
	case typeHTML:
		return html.UnescapeString(input), nil
	default:
		return "", errInvalidType
	}
}

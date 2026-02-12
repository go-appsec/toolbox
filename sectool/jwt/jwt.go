package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
)

type Result struct {
	Header    map[string]interface{} `json:"header"`
	Payload   map[string]interface{} `json:"payload"`
	Signature string                 `json:"signature"`
	Expiry    string                 `json:"expiry,omitempty"`
	Issues    []string               `json:"issues,omitempty"`
}

func DecodeJWT(token string) (*Result, error) {
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")
	token = strings.TrimSpace(token)

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT header: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid JWT payload: %w", err)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid JWT header JSON: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("invalid JWT payload JSON: %w", err)
	}

	result := &Result{
		Header:    header,
		Payload:   payload,
		Signature: parts[2],
	}

	if alg, ok := header["alg"]; ok {
		if algStr, ok := alg.(string); ok && strings.EqualFold(algStr, "none") {
			result.Issues = append(result.Issues, "algorithm set to 'none' - signature not verified")
		}
	}

	now := time.Now()

	exp, hasExp := getNumericClaim(payload, "exp")
	if !hasExp {
		result.Issues = append(result.Issues, "no 'exp' claim - token never expires")
	} else {
		expTime := time.Unix(int64(exp), 0)
		if expTime.Before(now) {
			ago := formatDuration(now.Sub(expTime))
			result.Expiry = fmt.Sprintf("expired %s ago", ago)
			result.Issues = append(result.Issues, fmt.Sprintf("token expired %s ago", ago))
		} else {
			result.Expiry = "expires in " + formatDuration(expTime.Sub(now))
		}
	}

	if iat, hasIAT := getNumericClaim(payload, "iat"); hasIAT && hasExp {
		iatTime := time.Unix(int64(iat), 0)
		expTime := time.Unix(int64(exp), 0)
		if expTime.Sub(iatTime) > 30*24*time.Hour {
			result.Issues = append(result.Issues, fmt.Sprintf("long-lived token: %s from issued to expiry", formatDuration(expTime.Sub(iatTime))))
		}
	}

	return result, nil
}

func getNumericClaim(payload map[string]interface{}, key string) (float64, bool) {
	v, ok := payload[key]
	if !ok {
		return 0, false
	}
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return f, true
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}

	days := int(math.Floor(d.Hours() / 24))
	hours := int(math.Floor(d.Hours())) % 24
	minutes := int(math.Floor(d.Minutes())) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

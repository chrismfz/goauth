package goauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// RouteMeSecurityTOTPEnrollStart is the self-service endpoint for beginning
	// TOTP enrollment.
	RouteMeSecurityTOTPEnrollStart = "/me/security/mfa/totp/enroll/start"
)

// TOTPEnrollStartPayload is the normalized enroll-start payload consumed by
// clients/UI code.
type TOTPEnrollStartPayload struct {
	OTPAuthURI string
	Issuer     string
	Account    string
}

// ParseTOTPEnrollStartPayload parses the enroll-start response body and
// supports both current top-level fields and legacy nested payloads.
//
// Supported aliases:
//   - otpauth_url -> otpauth_uri
//   - account_name -> account
func ParseTOTPEnrollStartPayload(statusCode int, body []byte) (*TOTPEnrollStartPayload, error) {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("decode enroll-start payload (status=%d): %w", statusCode, err)
	}

	payload := extractTOTPEnrollStartPayload(root)
	if payload == nil {
		return nil, fmt.Errorf("Enrollment payload missing expected fields (status=%d, body=%s)", statusCode, responseSnippet(body))
	}
	if payload.OTPAuthURI == "" {
		return nil, fmt.Errorf("Enrollment payload missing expected fields (status=%d, body=%s)", statusCode, responseSnippet(body))
	}
	return payload, nil
}

func extractTOTPEnrollStartPayload(obj map[string]any) *TOTPEnrollStartPayload {
	if p := parseTopLevelEnrollment(obj); p != nil {
		return p
	}

	for _, key := range []string{"enrollment", "data", "totp", "result", "payload"} {
		nested, ok := obj[key].(map[string]any)
		if !ok {
			continue
		}
		if p := parseTopLevelEnrollment(nested); p != nil {
			return p
		}
	}

	return nil
}

func parseTopLevelEnrollment(obj map[string]any) *TOTPEnrollStartPayload {
	if obj == nil {
		return nil
	}

	otpauthURI := stringField(obj, "otpauth_uri")
	if otpauthURI == "" {
		otpauthURI = stringField(obj, "otpauth_url")
	}
	issuer := stringField(obj, "issuer")
	account := stringField(obj, "account")
	if account == "" {
		account = stringField(obj, "account_name")
	}

	if otpauthURI == "" && issuer == "" && account == "" {
		return nil
	}
	return &TOTPEnrollStartPayload{
		OTPAuthURI: otpauthURI,
		Issuer:     issuer,
		Account:    account,
	}
}

func stringField(obj map[string]any, key string) string {
	v, ok := obj[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func responseSnippet(body []byte) string {
	s := strings.TrimSpace(string(bytes.TrimSpace(body)))
	const max = 240
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

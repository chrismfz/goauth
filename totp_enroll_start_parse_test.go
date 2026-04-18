package goauth

import (
	"net/http"
	"strings"
	"testing"
)

func TestParseTOTPEnrollStartPayload_TopLevel(t *testing.T) {
	body := []byte(`{"issuer":"goauth","account":"alice@example.com","otpauth_uri":"otpauth://totp/goauth:alice@example.com?secret=ABC&issuer=goauth"}`)

	got, err := ParseTOTPEnrollStartPayload(http.StatusOK, body)
	if err != nil {
		t.Fatalf("ParseTOTPEnrollStartPayload() error = %v", err)
	}
	if got.OTPAuthURI == "" || got.Issuer != "goauth" || got.Account != "alice@example.com" {
		t.Fatalf("unexpected payload: %#v", got)
	}
}

func TestParseTOTPEnrollStartPayload_LegacyNestedAliases(t *testing.T) {
	body := []byte(`{"enrollment":{"issuer":"goauth","account_name":"alice@example.com","otpauth_url":"otpauth://totp/goauth:alice@example.com?secret=ABC&issuer=goauth"}}`)

	got, err := ParseTOTPEnrollStartPayload(http.StatusOK, body)
	if err != nil {
		t.Fatalf("ParseTOTPEnrollStartPayload() error = %v", err)
	}
	if got.OTPAuthURI == "" || got.Account != "alice@example.com" {
		t.Fatalf("unexpected normalized payload: %#v", got)
	}
}

func TestParseTOTPEnrollStartPayload_MissingExpectedFieldsIncludesStatusAndSnippet(t *testing.T) {
	body := []byte(`{"error":"bad gateway"}`)

	_, err := ParseTOTPEnrollStartPayload(http.StatusBadGateway, body)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	errText := err.Error()
	if want := "Enrollment payload missing expected fields"; !strings.Contains(errText, want) {
		t.Fatalf("error %q missing %q", errText, want)
	}
	if want := "status=502"; !strings.Contains(errText, want) {
		t.Fatalf("error %q missing %q", errText, want)
	}
	if want := `{"error":"bad gateway"}`; !strings.Contains(errText, want) {
		t.Fatalf("error %q missing body snippet %q", errText, want)
	}
}

package goauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestLoginMFAVerifyRecoveryCodesAtRegenerationThreshold(t *testing.T) {
	tests := []struct {
		name           string
		codeCount      int
		code           string
		wantStatus     int
		wantRemaining  float64
		wantErrorCode  string
		wantSuccessful bool
	}{
		{
			name:           "two remaining succeeds and requires regeneration",
			codeCount:      2,
			wantStatus:     http.StatusOK,
			wantRemaining:  1,
			wantSuccessful: true,
		},
		{
			name:           "one remaining succeeds and requires regeneration",
			codeCount:      1,
			wantStatus:     http.StatusOK,
			wantRemaining:  0,
			wantSuccessful: true,
		},
		{
			name:          "zero remaining returns exhausted conflict",
			codeCount:     0,
			code:          "AAAA-BBBB-CCCC",
			wantStatus:    http.StatusConflict,
			wantErrorCode: "recovery_codes_exhausted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestMFAManager(t)
			defer m.Close()

			const username = "alice"
			const password = "correct horse battery staple"
			if err := m.Users.Create(username, password, []string{"user"}); err != nil {
				t.Fatalf("Create() error = %v", err)
			}
			if _, err := m.db.Exec(
				`UPDATE users SET mfa_enabled=1, mfa_type='totp' WHERE username=? COLLATE NOCASE`,
				username,
			); err != nil {
				t.Fatalf("enable MFA: %v", err)
			}

			code := tt.code
			if tt.codeCount > 0 {
				codes, err := m.Users.GenerateRecoveryCodes(username, tt.codeCount)
				if err != nil {
					t.Fatalf("GenerateRecoveryCodes() error = %v", err)
				}
				code = codes[0]
			}

			cookie := performLoginForMFATest(t, m, username, password)
			status, body := performMFAVerifyForTest(t, m, cookie, code)

			if status != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body = %#v", status, tt.wantStatus, body)
			}
			if got, _ := body["regenerate_required"].(bool); !got {
				t.Fatalf("regenerate_required = %v, want true; body = %#v", body["regenerate_required"], body)
			}

			if tt.wantSuccessful {
				if got := body["method"]; got != "recovery_code" {
					t.Fatalf("method = %v, want recovery_code; body = %#v", got, body)
				}
				if got := body["recovery_remaining"]; got != tt.wantRemaining {
					t.Fatalf("recovery_remaining = %v, want %v; body = %#v", got, tt.wantRemaining, body)
				}
				return
			}

			if got := body["code"]; got != tt.wantErrorCode {
				t.Fatalf("code = %v, want %s; body = %#v", got, tt.wantErrorCode, body)
			}
		})
	}
}

func newTestMFAManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(Config{
		DBPath:           filepath.Join(t.TempDir(), "auth.db"),
		MFAEncryptionKey: "0123456789abcdef",
		CookieName:       "sid",
		SecureCookie:     false,
		LoginRateLimit:   true,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return m
}

func performLoginForMFATest(t *testing.T, m *Manager, username, password string) *http.Cookie {
	t.Helper()
	body := map[string]string{"username": username, "password": password}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal login payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	m.session.LoadAndSave(m.LoginHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if got, _ := resp["mfa_required"].(bool); !got {
		t.Fatalf("mfa_required = %v, want true; body = %#v", resp["mfa_required"], resp)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login did not set a session cookie")
	}
	return cookies[0]
}

func performMFAVerifyForTest(t *testing.T, m *Manager, cookie *http.Cookie, code string) (int, map[string]any) {
	t.Helper()
	body := map[string]string{"method": "recovery_code", "code": code}
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal MFA payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/login/mfa/verify", bytes.NewReader(payload))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	m.session.LoadAndSave(m.LoginMFAVerifyHandler()).ServeHTTP(rec, req)

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode MFA response status=%d body=%q: %v", rec.Code, rec.Body.String(), err)
	}
	return rec.Code, resp
}

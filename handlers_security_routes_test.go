package goauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMeSecurityRoutesIgnoreSubjectQuery(t *testing.T) {
	m := newTestMFAManager(t)
	defer m.Close()
	createSecurityRouteTestUser(t, m, "alice", "alice-pass", []string{"user"})
	createSecurityRouteTestUser(t, m, "bob", "bob-pass", []string{"user"})
	if _, err := m.db.Exec(`UPDATE users SET mfa_enabled=1, mfa_type='totp' WHERE username='bob'`); err != nil {
		t.Fatalf("enable bob MFA: %v", err)
	}

	cookie := loginCookieForSecurityRouteTest(t, m, "alice", "alice-pass")
	mux := http.NewServeMux()
	m.RegisterMeSecurityRoutes(mux)

	status, resp := performSecurityRouteRequest(t, m, mux, http.MethodGet, "/me/security/factors?subject=bob", cookie, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %#v", status, http.StatusOK, resp)
	}
	if got := resp["subject"]; got != "alice" {
		t.Fatalf("subject = %v, want alice; /me route should ignore subject query", got)
	}
	if got := resp["has_totp"]; got != false {
		t.Fatalf("has_totp = %v, want false for alice", got)
	}
}

func TestAdminSecurityRoutesTargetPathUsername(t *testing.T) {
	m := newTestMFAManager(t)
	defer m.Close()
	createSecurityRouteTestUser(t, m, "admin", "admin-pass", []string{"admin"})
	createSecurityRouteTestUser(t, m, "bob", "bob-pass", []string{"user"})
	if _, err := m.db.Exec(`UPDATE users SET mfa_enabled=1, mfa_type='totp' WHERE username='bob'`); err != nil {
		t.Fatalf("enable bob MFA: %v", err)
	}

	cookie := loginCookieForSecurityRouteTest(t, m, "admin", "admin-pass")
	mux := http.NewServeMux()
	m.RegisterAdminSecurityRoutes(mux)

	status, resp := performSecurityRouteRequest(t, m, mux, http.MethodGet, "/admin/users/bob/security/factors?subject=admin", cookie, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %#v", status, http.StatusOK, resp)
	}
	if got := resp["subject"]; got != "bob" {
		t.Fatalf("subject = %v, want bob; admin route should use path username", got)
	}
	if got := resp["has_totp"]; got != true {
		t.Fatalf("has_totp = %v, want true for bob", got)
	}
}

func createSecurityRouteTestUser(t *testing.T, m *Manager, username, password string, roles []string) {
	t.Helper()
	if err := m.Users.Create(username, password, roles); err != nil {
		t.Fatalf("Create(%q) error = %v", username, err)
	}
}

func loginCookieForSecurityRouteTest(t *testing.T, m *Manager, username, password string) *http.Cookie {
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
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login did not set a session cookie")
	}
	return cookies[0]
}

func performSecurityRouteRequest(t *testing.T, m *Manager, mux *http.ServeMux, method, target string, cookie *http.Cookie, body []byte) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	m.session.LoadAndSave(mux).ServeHTTP(rec, req)

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response status=%d body=%q: %v", rec.Code, rec.Body.String(), err)
	}
	return rec.Code, resp
}

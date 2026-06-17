package goauth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func newTestWebAuthnManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(Config{
		DBPath:                filepath.Join(t.TempDir(), "auth.db"),
		MFAEncryptionKey:      "0123456789abcdef",
		CookieName:            "sid",
		SecureCookie:          false,
		WebAuthnRPID:          "example.com",
		WebAuthnOrigins:       []string{"https://example.com"},
		WebAuthnRPDisplayName: "goauth test",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return m
}

func TestWebAuthnLoginFinishRejectsMismatchedPendingMFAUser(t *testing.T) {
	m := newTestWebAuthnManager(t)
	defer m.Close()

	const (
		passkeyUser = "alice"
		pendingUser = "bob"
		challengeID = "challenge-alice"
	)
	if err := m.Users.Create(passkeyUser, "alice-password", []string{"user"}); err != nil {
		t.Fatalf("Create(%q) error = %v", passkeyUser, err)
	}
	if err := m.Users.Create(pendingUser, "bob-password", []string{"user"}); err != nil {
		t.Fatalf("Create(%q) error = %v", pendingUser, err)
	}
	if err := m.Users.SaveWebAuthnChallenge(challengeID, webauthnCeremonyAuthentication, passkeyUser, `{}`, time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("SaveWebAuthnChallenge() error = %v", err)
	}

	seed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.session.Put(r.Context(), sessionWebAuthnAuthChallengeIDKey, challengeID)
		m.session.Put(r.Context(), sessionWebAuthnLoginModeKey, string(webauthnLoginModePasswordless))
		m.session.Put(r.Context(), sessionMFAPendingUserKey, pendingUser)
		m.session.Put(r.Context(), sessionMFAPendingDeadlineKey, time.Now().Add(5*time.Minute).Format(time.RFC3339Nano))
		w.WriteHeader(http.StatusNoContent)
	})
	seedReq := httptest.NewRequest(http.MethodGet, "/seed", nil)
	seedRec := httptest.NewRecorder()
	m.session.LoadAndSave(seed).ServeHTTP(seedRec, seedReq)
	cookies := seedRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("seed handler did not set a session cookie")
	}

	req := httptest.NewRequest(http.MethodPost, "/login/webauthn/finish", nil)
	req.AddCookie(cookies[0])
	rec := httptest.NewRecorder()
	m.session.LoadAndSave(m.WebAuthnLoginFinishHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("finish status = %d, want %d, body = %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}

	var challengeCount int
	if err := m.db.QueryRow(`SELECT COUNT(*) FROM webauthn_challenges WHERE challenge_id=?`, challengeID).Scan(&challengeCount); err != nil {
		t.Fatalf("count challenge rows: %v", err)
	}
	if challengeCount != 0 {
		t.Fatalf("challenge rows = %d, want 0", challengeCount)
	}

	var event, username, reason string
	if err := m.db.QueryRow(`SELECT event, username, reason FROM auth_log ORDER BY id DESC LIMIT 1`).Scan(&event, &username, &reason); err != nil {
		t.Fatalf("query latest auth_log: %v", err)
	}
	if event != LogEventFail || username != pendingUser || reason != "mfa_passkey_user_mismatch" {
		t.Fatalf("auth_log = (%q, %q, %q), want (%q, %q, %q)", event, username, reason, LogEventFail, pendingUser, "mfa_passkey_user_mismatch")
	}

	checkReq := httptest.NewRequest(http.MethodGet, "/check", nil)
	for _, cookie := range rec.Result().Cookies() {
		checkReq.AddCookie(cookie)
	}
	checkRec := httptest.NewRecorder()
	m.session.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := m.session.GetString(r.Context(), sessionMFAPendingUserKey); got != "" {
			t.Errorf("pending MFA user session value = %q, want empty", got)
		}
		if got := m.session.GetString(r.Context(), sessionWebAuthnLoginModeKey); got != "" {
			t.Errorf("webauthn login mode session value = %q, want empty", got)
		}
	})).ServeHTTP(checkRec, checkReq)
}

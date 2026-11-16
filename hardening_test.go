package goauth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alexedwards/argon2id"
)

func TestClientIPTrustsOnlyTheProxyAppendedEntry(t *testing.T) {
	tests := []struct {
		name, remote string
		xff          []string
		want         string
	}{
		{"direct client, header ignored", "203.0.113.7:4000", []string{"127.0.0.1"}, "203.0.113.7"},
		{"proxy overwrote the header", "127.0.0.1:4000", []string{"198.51.100.9"}, "198.51.100.9"},
		{"proxy appended to a spoofed header", "127.0.0.1:4000", []string{"10.0.0.1, 198.51.100.9"}, "198.51.100.9"},
		{"spoofed header on its own line", "127.0.0.1:4000", []string{"10.0.0.1", "198.51.100.9"}, "198.51.100.9"},
		{"ipv6 loopback proxy", "[::1]:4000", []string{"2001:db8::1"}, "2001:db8::1"},
		{"loopback without header", "127.0.0.1:4000", nil, "127.0.0.1"},
		{"garbage header falls back to peer", "127.0.0.1:4000", []string{"not-an-ip"}, "127.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/login", nil)
			r.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := clientIP(r); got != tt.want {
				t.Fatalf("clientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRateLimiterUsernameKeyIsCaseInsensitive(t *testing.T) {
	rl := newLoginRateLimiter()
	variants := []string{"admin", "Admin", "ADMIN", " admin "}
	blocked := false
	for i := 0; i < rl.maxPerUser+1; i++ {
		// A new source address each time: only the per-username limit can trip.
		ip := "198.51.100." + string(rune('0'+i%10)) + string(rune('0'+i/10))
		if ok, _ := rl.Allow(ip, variants[i%len(variants)]); !ok {
			blocked = true
			if i != rl.maxPerUser {
				t.Fatalf("blocked at attempt %d, want %d", i, rl.maxPerUser)
			}
		}
	}
	if !blocked {
		t.Fatal("case variants of one username were never rate limited")
	}
}

// The dummy comparison for an unknown username must be a real Argon2 run with
// the parameters real hashes use, or response time reveals which names exist.
func TestDummyPasswordHashIsARealHash(t *testing.T) {
	params, _, _, err := argon2id.DecodeHash(dummyPasswordHash())
	if err != nil {
		t.Fatalf("dummy hash does not decode: %v", err)
	}
	if *params != *argon2id.DefaultParams {
		t.Fatalf("dummy hash params = %+v, want %+v", *params, *argon2id.DefaultParams)
	}
	if _, err := argon2id.ComparePasswordAndHash("x", dummyPasswordHash()); err != nil {
		t.Fatalf("comparison against dummy hash failed early: %v", err)
	}
}

func TestLoginRejectsOversizedInput(t *testing.T) {
	m := newTestMFAManager(t)
	defer m.Close()
	h := m.session.LoadAndSave(m.LoginHandler())

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := post(`{"username":"` + strings.Repeat("a", maxRequestBody) + `","password":"x"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if rec := post(`{"username":"` + strings.Repeat("a", maxUsernameLen+1) + `","password":"x"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("long username status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if rec := post(`{"username":"alice","password":"` + strings.Repeat("p", maxPasswordLen+1) + `"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("long password status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}

	m.rl.mu.Lock()
	defer m.rl.mu.Unlock()
	for key := range m.rl.byUser {
		if len(key) > maxUsernameLen+2 {
			t.Fatalf("rate limiter stored a %d-byte username key", len(key))
		}
	}
	var longest int
	if err := m.db.QueryRow(`SELECT COALESCE(MAX(LENGTH(username)),0) FROM auth_log`).Scan(&longest); err != nil {
		t.Fatalf("query auth_log: %v", err)
	}
	if longest > maxUsernameLen {
		t.Fatalf("auth_log stored a %d-byte username", longest)
	}
}

// A password-verified MFA login expires after its deadline on the passkey
// path too, not only on the TOTP one.
func TestWebAuthnLoginRejectsExpiredPendingMFA(t *testing.T) {
	m := newTestWebAuthnManager(t)
	defer m.Close()
	if err := m.Users.Create("alice", "alice-password", []string{"user"}); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	seed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.session.Put(r.Context(), sessionMFAPendingUserKey, "alice")
		m.session.Put(r.Context(), sessionMFAPendingDeadlineKey, time.Now().Add(-time.Second).Format(time.RFC3339Nano))
	})
	seedRec := httptest.NewRecorder()
	m.session.LoadAndSave(seed).ServeHTTP(seedRec, httptest.NewRequest(http.MethodGet, "/seed", nil))
	cookies := seedRec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("seed handler did not set a session cookie")
	}

	req := httptest.NewRequest(http.MethodPost, "/login/webauthn/begin", nil)
	req.AddCookie(cookies[0])
	rec := httptest.NewRecorder()
	m.session.LoadAndSave(m.WebAuthnLoginBeginHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "expired") {
		t.Fatalf("begin = %d %s, want 401 expired", rec.Code, rec.Body.String())
	}

	check := httptest.NewRequest(http.MethodGet, "/check", nil)
	check.AddCookie(cookies[0])
	m.session.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := m.session.GetString(r.Context(), sessionMFAPendingUserKey); got != "" {
			t.Errorf("pending MFA user = %q after expiry, want empty", got)
		}
	})).ServeHTTP(httptest.NewRecorder(), check)
}

func TestSaveWebAuthnChallengePrunesExpiredRows(t *testing.T) {
	m := newTestWebAuthnManager(t)
	defer m.Close()
	if err := m.Users.SaveWebAuthnChallenge("old", webauthnCeremonyAuthentication, "alice", `{}`, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("save old: %v", err)
	}
	if err := m.Users.SaveWebAuthnChallenge("new", webauthnCeremonyAuthentication, "alice", `{}`, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("save new: %v", err)
	}
	var ids string
	if err := m.db.QueryRow(`SELECT GROUP_CONCAT(challenge_id) FROM webauthn_challenges`).Scan(&ids); err != nil {
		t.Fatalf("query: %v", err)
	}
	if ids != "new" {
		t.Fatalf("challenge rows = %q, want only the live one", ids)
	}
}

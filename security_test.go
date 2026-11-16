package goauth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// testClient drives handlers through the session middleware and keeps the
// session cookie between calls, like a browser.
type testClient struct {
	t       *testing.T
	m       *Manager
	cookies map[string]*http.Cookie
}

func newTestClient(t *testing.T, m *Manager) *testClient {
	return &testClient{t: t, m: m, cookies: map[string]*http.Cookie{}}
}

func (c *testClient) do(h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if raw, ok := body.([]byte); ok {
			buf.Write(raw)
		} else if err := json.NewEncoder(&buf).Encode(body); err != nil {
			c.t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Origin", "https://example.com")
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	c.m.session.LoadAndSave(h).ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.MaxAge < 0 {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck
		}
	}
	return rec
}

func (c *testClient) login(username, password string) *httptest.ResponseRecorder {
	c.t.Helper()
	return c.do(c.m.LoginHandler(), http.MethodPost, "/login", map[string]string{"username": username, "password": password})
}

// authed reports whether a Require()-guarded handler lets the client in, and
// the roles it saw.
func (c *testClient) authed(roles ...string) (bool, []string) {
	c.t.Helper()
	var seen []string
	rec := c.do(c.m.Require(roles...)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _ := UserFromContext(r.Context())
		seen = u.Roles
		if !c.m.IsAuthenticated(r) {
			c.t.Error("Require passed but IsAuthenticated is false")
		}
	})), http.MethodGet, "/guarded", nil)
	return rec.Code == http.StatusOK, seen
}

func mustCreate(t *testing.T, m *Manager, username, password string, roles ...string) {
	t.Helper()
	if err := m.Users.Create(username, password, roles); err != nil {
		t.Fatalf("Create(%q): %v", username, err)
	}
}

const testPassword = "correct horse battery staple"

func TestSessionsEndWhenTheAccountChanges(t *testing.T) {
	tests := []struct {
		name   string
		change func(m *Manager) error
	}{
		{"password reset", func(m *Manager) error { return m.Users.SetPassword("alice", "a whole new password") }},
		{"account disabled", func(m *Manager) error { return m.Users.SetActive("alice", false) }},
		{"account deleted", func(m *Manager) error { return m.Users.Delete("alice") }},
		{"sessions revoked", func(m *Manager) error { return m.Users.RevokeSessions("ALICE") }},
		{"disabled then enabled again", func(m *Manager) error {
			if err := m.Users.SetActive("alice", false); err != nil {
				return err
			}
			return m.Users.SetActive("alice", true)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestMFAManager(t)
			defer m.Close()
			mustCreate(t, m, "alice", testPassword, "user")
			c := newTestClient(t, m)
			if rec := c.login("alice", testPassword); rec.Code != http.StatusOK {
				t.Fatalf("login = %d %s", rec.Code, rec.Body.String())
			}
			if ok, _ := c.authed(); !ok {
				t.Fatal("fresh session was not accepted")
			}
			if err := tt.change(m); err != nil {
				t.Fatalf("change: %v", err)
			}
			if ok, _ := c.authed(); ok {
				t.Fatal("session survived the change")
			}
			if rec := c.do(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if m.IsAuthenticated(r) {
					t.Error("IsAuthenticated is still true")
				}
			}), http.MethodGet, "/", nil); rec.Code != http.StatusOK {
				t.Fatalf("probe = %d", rec.Code)
			}
		})
	}
}

func TestRoleChangeAppliesToOpenSessions(t *testing.T) {
	m := newTestMFAManager(t)
	defer m.Close()
	mustCreate(t, m, "alice", testPassword, "admin")
	c := newTestClient(t, m)
	c.login("alice", testPassword)
	if ok, _ := c.authed("admin"); !ok {
		t.Fatal("admin was refused")
	}
	if err := m.Users.SetRoles("alice", []string{"viewer"}); err != nil {
		t.Fatalf("SetRoles: %v", err)
	}
	if ok, _ := c.authed("admin"); ok {
		t.Fatal("demoted user still passes Require(admin)")
	}
	ok, roles := c.authed()
	if !ok || len(roles) != 1 || roles[0] != "viewer" {
		t.Fatalf("after demotion: ok=%v roles=%v, want the session kept with [viewer]", ok, roles)
	}
}

// A change made by another process (the CLI opens its own Manager on the same
// file) reaches a running server once its cached answer expires.
func TestRevocationFromAnotherProcess(t *testing.T) {
	m := newTestMFAManager(t)
	defer m.Close()
	mustCreate(t, m, "alice", testPassword)
	c := newTestClient(t, m)
	c.login("alice", testPassword)
	if ok, _ := c.authed(); !ok {
		t.Fatal("fresh session was not accepted")
	}
	// Straight to the database, as a second process would.
	if _, err := m.db.Exec(`UPDATE users SET active=0 WHERE username='alice'`); err != nil {
		t.Fatal(err)
	}
	m.Users.stateMu.Lock()
	for k, v := range m.Users.state {
		v.at = v.at.Add(-sessionStateTTL - time.Second)
		m.Users.state[k] = v
	}
	m.Users.stateMu.Unlock()
	if ok, _ := c.authed(); ok {
		t.Fatal("session survived an out-of-process disable")
	}
}

// A session written before sessions carried an epoch has none, and a user
// row from then has epoch 0: an upgrade must not log anyone out.
func TestSessionWithoutEpochStaysValidUntilRevoked(t *testing.T) {
	m := newTestMFAManager(t)
	defer m.Close()
	mustCreate(t, m, "alice", testPassword)
	c := newTestClient(t, m)
	c.do(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.session.Put(r.Context(), sessionUsernameKey, "alice")
		m.session.Put(r.Context(), sessionRolesKey, `["user"]`)
	}), http.MethodGet, "/seed", nil)
	if ok, _ := c.authed(); !ok {
		t.Fatal("pre-upgrade session was refused")
	}
	if err := m.Users.RevokeSessions("alice"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.authed(); ok {
		t.Fatal("pre-upgrade session survived a revoke")
	}
}

func TestOwnPasswordChangeKeepsThisSessionAndEndsTheOthers(t *testing.T) {
	m := newTestMFAManager(t)
	defer m.Close()
	mustCreate(t, m, "alice", testPassword)
	here, elsewhere := newTestClient(t, m), newTestClient(t, m)
	here.login("alice", testPassword)
	elsewhere.login("alice", testPassword)

	change := m.Require()(m.selfSecurityPasswordChangeHandler())
	const newPassword = "  spaces are part of it  "
	rec := here.do(change, http.MethodPost, "/me/security/password", map[string]string{
		"current_password": testPassword, "new_password": newPassword,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("change = %d %s", rec.Code, rec.Body.String())
	}
	if ok, _ := here.authed(); !ok {
		t.Fatal("the session that changed the password was logged out")
	}
	if ok, _ := elsewhere.authed(); ok {
		t.Fatal("another session survived the password change")
	}
	// Stored as typed: the same string logs in, the trimmed one does not.
	if rec := newTestClient(t, m).login("alice", newPassword); rec.Code != http.StatusOK {
		t.Fatalf("login with the new password = %d", rec.Code)
	}
	if rec := newTestClient(t, m).login("alice", strings.TrimSpace(newPassword)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("login with the trimmed password = %d, want 401", rec.Code)
	}
}

func TestPasswordChangeEnforcesLengthAndLimitsGuesses(t *testing.T) {
	m := newTestMFAManager(t)
	defer m.Close()
	mustCreate(t, m, "alice", testPassword)
	c := newTestClient(t, m)
	c.login("alice", testPassword)
	change := m.Require()(m.selfSecurityPasswordChangeHandler())

	rec := c.do(change, http.MethodPost, "/me/security/password", map[string]string{
		"current_password": testPassword, "new_password": "short",
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "at least 12") {
		t.Fatalf("short password = %d %s, want 400 at least 12", rec.Code, rec.Body.String())
	}

	// Guessing the current password from inside a session runs out.
	var last int
	for i := 0; i < m.reauthRL.maxPerUser+1; i++ {
		last = c.do(change, http.MethodPost, "/me/security/password", map[string]string{
			"current_password": "wrong guess", "new_password": "a long enough password",
		}).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("after %d wrong guesses status = %d, want 429", m.reauthRL.maxPerUser+1, last)
	}
}

func TestSessionTokenIsStoredHashed(t *testing.T) {
	m := newTestMFAManager(t)
	defer m.Close()
	mustCreate(t, m, "alice", testPassword)
	c := newTestClient(t, m)
	c.login("alice", testPassword)
	token := c.cookies["sid"].Value

	var stored string
	if err := m.sessionDB.QueryRow(`SELECT token FROM sessions`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token || stored != hashSessionToken(token) {
		t.Fatalf("stored token = %q, want the SHA-256 of the cookie value", stored)
	}
	sessions, err := m.ListSessions()
	if err != nil || len(sessions) != 1 || sessions[0].Token == token {
		t.Fatalf("ListSessions = %+v, %v: must not return a usable token", sessions, err)
	}
	if ok, _ := c.authed(); !ok {
		t.Fatal("session lookup by hashed token failed")
	}
}

func TestLegacyPlaintextSessionRowsAreHashedOnOpen(t *testing.T) {
	m := newTestMFAManager(t)
	defer m.Close()
	mustCreate(t, m, "alice", testPassword)
	c := newTestClient(t, m)
	c.login("alice", testPassword)
	token := c.cookies["sid"].Value

	// Put the row back the way an older version wrote it.
	if _, err := m.sessionDB.Exec(`UPDATE sessions SET token=?`, token); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.authed(); ok {
		t.Fatal("test setup: a plaintext row should not be found by hash")
	}
	for i := 0; i < 2; i++ { // the second run must be a no-op
		if err := hashLegacySessionTokens(m.sessionDB); err != nil {
			t.Fatalf("hashLegacySessionTokens: %v", err)
		}
	}
	if ok, _ := c.authed(); !ok {
		t.Fatal("session did not survive the token-hash upgrade")
	}
}

// ── TOTP ─────────────────────────────────────────────────────────────────────

func otpSecret(t *testing.T, body []byte) string {
	t.Helper()
	var resp struct {
		URI string `json:"otpauth_uri"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("enroll start response: %v: %s", err, body)
	}
	u, err := url.Parse(resp.URI)
	if err != nil || u.Query().Get("secret") == "" {
		t.Fatalf("no secret in %q", resp.URI)
	}
	return u.Query().Get("secret")
}

func totpCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// enrollTOTP takes a logged-in client through a first enrollment and returns
// the secret.
func enrollTOTP(t *testing.T, c *testClient) string {
	t.Helper()
	m := c.m
	rec := c.do(m.Require()(m.selfTOTPEnrollStartHandler()), http.MethodPost, RouteMeSecurityTOTPEnrollStart, map[string]string{})
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll start = %d %s", rec.Code, rec.Body.String())
	}
	secret := otpSecret(t, rec.Body.Bytes())
	// One step back, so that the current and next steps stay usable below.
	rec = c.do(m.Require()(m.selfTOTPEnrollConfirmHandler()), http.MethodPost, "/confirm",
		map[string]string{"code": totpCode(t, secret, time.Now().Add(-totpPeriod*time.Second))})
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll confirm = %d %s", rec.Code, rec.Body.String())
	}
	return secret
}

func mfaVerify(c *testClient, code string) *httptest.ResponseRecorder {
	return c.do(c.m.LoginMFAVerifyHandler(), http.MethodPost, "/login/mfa/verify", map[string]string{"method": "totp", "code": code})
}

func TestStartingAnEnrollmentDoesNotRemoveMFA(t *testing.T) {
	m := newTestMFAManager(t)
	defer m.Close()
	mustCreate(t, m, "alice", testPassword)
	c := newTestClient(t, m)
	c.login("alice", testPassword)
	oldSecret := enrollTOTP(t, c)

	// The session alone (no recent MFA proof, no password) must not be able
	// to touch the second factor.
	c.do(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.session.Remove(r.Context(), sessionMFAVerifiedAtKey)
	}), http.MethodGet, "/forget-proof", nil)
	start := m.Require()(m.selfTOTPEnrollStartHandler())
	if rec := c.do(start, http.MethodPost, "/start", map[string]string{}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("re-enroll without proof = %d %s, want 401", rec.Code, rec.Body.String())
	}
	if rec := c.do(start, http.MethodPost, "/start", map[string]string{"password": "not the password"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("re-enroll with a wrong password = %d, want 401", rec.Code)
	}

	// With the password it starts, and MFA stays on with the OLD secret.
	rec := c.do(start, http.MethodPost, "/start", map[string]string{"password": testPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("re-enroll with password = %d %s", rec.Code, rec.Body.String())
	}
	newSecret := otpSecret(t, rec.Body.Bytes())
	u, err := m.Users.GetByUsername("alice")
	if err != nil || !u.MFAEnabled {
		t.Fatalf("after starting a re-enrollment MFAEnabled = %v (%v), want still enabled", u != nil && u.MFAEnabled, err)
	}
	fresh := newTestClient(t, m)
	if rec := fresh.login("alice", testPassword); !strings.Contains(rec.Body.String(), "mfa_required") {
		t.Fatalf("login during a pending re-enrollment did not ask for MFA: %s", rec.Body.String())
	}
	if rec := mfaVerify(fresh, totpCode(t, newSecret, time.Now())); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unconfirmed secret was accepted at login: %d", rec.Code)
	}
	if rec := mfaVerify(fresh, totpCode(t, oldSecret, time.Now())); rec.Code != http.StatusOK {
		t.Fatalf("old secret refused during a pending re-enrollment: %d %s", rec.Code, rec.Body.String())
	}

	// Confirming switches over.
	rec = c.do(m.Require()(m.selfTOTPEnrollConfirmHandler()), http.MethodPost, "/confirm",
		map[string]string{"code": totpCode(t, newSecret, time.Now())})
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm = %d %s", rec.Code, rec.Body.String())
	}
	after := newTestClient(t, m)
	after.login("alice", testPassword)
	if rec := mfaVerify(after, totpCode(t, oldSecret, time.Now().Add(totpPeriod*time.Second))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old secret still accepted after the switch: %d", rec.Code)
	}
	if rec := mfaVerify(after, totpCode(t, newSecret, time.Now().Add(totpPeriod*time.Second))); rec.Code != http.StatusOK {
		t.Fatalf("new secret refused after the switch: %d %s", rec.Code, rec.Body.String())
	}
}

func TestTOTPCodeWorksOnce(t *testing.T) {
	m := newTestMFAManager(t)
	defer m.Close()
	mustCreate(t, m, "alice", testPassword)
	c := newTestClient(t, m)
	c.login("alice", testPassword)
	secret := enrollTOTP(t, c)
	code := totpCode(t, secret, time.Now())

	first := newTestClient(t, m)
	first.login("alice", testPassword)
	if rec := mfaVerify(first, code); rec.Code != http.StatusOK {
		t.Fatalf("first use = %d %s", rec.Code, rec.Body.String())
	}
	second := newTestClient(t, m)
	second.login("alice", testPassword)
	if rec := mfaVerify(second, code); rec.Code != http.StatusUnauthorized {
		t.Fatalf("second use of the same code = %d, want 401", rec.Code)
	}
	// An earlier step is refused as well once a later one was used.
	if rec := mfaVerify(second, totpCode(t, secret, time.Now().Add(-totpPeriod*time.Second))); rec.Code != http.StatusUnauthorized {
		t.Fatalf("older code after a newer one = %d, want 401", rec.Code)
	}
	if rec := mfaVerify(second, totpCode(t, secret, time.Now().Add(totpPeriod*time.Second))); rec.Code != http.StatusOK {
		t.Fatalf("next code = %d %s", rec.Code, rec.Body.String())
	}
}

func TestMFACodeGuessesAreLimitedPerUser(t *testing.T) {
	m := newTestMFAManager(t)
	defer m.Close()
	mustCreate(t, m, "alice", testPassword)
	c := newTestClient(t, m)
	c.login("alice", testPassword)
	secret := enrollTOTP(t, c)

	attacker := newTestClient(t, m)
	attacker.login("alice", testPassword)
	for i := 0; i < m.mfaRL.maxPerUser; i++ {
		if rec := mfaVerify(attacker, "000000"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("guess %d = %d, want 401", i, rec.Code)
		}
	}
	// The budget is the user's, not the session's or the code's: even the
	// right code waits now.
	if rec := mfaVerify(attacker, totpCode(t, secret, time.Now())); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt past the limit = %d, want 429", rec.Code)
	}
	// Failed second-factor guesses do not use up the password login budget.
	if rec := newTestClient(t, m).login("alice", testPassword); rec.Code != http.StatusOK {
		t.Fatalf("password step after MFA lockout = %d, want 200 (mfa_required)", rec.Code)
	}
}

func TestMFASuccessClearsTheUsersAttemptCount(t *testing.T) {
	m := newTestMFAManager(t)
	defer m.Close()
	mustCreate(t, m, "alice", testPassword)
	c := newTestClient(t, m)
	c.login("alice", testPassword)
	secret := enrollTOTP(t, c)

	for i := 0; i < m.mfaRL.maxPerUser+2; i++ {
		u := newTestClient(t, m)
		u.login("alice", testPassword)
		// Every login needs a code it has not seen, and the clock offers one
		// per 30 seconds: wind the stored step back instead of waiting.
		if _, err := m.db.Exec(`UPDATE users SET totp_last_step=0 WHERE username='alice'`); err != nil {
			t.Fatal(err)
		}
		if rec := mfaVerify(u, totpCode(t, secret, time.Now())); rec.Code != http.StatusOK {
			t.Fatalf("legitimate login %d = %d %s", i, rec.Code, rec.Body.String())
		}
	}
}

func TestPasskeyLoginBeginDoesNotRevealAccounts(t *testing.T) {
	m := newTestWebAuthnManager(t)
	defer m.Close()
	mustCreate(t, m, "alice", testPassword)
	mustCreate(t, m, "disabled", testPassword)
	if err := m.Users.SetActive("disabled", false); err != nil {
		t.Fatal(err)
	}

	var bodies []string
	for i, name := range []string{"alice", "disabled", "nobody"} {
		c := newTestClient(t, m)
		req := map[string]string{"username": name}
		rec := c.do(m.WebAuthnLoginBeginHandler(), http.MethodPost, "/login/webauthn/begin", req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401", name, rec.Code)
		}
		bodies = append(bodies, rec.Body.String())
		if i > 0 && bodies[i] != bodies[0] {
			t.Fatalf("answer for %q differs from the one for %q:\n%s\n%s", name, "alice", bodies[i], bodies[0])
		}
	}
}

package goauth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
)

const (
	webauthnCeremonyRegistration   = "registration"
	webauthnCeremonyAuthentication = "authentication"
)

type webAuthnUser struct {
	user        *User
	userHandle  []byte
	credentials []webauthnlib.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte {
	return u.userHandle
}

func (u *webAuthnUser) WebAuthnName() string {
	return u.user.Username
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	return u.user.Username
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthnlib.Credential {
	return u.credentials
}

type webAuthnChallengeRecord struct {
	ChallengeID string
	Username    string
	SessionData webauthnlib.SessionData
	ExpiresAt   time.Time
}

type webAuthnLoginBeginRequest struct {
	Username string `json:"username"`
}

type webAuthnLoginMode string

const (
	webauthnLoginModePasswordless webAuthnLoginMode = "passwordless"
	webauthnLoginModeMFA          webAuthnLoginMode = "mfa"
)

func randomTokenHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func (m *Manager) webAuthnEnabled() bool {
	return m.webAuthn != nil
}

func (m *Manager) getWebAuthnUser(username string) (*webAuthnUser, error) {
	user, err := m.Users.GetByUsername(username)
	if err != nil {
		return nil, err
	}
	creds, err := m.Users.ListWebAuthnCredentials(username)
	if err != nil {
		return nil, err
	}
	handle, err := m.Users.GetOrCreateWebAuthnUserHandle(username)
	if err != nil {
		return nil, err
	}
	return &webAuthnUser{user: user, userHandle: handle, credentials: creds}, nil
}

func (m *Manager) storeWebAuthnChallenge(r *http.Request, ceremony, username string, sd *webauthnlib.SessionData, ttl time.Duration) error {
	challengeID, err := randomTokenHex(24)
	if err != nil {
		return fmt.Errorf("create challenge id: %w", err)
	}
	blob, err := json.Marshal(sd)
	if err != nil {
		return fmt.Errorf("encode session data: %w", err)
	}
	expiresAt := time.Now().Add(ttl)
	if err := m.Users.SaveWebAuthnChallenge(challengeID, ceremony, username, string(blob), expiresAt); err != nil {
		return err
	}
	sessionKey := sessionWebAuthnRegChallengeIDKey
	if ceremony == webauthnCeremonyAuthentication {
		sessionKey = sessionWebAuthnAuthChallengeIDKey
	}
	m.session.Put(r.Context(), sessionKey, challengeID)
	return nil
}

func (m *Manager) consumeWebAuthnChallenge(r *http.Request, ceremony string) (*webAuthnChallengeRecord, error) {
	sessionKey := sessionWebAuthnRegChallengeIDKey
	if ceremony == webauthnCeremonyAuthentication {
		sessionKey = sessionWebAuthnAuthChallengeIDKey
	}
	challengeID := m.session.GetString(r.Context(), sessionKey)
	if challengeID == "" {
		return nil, errors.New("no pending webauthn challenge")
	}
	rec, err := m.Users.ConsumeWebAuthnChallenge(challengeID, ceremony)
	if err != nil {
		return nil, err
	}
	m.session.Remove(r.Context(), sessionKey)
	return rec, nil
}

func (m *Manager) WebAuthnRegistrationBeginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !m.webAuthnEnabled() {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "webauthn is not configured"})
			return
		}
		ctxUser, ok := UserFromContext(r.Context())
		if !ok || ctxUser.Username == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
			return
		}

		waUser, err := m.getWebAuthnUser(ctxUser.Username)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not prepare passkey registration"})
			return
		}
		exclusions := make([]webauthnlib.Credential, len(waUser.credentials))
		copy(exclusions, waUser.credentials)
		descriptors := webauthnlib.Credentials(exclusions).CredentialDescriptors()

		options, sd, err := m.webAuthn.BeginRegistration(waUser, webauthnlib.WithExclusions(descriptors))
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not begin passkey registration"})
			return
		}
		if err := m.storeWebAuthnChallenge(r, webauthnCeremonyRegistration, waUser.user.Username, sd, 5*time.Minute); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store registration challenge"})
			return
		}

		writeJSON(w, http.StatusOK, options)
	}
}

func (m *Manager) WebAuthnRegistrationFinishHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !m.webAuthnEnabled() {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "webauthn is not configured"})
			return
		}
		ctxUser, ok := UserFromContext(r.Context())
		if !ok || ctxUser.Username == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
			return
		}

		rec, err := m.consumeWebAuthnChallenge(r, webauthnCeremonyRegistration)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no pending passkey registration challenge"})
			return
		}
		if !strings.EqualFold(rec.Username, ctxUser.Username) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "challenge does not match current user"})
			return
		}
		if time.Now().After(rec.ExpiresAt) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "registration challenge expired"})
			return
		}

		waUser, err := m.getWebAuthnUser(ctxUser.Username)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load user for passkey registration"})
			return
		}
		credential, err := m.webAuthn.FinishRegistration(waUser, rec.SessionData, r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid passkey attestation"})
			return
		}
		if err := m.Users.UpsertWebAuthnCredential(ctxUser.Username, waUser.userHandle, credential); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store passkey credential"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"registered":    true,
			"credential_id": credential.ID,
		})
	}
}

func (m *Manager) WebAuthnLoginBeginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !m.webAuthnEnabled() {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "webauthn is not configured"})
			return
		}

		ip := clientIP(r)
		pendingUser := m.session.GetString(r.Context(), sessionMFAPendingUserKey)
		mode := webauthnLoginModePasswordless
		username := pendingUser

		if username == "" {
			var req webAuthnLoginBeginRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
				return
			}
			username = strings.TrimSpace(req.Username)
			if username == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required when no MFA login is pending"})
				return
			}
		} else {
			mode = webauthnLoginModeMFA
		}

		waUser, err := m.getWebAuthnUser(username)
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid login request"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not begin passkey login"})
			return
		}
		if !waUser.user.Active {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "account is disabled"})
			return
		}
		if len(waUser.credentials) == 0 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no passkey enrolled for user"})
			return
		}
		if mode == webauthnLoginModePasswordless {
			if !waUser.user.MFAEnabled || !strings.EqualFold(waUser.user.MFAType, "passkey") {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "passkey-first login is not enabled for this user"})
				return
			}
		}

		if allowed, retryAfter := m.rl.Allow(ip, username); !allowed {
			secs := int(retryAfter / time.Second)
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
			auditLog(m.db, LogEventRateLimit, username, ip, LogReasonTooManyUser)
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts — please wait before trying again"})
			return
		}

		options, sd, err := m.webAuthn.BeginLogin(waUser)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not begin passkey login"})
			return
		}
		if err := m.storeWebAuthnChallenge(r, webauthnCeremonyAuthentication, username, sd, 5*time.Minute); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store login challenge"})
			return
		}
		m.session.Put(r.Context(), sessionWebAuthnLoginModeKey, string(mode))
		writeJSON(w, http.StatusOK, options)
	}
}

func (m *Manager) finalizeAuthenticatedSession(r *http.Request, user *User) error {
	if err := m.session.RenewToken(r.Context()); err != nil {
		return err
	}
	rolesJSON, _ := json.Marshal(user.Roles)
	m.session.Put(r.Context(), sessionUsernameKey, user.Username)
	m.session.Put(r.Context(), sessionRolesKey, string(rolesJSON))
	m.session.Remove(r.Context(), sessionMFAPendingUserKey)
	m.session.Remove(r.Context(), sessionMFAPendingDeadlineKey)
	m.session.Remove(r.Context(), sessionWebAuthnLoginModeKey)
	return nil
}

func (m *Manager) WebAuthnLoginFinishHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !m.webAuthnEnabled() {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "webauthn is not configured"})
			return
		}
		ip := clientIP(r)

		rec, err := m.consumeWebAuthnChallenge(r, webauthnCeremonyAuthentication)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no pending passkey login challenge"})
			return
		}
		if time.Now().After(rec.ExpiresAt) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "passkey login challenge expired"})
			return
		}

		waUser, err := m.getWebAuthnUser(rec.Username)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid passkey login session"})
			return
		}
		credential, err := m.webAuthn.FinishLogin(waUser, rec.SessionData, r)
		if err != nil {
			auditLog(m.db, LogEventFail, rec.Username, ip, "passkey_assertion_failed")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid passkey assertion"})
			return
		}
		if err := m.Users.UpdateWebAuthnSignCount(rec.Username, credential.ID, credential.Authenticator.SignCount); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update passkey signature state"})
			return
		}

		mode := webAuthnLoginMode(m.session.GetString(r.Context(), sessionWebAuthnLoginModeKey))
		pendingUser := m.session.GetString(r.Context(), sessionMFAPendingUserKey)
		if pendingUser != "" {
			mode = webauthnLoginModeMFA
		}

		if mode == webauthnLoginModePasswordless {
			if !waUser.user.MFAEnabled || !strings.EqualFold(waUser.user.MFAType, "passkey") {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "passkey-first login is not enabled for this user"})
				return
			}
		}

		if err := m.finalizeAuthenticatedSession(r, waUser.user); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
			return
		}
		if mode == webauthnLoginModeMFA {
			m.writeMFAProof(r)
			auditLog(m.db, LogEventSuccess, waUser.user.Username, ip, "mfa_passkey_verified")
		} else {
			auditLog(m.db, LogEventSuccess, waUser.user.Username, ip, "passkey_passwordless")
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"username": waUser.user.Username,
			"roles":    waUser.user.Roles,
			"method":   "passkey",
		})
	}
}

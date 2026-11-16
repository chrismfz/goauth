package goauth

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	webauthnprotocol "github.com/go-webauthn/webauthn/protocol"
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
	// flagsKnown[i] is false for a credential stored before authenticator
	// flags were kept.
	flagsKnown []bool
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
	creds, flagsKnown, err := m.Users.listWebAuthnCredentials(username)
	if err != nil {
		return nil, err
	}
	handle, err := m.Users.GetOrCreateWebAuthnUserHandle(username)
	if err != nil {
		return nil, err
	}
	return &webAuthnUser{user: user, userHandle: handle, credentials: creds, flagsKnown: flagsKnown}, nil
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
	return m.webAuthnRegistrationBeginHandlerWithResolver(m.resolveSecuritySubjectOrWriteError)
}

func (m *Manager) selfWebAuthnRegistrationBeginHandler() http.HandlerFunc {
	return m.webAuthnRegistrationBeginHandlerWithResolver(m.resolveSelfSecuritySubjectOrWriteError)
}

func (m *Manager) webAuthnRegistrationBeginHandlerWithResolver(resolve securitySubjectResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !m.webAuthnEnabled() {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "webauthn is not configured"})
			return
		}
		actor, subject, ok := resolve(w, r, "")
		if !ok {
			return
		}

		// A passkey is a sign-in factor: adding one to your own account takes
		// the same proof as removing MFA. With a session alone, whoever held
		// it could attach their own authenticator and keep it.
		var req mfaDisableRequest
		_ = decodeJSONBody(w, r, &req)
		if !m.reauthenticate(w, r, actor, subject, req.Password) {
			return
		}

		waUser, err := m.getWebAuthnUser(subject)
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
	return m.webAuthnRegistrationFinishHandlerWithResolver(m.resolveSecuritySubjectOrWriteError)
}

func (m *Manager) selfWebAuthnRegistrationFinishHandler() http.HandlerFunc {
	return m.webAuthnRegistrationFinishHandlerWithResolver(m.resolveSelfSecuritySubjectOrWriteError)
}

func (m *Manager) webAuthnRegistrationFinishHandlerWithResolver(resolve securitySubjectResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !m.webAuthnEnabled() {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "webauthn is not configured"})
			return
		}
		_, subject, ok := resolve(w, r, "")
		if !ok {
			return
		}

		rec, err := m.consumeWebAuthnChallenge(r, webauthnCeremonyRegistration)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no pending passkey registration challenge"})
			return
		}
		if !strings.EqualFold(rec.Username, subject) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "challenge does not match current user"})
			return
		}
		if time.Now().After(rec.ExpiresAt) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "registration challenge expired"})
			return
		}

		waUser, err := m.getWebAuthnUser(subject)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load user for passkey registration"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		credential, err := m.webAuthn.FinishRegistration(waUser, rec.SessionData, r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid passkey attestation"})
			return
		}
		if err := m.Users.UpsertWebAuthnCredential(subject, waUser.userHandle, credential); err != nil {
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
			if err := decodeJSONBody(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
				return
			}
			username = strings.TrimSpace(req.Username)
			if username == "" {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required when no MFA login is pending"})
				return
			}
		} else {
			if !m.mfaPendingValid(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "MFA challenge expired; please log in again"})
				return
			}
			mode = webauthnLoginModeMFA
		}

		// Before any lookup: this endpoint takes a username from anyone.
		if len(username) > maxUsernameLen {
			username = username[:maxUsernameLen]
		}
		if allowed, retryAfter := m.rl.Allow(ip, username); !allowed {
			auditLog(m.db, LogEventRateLimit, username, ip, LogReasonTooManyUser)
			writeTooManyAttempts(w, retryAfter, "too many login attempts — please wait before trying again")
			return
		}

		// Without a password-verified login behind it, every refusal reads the
		// same. The separate answers (no such user / disabled / no passkey /
		// not enabled) told anyone which accounts exist and how they sign in.
		refuse := func(status int, detail string) {
			if mode == webauthnLoginModePasswordless {
				status, detail = http.StatusUnauthorized, "passkey login is not available for this account"
			}
			writeJSON(w, status, map[string]string{"error": detail})
		}

		waUser, err := m.getWebAuthnUser(username)
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				refuse(http.StatusUnauthorized, "invalid login request")
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not begin passkey login"})
			return
		}
		if !waUser.user.Active {
			refuse(http.StatusForbidden, "account is disabled")
			return
		}
		if len(waUser.credentials) == 0 {
			refuse(http.StatusUnauthorized, "no passkey enrolled for user")
			return
		}
		if mode == webauthnLoginModePasswordless {
			if !waUser.user.MFAEnabled || !strings.EqualFold(waUser.user.MFAType, "passkey") {
				refuse(http.StatusUnauthorized, "")
				return
			}
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

// mfaPendingValid reports whether the session's password-verified MFA login is
// still inside its deadline, and clears it when it is not. The TOTP verify
// handler always enforced the deadline; the passkey path did not, so a
// password-verified session stayed one passkey touch away from a login for the
// whole session lifetime.
func (m *Manager) mfaPendingValid(r *http.Request) bool {
	raw := m.session.GetString(r.Context(), sessionMFAPendingDeadlineKey)
	deadline, err := time.Parse(time.RFC3339Nano, raw)
	if raw == "" || err != nil || time.Now().After(deadline) {
		m.session.Remove(r.Context(), sessionMFAPendingUserKey)
		m.session.Remove(r.Context(), sessionMFAPendingDeadlineKey)
		return false
	}
	return true
}

// finalizeAuthenticatedSession turns the current session into a logged-in one
// for user: new token (no session fixation), identity, and the user's current
// session epoch, which Require compares on every request. mfaVerified says
// whether a second factor was just checked; a proof left behind by an earlier
// login in the same session is dropped otherwise.
func (m *Manager) finalizeAuthenticatedSession(r *http.Request, user *User, mfaVerified bool) error {
	st, found, err := m.Users.sessionStateFor(user.Username, true)
	if err != nil {
		return err
	}
	if !found || !st.Active {
		return ErrUserInactive
	}
	if err := m.session.RenewToken(r.Context()); err != nil {
		return err
	}
	rolesJSON, _ := json.Marshal(st.Roles)
	m.session.Put(r.Context(), sessionUsernameKey, st.Username)
	m.session.Put(r.Context(), sessionRolesKey, string(rolesJSON))
	m.session.Put(r.Context(), sessionEpochKey, st.Epoch)
	m.session.Remove(r.Context(), sessionMFAPendingUserKey)
	m.session.Remove(r.Context(), sessionMFAPendingDeadlineKey)
	m.session.Remove(r.Context(), sessionWebAuthnLoginModeKey)
	if mfaVerified {
		m.writeMFAProof(r)
	} else {
		m.session.Remove(r.Context(), sessionMFAVerifiedAtKey)
	}
	return nil
}

// adoptCurrentEpoch keeps the current session alive across a change that
// ended the user's sessions (their own password change).
func (m *Manager) adoptCurrentEpoch(r *http.Request, username string) error {
	st, found, err := m.Users.sessionStateFor(username, true)
	if err != nil {
		return err
	}
	if !found {
		return ErrUserNotFound
	}
	if err := m.session.RenewToken(r.Context()); err != nil {
		return err
	}
	m.session.Put(r.Context(), sessionEpochKey, st.Epoch)
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

		mode := webAuthnLoginMode(m.session.GetString(r.Context(), sessionWebAuthnLoginModeKey))
		pendingUser := m.session.GetString(r.Context(), sessionMFAPendingUserKey)
		if pendingUser != "" {
			if !m.mfaPendingValid(r) {
				m.session.Remove(r.Context(), sessionWebAuthnLoginModeKey)
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "MFA challenge expired; please log in again"})
				return
			}
			if !strings.EqualFold(pendingUser, rec.Username) {
				m.session.Remove(r.Context(), sessionWebAuthnLoginModeKey)
				m.session.Remove(r.Context(), sessionMFAPendingUserKey)
				m.session.Remove(r.Context(), sessionMFAPendingDeadlineKey)
				auditLog(m.db, LogEventFail, pendingUser, ip, "mfa_passkey_user_mismatch")
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "passkey challenge does not match pending MFA user"})
				return
			}
			mode = webauthnLoginModeMFA
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		parsed, err := webauthnprotocol.ParseCredentialRequestResponse(r)
		if err != nil {
			auditLog(m.db, LogEventFail, rec.Username, ip, "passkey_assertion_failed")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid passkey assertion"})
			return
		}
		// The library refuses an assertion whose "backup eligible" flag differs
		// from the stored credential's. Flags were not stored at first, so a
		// synced passkey (iCloud, Google) registered then reads as "not
		// eligible" and could never log in. For such a row, take the flag from
		// this assertion once; it is stored below and checked from then on.
		for i := range waUser.credentials {
			if !waUser.flagsKnown[i] && bytes.Equal(waUser.credentials[i].ID, parsed.RawID) {
				waUser.credentials[i].Flags.BackupEligible = parsed.Response.AuthenticatorData.Flags.HasBackupEligible()
			}
		}
		credential, err := m.webAuthn.ValidateLogin(waUser, rec.SessionData, parsed)
		if err != nil {
			auditLog(m.db, LogEventFail, rec.Username, ip, "passkey_assertion_failed")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid passkey assertion"})
			return
		}
		if err := m.Users.recordWebAuthnLogin(rec.Username, credential); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update passkey signature state"})
			return
		}

		if mode == webauthnLoginModePasswordless {
			if !waUser.user.MFAEnabled || !strings.EqualFold(waUser.user.MFAType, "passkey") {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "passkey-first login is not enabled for this user"})
				return
			}
		}

		if err := m.finalizeAuthenticatedSession(r, waUser.user, mode == webauthnLoginModeMFA); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
			return
		}
		if mode == webauthnLoginModeMFA {
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

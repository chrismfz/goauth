package goauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// loginRequest is the JSON body expected by LoginHandler.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// loginMFAVerifyRequest is the JSON body expected by LoginMFAVerifyHandler.
type loginMFAVerifyRequest struct {
	Method string `json:"method"`
	Code   string `json:"code"`
}

type totpEnrollConfirmRequest struct {
	Code string `json:"code"`
}

type mfaDisableRequest struct {
	Password string `json:"password"`
}

type passwordChangeRequest struct {
	Subject         string `json:"subject"`
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type factorsResponse struct {
	Subject                string `json:"subject"`
	HasTOTP                bool   `json:"has_totp"`
	PasskeyCount           int    `json:"passkey_count"`
	RecoveryCodesRemaining int    `json:"recovery_codes_remaining"`
}

const mfaProofWindow = 10 * time.Minute

const (
	recoveryCodeRegenerateThreshold = 2
)

func actorReason(actor, target string) string {
	if sameUsername(actor, target) {
		return "self_service"
	}
	return "admin_scope"
}

type securitySubjectResolver func(w http.ResponseWriter, r *http.Request, requested string) (*User, string, bool)

func (m *Manager) resolveSecuritySubjectOrWriteError(w http.ResponseWriter, r *http.Request, requested string) (*User, string, bool) {
	actor, ok := UserFromContext(r.Context())
	if !ok || strings.TrimSpace(actor.Username) == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return nil, "", false
	}

	requested = strings.TrimSpace(requested)
	if requested == "" {
		requested = strings.TrimSpace(r.URL.Query().Get("subject"))
	}
	if requested == "" || sameUsername(requested, actor.Username) {
		return actor, actor.Username, true
	}
	if hasAnyRole(actor.Roles, []string{"admin"}) {
		return actor, requested, true
	}

	writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
	return nil, "", false
}

func (m *Manager) resolveSelfSecuritySubjectOrWriteError(w http.ResponseWriter, r *http.Request, _ string) (*User, string, bool) {
	actor, ok := UserFromContext(r.Context())
	if !ok || strings.TrimSpace(actor.Username) == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return nil, "", false
	}
	return actor, actor.Username, true
}

// writeTooManyAttempts answers 429 with a Retry-After header.
func writeTooManyAttempts(w http.ResponseWriter, retryAfter time.Duration, msg string) {
	secs := int(retryAfter / time.Second)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
	writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": msg})
}

// checkPassword verifies subject's password for an already logged-in caller
// and writes the error response when it does not hold. These checks are rate
// limited like a login: an open session must not be a place to guess the
// password without limit.
func (m *Manager) checkPassword(w http.ResponseWriter, r *http.Request, subject, password, wrongMsg string) bool {
	if allowed, retryAfter := m.reauthRL.Allow(clientIP(r), subject); !allowed {
		auditLog(m.db, LogEventRateLimit, subject, clientIP(r), "too_many_reauth_attempts")
		writeTooManyAttempts(w, retryAfter, "too many attempts — please wait before trying again")
		return false
	}
	if len(password) > maxPasswordLen {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": wrongMsg})
		return false
	}
	if _, err := m.Users.Authenticate(subject, password); err != nil {
		auditLog(m.db, LogEventFail, subject, clientIP(r), "reauth_bad_password")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": wrongMsg})
		return false
	}
	m.reauthRL.ResetUser(subject)
	return true
}

// reauthenticate guards a change to the caller's own sign-in factors: it
// passes on a recent MFA proof in this session, or else on the password.
// An admin acting on another user is not asked (the admin role is the proof).
func (m *Manager) reauthenticate(w http.ResponseWriter, r *http.Request, actor *User, subject, password string) bool {
	if !sameUsername(actor.Username, subject) || m.hasRecentMFAProof(r) {
		return true
	}
	if password == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "re-authentication required (password or recent MFA proof)",
		})
		return false
	}
	return m.checkPassword(w, r, subject, password, "invalid password")
}

// SecurityPasswordChangeHandler changes the authenticated user's password.
// A different subject can only be targeted by callers with admin role.
func (m *Manager) SecurityPasswordChangeHandler() http.HandlerFunc {
	return m.securityPasswordChangeHandlerWithResolver(m.resolveSecuritySubjectOrWriteError)
}

func (m *Manager) selfSecurityPasswordChangeHandler() http.HandlerFunc {
	return m.securityPasswordChangeHandlerWithResolver(m.resolveSelfSecuritySubjectOrWriteError)
}

func (m *Manager) securityPasswordChangeHandlerWithResolver(resolve securitySubjectResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req passwordChangeRequest
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		actor, subject, ok := resolve(w, r, req.Subject)
		if !ok {
			return
		}

		// Passwords are taken as typed. They used to be trimmed here but not
		// at login, so one set with a leading or trailing space never worked.
		self := sameUsername(actor.Username, subject)
		requireCurrentPassword := self || !hasAnyRole(actor.Roles, []string{"admin"})
		if req.NewPassword == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new_password is required"})
			return
		}
		if len(req.NewPassword) < m.cfg.MinPasswordLength {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("new_password must be at least %d characters", m.cfg.MinPasswordLength),
			})
			return
		}
		if len(req.NewPassword) > maxPasswordLen {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": fmt.Sprintf("new_password must be at most %d bytes", maxPasswordLen),
			})
			return
		}
		if requireCurrentPassword {
			if req.CurrentPassword == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current_password is required"})
				return
			}
			if !m.checkPassword(w, r, subject, req.CurrentPassword, "invalid current_password") {
				return
			}
		}

		if err := m.Users.SetPassword(subject, req.NewPassword); err != nil {
			if errors.Is(err, ErrUserNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not update password"})
			return
		}
		auditLogWithContext(m.db, LogEventPasswordChange, subject, clientIP(r), actorReason(actor.Username, subject), actor.Username, subject, r.Host, "")

		// SetPassword ended every session of the user. The one that just
		// proved the old password carries on, under a new token.
		if self {
			if err := m.adoptCurrentEpoch(r, subject); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
				return
			}
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"password_changed": true,
			"subject":          subject,
			"actor":            actor.Username,
		})
	}
}

// SecurityFactorsHandler returns MFA/passkey status for account-security UI.
// A different subject can only be queried by callers with admin role.
func (m *Manager) SecurityFactorsHandler() http.HandlerFunc {
	return m.securityFactorsHandlerWithResolver(m.resolveSecuritySubjectOrWriteError)
}

func (m *Manager) selfSecurityFactorsHandler() http.HandlerFunc {
	return m.securityFactorsHandlerWithResolver(m.resolveSelfSecuritySubjectOrWriteError)
}

func (m *Manager) securityFactorsHandlerWithResolver(resolve securitySubjectResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		_, subject, ok := resolve(w, r, "")
		if !ok {
			return
		}

		u, err := m.Users.GetByUsername(subject)
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load factors"})
			return
		}

		creds, err := m.Users.ListWebAuthnCredentials(subject)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load factors"})
			return
		}

		recoveryCount, err := m.Users.CountRecoveryCodes(subject)
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not load factors"})
			return
		}

		writeJSON(w, http.StatusOK, factorsResponse{
			Subject:                subject,
			HasTOTP:                u.MFAEnabled && strings.EqualFold(u.MFAType, "totp"),
			PasskeyCount:           len(creds),
			RecoveryCodesRemaining: recoveryCount,
		})
	}
}

// clientIP extracts the real client IP for audit logging and rate limiting.
//
// X-Forwarded-For is trusted only when the direct connection is from loopback
// (a local reverse proxy), and then only its LAST entry: that is the one the
// proxy itself appended. Everything to its left was sent by the client. The
// first entry used to be taken, so a client behind a proxy that appends
// (nginx's $proxy_add_x_forwarded_for) chose its own address, and with it a
// fresh per-IP rate-limit bucket on every request.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	host = strings.Trim(host, "[]")
	direct := net.ParseIP(host)
	if direct == nil || !direct.IsLoopback() {
		return host
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return host
	}
	parts := strings.Split(values[len(values)-1], ",")
	last := strings.TrimSpace(parts[len(parts)-1])
	if ip := net.ParseIP(last); ip != nil {
		return ip.String()
	}
	return host
}

// maxRequestBody caps every JSON body the handlers read. The largest
// legitimate one is a WebAuthn attestation, a few KiB.
const maxRequestBody = 64 << 10

// Longer credentials are refused before they reach Argon2 or the rate
// limiter's map.
const (
	maxUsernameLen = 255
	maxPasswordLen = 1024
)

// decodeJSONBody decodes a size-capped JSON body into v.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	return json.NewDecoder(r.Body).Decode(v)
}

func mfaMethods(user *User) []string {
	methods := []string{"recovery_code"}
	if strings.EqualFold(user.MFAType, "totp") {
		methods = append([]string{"totp"}, methods...)
	} else if user.MFAType != "" {
		methods = append([]string{user.MFAType}, methods...)
	}
	return methods
}

func normalizeMFACode(code string) string {
	code = strings.TrimSpace(code)
	code = strings.ReplaceAll(code, " ", "")
	code = strings.ReplaceAll(code, "-", "")
	return code
}

type mfaVerifyResult struct {
	OK                         bool
	Method                     string
	RecoveryCodesRemaining     int
	RecoveryRegenerateRequired bool
	RecoveryCodesExhausted     bool
}

func (m *Manager) verifyMFA(username, method, code string) (mfaVerifyResult, error) {
	result := mfaVerifyResult{
		RecoveryCodesRemaining: -1,
	}

	method = strings.TrimSpace(strings.ToLower(method))
	code = normalizeMFACode(code)
	if code == "" {
		return result, nil
	}

	if method == "" || method == "totp" {
		encryptedSecret, err := m.Users.GetTOTPSecret(username)
		if err != nil && !errors.Is(err, ErrUserNotFound) {
			return result, err
		}
		if err == nil && encryptedSecret != "" {
			secret, err := decryptSecret(encryptedSecret, m.mfaKey)
			if err != nil {
				return result, fmt.Errorf("decrypt totp secret: %w", err)
			}
			if step, ok := matchTOTPStep(code, secret, time.Now()); ok {
				fresh, err := m.Users.consumeTOTPStep(username, step)
				if err != nil {
					return result, err
				}
				if fresh {
					result.OK = true
					result.Method = "totp"
				}
				// A replayed code is simply a wrong code.
				return result, nil
			}
		}
		if method == "totp" {
			return result, nil
		}
	}

	if method != "" && method != "recovery_code" {
		return result, nil
	}

	remainingBefore, err := m.Users.CountRecoveryCodes(username)
	if errors.Is(err, ErrUserNotFound) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	result.RecoveryCodesRemaining = remainingBefore
	if remainingBefore == 0 {
		// Only when a recovery code was asked for by name. With no method, a
		// wrong TOTP code used to end here as "recovery codes exhausted".
		result.RecoveryCodesExhausted = method == "recovery_code"
		return result, nil
	}
	consumed, remainingAfter, err := m.Users.ConsumeRecoveryCode(username, code)
	if errors.Is(err, ErrUserNotFound) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	result.RecoveryCodesRemaining = remainingAfter
	if !consumed {
		if remainingAfter == 0 {
			result.RecoveryCodesExhausted = true
		}
		return result, nil
	}
	result.OK = true
	result.Method = "recovery_code"
	if remainingAfter <= recoveryCodeRegenerateThreshold {
		result.RecoveryRegenerateRequired = true
	}
	return result, nil
}

type regenerateRecoveryCodesRequest struct {
	Password string `json:"password"`
}

// MFARecoveryRegenerateHandler rotates the currently authenticated user's
// recovery codes and returns the new plaintext codes exactly once.
func (m *Manager) MFARecoveryRegenerateHandler() http.HandlerFunc {
	return m.mfaRecoveryRegenerateHandlerWithResolver(m.resolveSecuritySubjectOrWriteError)
}

func (m *Manager) selfMFARecoveryRegenerateHandler() http.HandlerFunc {
	return m.mfaRecoveryRegenerateHandlerWithResolver(m.resolveSelfSecuritySubjectOrWriteError)
}

func (m *Manager) mfaRecoveryRegenerateHandlerWithResolver(resolve securitySubjectResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		actor, subject, ok := resolve(w, r, "")
		if !ok {
			return
		}

		var req regenerateRecoveryCodesRequest
		_ = decodeJSONBody(w, r, &req)

		if !m.reauthenticate(w, r, actor, subject, req.Password) {
			return
		}

		auditCtx := AdminAuditContext{
			Actor:  actor.Username,
			Target: subject,
			IP:     clientIP(r),
			Host:   r.Host,
			Reason: actorReason(actor.Username, subject),
		}
		codes, err := m.AdminRotateRecoveryCodes(auditCtx, DefaultRecoveryCodeCount)
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not regenerate recovery codes"})
			return
		}
		// (No MFA proof is written here: the caller proved one to get this far,
		// and an admin rotating someone else's codes proved nothing about
		// their own account.)
		writeJSON(w, http.StatusOK, map[string]any{
			"codes":                codes,
			"total_codes":          len(codes),
			"regenerate_threshold": recoveryCodeRegenerateThreshold,
			"warning":              "save these recovery codes now; they will not be shown again",
		})
	}
}

func (m *Manager) hasRecentMFAProof(r *http.Request) bool {
	raw := m.session.GetString(r.Context(), sessionMFAVerifiedAtKey)
	if raw == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return false
	}
	return time.Since(t) <= mfaProofWindow
}

func (m *Manager) writeMFAProof(r *http.Request) {
	m.session.Put(r.Context(), sessionMFAVerifiedAtKey, time.Now().Format(time.RFC3339Nano))
}

// TOTPEnrollStartHandler creates a fresh unverified TOTP secret and returns
// the otpauth URI for QR-code generation.
func (m *Manager) TOTPEnrollStartHandler() http.HandlerFunc {
	return m.totpEnrollStartHandlerWithResolver(m.resolveSecuritySubjectOrWriteError)
}

func (m *Manager) selfTOTPEnrollStartHandler() http.HandlerFunc {
	return m.totpEnrollStartHandlerWithResolver(m.resolveSelfSecuritySubjectOrWriteError)
}

func (m *Manager) totpEnrollStartHandlerWithResolver(resolve securitySubjectResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		actor, subject, ok := resolve(w, r, "")
		if !ok {
			return
		}

		// Adding or replacing your own second factor takes the same proof as
		// removing it. With a session alone, whoever held it could enroll
		// their own authenticator: on an account without MFA that locks the
		// owner out, and the confirmation then counted as an MFA proof for
		// everything else guarded this way.
		var req mfaDisableRequest
		_ = decodeJSONBody(w, r, &req)
		if !m.reauthenticate(w, r, actor, subject, req.Password) {
			return
		}

		auditCtx := AdminAuditContext{
			Actor:  actor.Username,
			Target: subject,
			IP:     clientIP(r),
			Host:   r.Host,
			Reason: actorReason(actor.Username, subject),
		}
		enrollment, err := m.AdminBeginTOTPEnrollment(auditCtx)
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not generate TOTP secret"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"issuer":      enrollment.Issuer,
			"account":     enrollment.Account,
			"otpauth_uri": enrollment.OTPAuthURI,
		})
	}
}

// TOTPEnrollConfirmHandler verifies one code from the newly enrolled authenticator
// and enables TOTP MFA for the current user.
func (m *Manager) TOTPEnrollConfirmHandler() http.HandlerFunc {
	return m.totpEnrollConfirmHandlerWithResolver(m.resolveSecuritySubjectOrWriteError)
}

func (m *Manager) selfTOTPEnrollConfirmHandler() http.HandlerFunc {
	return m.totpEnrollConfirmHandlerWithResolver(m.resolveSelfSecuritySubjectOrWriteError)
}

func (m *Manager) totpEnrollConfirmHandlerWithResolver(resolve securitySubjectResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		actor, subject, ok := resolve(w, r, "")
		if !ok {
			return
		}
		var req totpEnrollConfirmRequest
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		auditCtx := AdminAuditContext{
			Actor:  actor.Username,
			Target: subject,
			IP:     clientIP(r),
			Host:   r.Host,
			Reason: actorReason(actor.Username, subject),
		}
		// A pending secret is guessable like any 6-digit code: same budget as
		// a login's second factor.
		if allowed, retryAfter := m.mfaRL.Allow(clientIP(r), subject); !allowed {
			auditLog(m.db, LogEventRateLimit, subject, clientIP(r), "too_many_mfa_attempts")
			writeTooManyAttempts(w, retryAfter, "too many attempts — please wait before trying again")
			return
		}
		err := m.AdminConfirmTOTPEnrollment(auditCtx, req.Code)
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
				return
			}
			if errors.Is(err, errMFANoPending) {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no pending TOTP enrollment"})
				return
			}
			if errors.Is(err, errMFAVerifyFailed) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid TOTP code"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not enable TOTP MFA"})
			return
		}
		m.mfaRL.ResetUser(subject)
		if sameUsername(actor.Username, subject) {
			m.writeMFAProof(r)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"mfa_enabled": true,
			"mfa_type":    "totp",
		})
	}
}

// MFADisableHandler disables all configured MFA for the current user.
// Requires either recent MFA proof in the current session or password re-auth.
func (m *Manager) MFADisableHandler() http.HandlerFunc {
	return m.mfaDisableHandlerWithResolver(m.resolveSecuritySubjectOrWriteError)
}

func (m *Manager) selfMFADisableHandler() http.HandlerFunc {
	return m.mfaDisableHandlerWithResolver(m.resolveSelfSecuritySubjectOrWriteError)
}

func (m *Manager) mfaDisableHandlerWithResolver(resolve securitySubjectResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		actor, subject, ok := resolve(w, r, "")
		if !ok {
			return
		}

		var req mfaDisableRequest
		_ = decodeJSONBody(w, r, &req)

		if !m.reauthenticate(w, r, actor, subject, req.Password) {
			return
		}

		auditCtx := AdminAuditContext{
			Actor:  actor.Username,
			Target: subject,
			IP:     clientIP(r),
			Host:   r.Host,
			Reason: actorReason(actor.Username, subject),
		}
		if err := m.AdminDisableMFA(auditCtx); err != nil {
			if errors.Is(err, ErrUserNotFound) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not disable MFA"})
			return
		}
		m.session.Remove(r.Context(), sessionMFAVerifiedAtKey)
		writeJSON(w, http.StatusOK, map[string]any{
			"mfa_enabled": false,
		})
	}
}

// RegisterMeSecurityRoutes mounts authenticated /me/security endpoints.
func (m *Manager) RegisterMeSecurityRoutes(mux *http.ServeMux) {
	mux.Handle("POST /me/security/password", m.Require()(m.selfSecurityPasswordChangeHandler()))
	mux.Handle("POST "+RouteMeSecurityTOTPEnrollStart, m.Require()(m.selfTOTPEnrollStartHandler()))
	mux.Handle("POST /me/security/mfa/totp/enroll/confirm", m.Require()(m.selfTOTPEnrollConfirmHandler()))
	mux.Handle("POST /me/security/mfa/disable", m.Require()(m.selfMFADisableHandler()))
	mux.Handle("POST /me/security/recovery-codes/regenerate", m.Require()(m.selfMFARecoveryRegenerateHandler()))
	mux.Handle("POST /me/security/passkeys/register/start", m.Require()(m.selfWebAuthnRegistrationBeginHandler()))
	mux.Handle("POST /me/security/passkeys/register/finish", m.Require()(m.selfWebAuthnRegistrationFinishHandler()))
	mux.Handle("GET /me/security/factors", m.Require()(m.selfSecurityFactorsHandler()))
}

// RegisterAdminSecurityRoutes mounts admin-only account-security endpoints for
// explicitly targeting a user by username.
func (m *Manager) RegisterAdminSecurityRoutes(mux *http.ServeMux) {
	adminSubject := func(w http.ResponseWriter, r *http.Request, _ string) (*User, string, bool) {
		return m.resolveSecuritySubjectOrWriteError(w, r, r.PathValue("username"))
	}

	mux.Handle("POST /admin/users/{username}/security/password", m.Require("admin")(m.securityPasswordChangeHandlerWithResolver(adminSubject)))
	mux.Handle("POST /admin/users/{username}/security/mfa/totp/enroll/start", m.Require("admin")(m.totpEnrollStartHandlerWithResolver(adminSubject)))
	mux.Handle("POST /admin/users/{username}/security/mfa/totp/enroll/confirm", m.Require("admin")(m.totpEnrollConfirmHandlerWithResolver(adminSubject)))
	mux.Handle("POST /admin/users/{username}/security/mfa/disable", m.Require("admin")(m.mfaDisableHandlerWithResolver(adminSubject)))
	mux.Handle("POST /admin/users/{username}/security/recovery-codes/regenerate", m.Require("admin")(m.mfaRecoveryRegenerateHandlerWithResolver(adminSubject)))
	mux.Handle("POST /admin/users/{username}/security/passkeys/register/start", m.Require("admin")(m.webAuthnRegistrationBeginHandlerWithResolver(adminSubject)))
	mux.Handle("POST /admin/users/{username}/security/passkeys/register/finish", m.Require("admin")(m.webAuthnRegistrationFinishHandlerWithResolver(adminSubject)))
	mux.Handle("GET /admin/users/{username}/security/factors", m.Require("admin")(m.securityFactorsHandlerWithResolver(adminSubject)))
}

// LoginHandler returns an http.Handler that accepts POST requests with
// JSON credentials and establishes an authenticated session on success.
//
// Includes:
//   - Per-IP and per-username rate limiting (429 on breach)
//   - Audit logging of every attempt to the auth_log table
//   - Session token rotation on login (prevents session fixation)
//
// On success:  200 {"username":"...","roles":[...]}
// On MFA:      200 {"mfa_required":true,"methods":[...]}
// On failure:  401 {"error":"invalid username or password"}
// On locked:   429 {"error":"too many attempts"} + Retry-After header
func (m *Manager) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ip := clientIP(r)

		var req loginRequest
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		// The limiter key and the audit row are attacker-chosen: bound them.
		if len(req.Username) > maxUsernameLen || len(req.Password) > maxPasswordLen {
			m.rl.Allow(ip, "")
			auditLog(m.db, LogEventFail, req.Username[:min(len(req.Username), maxUsernameLen)], ip, LogReasonBadCredentials)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
			return
		}

		// ── Rate limiting ─────────────────────────────────────────────────────
		if allowed, retryAfter := m.rl.Allow(ip, req.Username); !allowed {
			reason := LogReasonTooManyIP
			if req.Username != "" {
				reason = LogReasonTooManyUser
			}
			auditLog(m.db, LogEventRateLimit, req.Username, ip, reason)
			secs := int(retryAfter / time.Second)
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{
				"error": "too many login attempts — please wait before trying again",
			})
			return
		}

		// ── Authenticate ──────────────────────────────────────────────────────
		user, err := m.Users.Authenticate(req.Username, req.Password)
		if err != nil {
			switch {
			case errors.Is(err, ErrBadCredentials):
				auditLog(m.db, LogEventFail, req.Username, ip, LogReasonBadCredentials)
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
			case errors.Is(err, ErrUserInactive):
				auditLog(m.db, LogEventFail, req.Username, ip, LogReasonUserInactive)
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "account is disabled"})
			default:
				auditLog(m.db, LogEventFail, req.Username, ip, "internal_error")
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			}
			return
		}

		if user.MFAEnabled {
			deadline := time.Now().Add(5 * time.Minute)
			m.session.Put(r.Context(), sessionMFAPendingUserKey, user.Username)
			m.session.Put(r.Context(), sessionMFAPendingDeadlineKey, deadline.Format(time.RFC3339Nano))
			if st, found, err := m.Users.sessionStateFor(user.Username, true); err == nil && found {
				m.session.Put(r.Context(), sessionMFAPendingEpochKey, st.Epoch)
			}
			auditLog(m.db, LogEventSuccess, user.Username, ip, "mfa_pending")
			writeJSON(w, http.StatusOK, map[string]any{
				"mfa_required": true,
				"methods":      mfaMethods(user),
			})
			return
		}

		// ── Session ───────────────────────────────────────────────────────────
		// Rotates the session ID on login to prevent session fixation.
		if err := m.finalizeAuthenticatedSession(r, user, false); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
			return
		}

		auditLog(m.db, LogEventSuccess, user.Username, ip, "")

		writeJSON(w, http.StatusOK, map[string]any{
			"username": user.Username,
			"roles":    user.Roles,
		})
	}
}

// LoginMFAVerifyHandler verifies an MFA code for a pending login session.
//
// Accepts POST /login/mfa/verify with JSON body:
// {"method":"totp","code":"123456"} or {"method":"recovery_code","code":"ABCD-EFGH-IJKL"}
//
// On success:  200 {"username":"...","roles":[...]}
// On failure:  401 {"error":"invalid MFA code"}
// On locked:   429 {"error":"too many MFA attempts"} + Retry-After header
func (m *Manager) LoginMFAVerifyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ip := clientIP(r)
		username := m.session.GetString(r.Context(), sessionMFAPendingUserKey)
		if username == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no pending MFA challenge"})
			return
		}

		deadlineRaw := m.session.GetString(r.Context(), sessionMFAPendingDeadlineKey)
		if deadlineRaw == "" {
			m.session.Remove(r.Context(), sessionMFAPendingUserKey)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no pending MFA challenge"})
			return
		}
		deadline, err := time.Parse(time.RFC3339Nano, deadlineRaw)
		if err != nil || time.Now().After(deadline) {
			m.session.Remove(r.Context(), sessionMFAPendingUserKey)
			m.session.Remove(r.Context(), sessionMFAPendingDeadlineKey)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "MFA challenge expired; please log in again"})
			return
		}

		var req loginMFAVerifyRequest
		if err := decodeJSONBody(w, r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}
		req.Method = strings.TrimSpace(strings.ToLower(req.Method))
		if req.Method != "" && req.Method != "totp" && req.Method != "recovery_code" {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":             "invalid MFA method",
				"supported_methods": []string{"totp", "recovery_code"},
			})
			return
		}

		if !m.mfaPendingValid(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "MFA challenge expired; please log in again"})
			return
		}

		if allowed, retryAfter := m.mfaRL.Allow(ip, username); !allowed {
			auditLog(m.db, LogEventRateLimit, username, ip, "too_many_mfa_attempts")
			writeTooManyAttempts(w, retryAfter, "too many MFA attempts — please wait before trying again")
			return
		}

		verify, err := m.verifyMFA(username, req.Method, req.Code)
		if err != nil {
			auditLog(m.db, LogEventFail, username, ip, "mfa_internal_error")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}

		if verify.RecoveryCodesExhausted {
			auditLog(m.db, LogEventFail, username, ip, "mfa_recovery_codes_exhausted")
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":               "recovery codes exhausted; regenerate recovery codes from account settings",
				"code":                "recovery_codes_exhausted",
				"regenerate_required": true,
			})
			return
		}
		if verify.RecoveryRegenerateRequired && !verify.OK && (req.Method == "recovery_code" || req.Method == "") {
			auditLog(m.db, LogEventFail, username, ip, "mfa_recovery_regeneration_required")
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":               "recovery code login disabled until you regenerate recovery codes",
				"code":                "recovery_regeneration_required",
				"recovery_remaining":  verify.RecoveryCodesRemaining,
				"regenerate_required": true,
			})
			return
		}

		if !verify.OK {
			auditLog(m.db, LogEventFail, username, ip, "mfa_invalid_code")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid MFA code"})
			return
		}

		user, err := m.Users.GetByUsername(username)
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				m.session.Remove(r.Context(), sessionMFAPendingUserKey)
				m.session.Remove(r.Context(), sessionMFAPendingDeadlineKey)
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid MFA session"})
				return
			}
			auditLog(m.db, LogEventFail, username, ip, "mfa_internal_error")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		if !user.Active {
			m.session.Remove(r.Context(), sessionMFAPendingUserKey)
			m.session.Remove(r.Context(), sessionMFAPendingDeadlineKey)
			auditLog(m.db, LogEventFail, username, ip, LogReasonUserInactive)
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "account is disabled"})
			return
		}

		if err := m.finalizeAuthenticatedSession(r, user, true); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
			return
		}
		m.mfaRL.ResetUser(username)
		reason := "mfa_verified"
		if verify.Method == "recovery_code" {
			reason = LogReasonMFARecoveryUsed
		}
		auditLog(m.db, LogEventSuccess, user.Username, ip, reason)

		resp := map[string]any{
			"username": user.Username,
			"roles":    user.Roles,
		}
		if verify.Method != "" {
			resp["method"] = verify.Method
		}
		if verify.Method == "recovery_code" {
			resp["recovery_remaining"] = verify.RecoveryCodesRemaining
			resp["regenerate_required"] = verify.RecoveryRegenerateRequired
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// LogoutHandler returns an http.Handler that destroys the current session.
// Accepts GET or POST. Responds with 200 {"message":"logged out"}.
func (m *Manager) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := m.session.Destroy(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "logout failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
	}
}

// MeHandler returns an http.Handler that returns the currently authenticated
// user's info. Must be wrapped with Require().
func (m *Manager) MeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := UserFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"username": user.Username,
			"roles":    user.Roles,
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

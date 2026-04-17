package goauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
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

const mfaProofWindow = 10 * time.Minute

const (
	recoveryCodeCount               = 10
	recoveryCodeRegenerateThreshold = 2
)

// clientIP extracts the real client IP for audit logging and rate limiting.
// Trusts X-Forwarded-For only when the direct connection is from loopback.
func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}
	// strip brackets from IPv6
	host = strings.Trim(host, "[]")
	if host == "127.0.0.1" || host == "::1" || host == "localhost" {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			first := strings.TrimSpace(strings.Split(fwd, ",")[0])
			if first != "" {
				return first
			}
		}
	}
	return host
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
			if totp.Validate(code, secret) {
				result.OK = true
				result.Method = "totp"
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
		result.RecoveryCodesExhausted = true
		return result, nil
	}
	if remainingBefore <= recoveryCodeRegenerateThreshold {
		result.RecoveryRegenerateRequired = true
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
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user, ok := UserFromContext(r.Context())
		if !ok || user.Username == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
			return
		}

		var req regenerateRecoveryCodesRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		req.Password = strings.TrimSpace(req.Password)

		if !m.hasRecentMFAProof(r) {
			if req.Password == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "re-authentication required (password or recent MFA proof)",
				})
				return
			}
			if _, err := m.Users.Authenticate(user.Username, req.Password); err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid password"})
				return
			}
		}

		codes, err := m.Users.GenerateRecoveryCodes(user.Username, recoveryCodeCount)
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not regenerate recovery codes"})
			return
		}
		m.writeMFAProof(r)
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
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user, ok := UserFromContext(r.Context())
		if !ok || user.Username == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
			return
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      m.cfg.MFAIssuer,
			AccountName: user.Username,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not generate TOTP secret"})
			return
		}

		enc, err := encryptSecret(key.Secret(), m.mfaKey)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not protect TOTP secret"})
			return
		}
		if err := m.Users.SetTOTPSecretUnverified(user.Username, enc); err != nil {
			if errors.Is(err, ErrUserNotFound) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store TOTP secret"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"issuer":      m.cfg.MFAIssuer,
			"account":     user.Username,
			"otpauth_uri": key.URL(),
		})
	}
}

// TOTPEnrollConfirmHandler verifies one code from the newly enrolled authenticator
// and enables TOTP MFA for the current user.
func (m *Manager) TOTPEnrollConfirmHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user, ok := UserFromContext(r.Context())
		if !ok || user.Username == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
			return
		}
		var req totpEnrollConfirmRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		enc, err := m.Users.GetTOTPSecret(user.Username)
		if err != nil {
			if errors.Is(err, ErrUserNotFound) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read TOTP secret"})
			return
		}
		if enc == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no pending TOTP enrollment"})
			return
		}

		secret, err := decryptSecret(enc, m.mfaKey)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not read TOTP secret"})
			return
		}
		if !totp.Validate(normalizeMFACode(req.Code), secret) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid TOTP code"})
			return
		}
		if err := m.Users.ConfirmTOTP(user.Username); err != nil {
			if errors.Is(err, ErrUserNotFound) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not enable TOTP MFA"})
			return
		}
		m.writeMFAProof(r)
		writeJSON(w, http.StatusOK, map[string]any{
			"mfa_enabled": true,
			"mfa_type":    "totp",
		})
	}
}

// MFADisableHandler disables all configured MFA for the current user.
// Requires either recent MFA proof in the current session or password re-auth.
func (m *Manager) MFADisableHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		user, ok := UserFromContext(r.Context())
		if !ok || user.Username == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
			return
		}

		var req mfaDisableRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		req.Password = strings.TrimSpace(req.Password)

		if !m.hasRecentMFAProof(r) {
			if req.Password == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error": "re-authentication required (password or recent MFA proof)",
				})
				return
			}
			if _, err := m.Users.Authenticate(user.Username, req.Password); err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid password"})
				return
			}
		}

		if err := m.Users.DisableMFA(user.Username); err != nil {
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
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
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
			auditLog(m.db, LogEventSuccess, user.Username, ip, "mfa_pending")
			writeJSON(w, http.StatusOK, map[string]any{
				"mfa_required": true,
				"methods":      mfaMethods(user),
			})
			return
		}

		// ── Session ───────────────────────────────────────────────────────────
		// Rotate session ID on login to prevent session fixation.
		if err := m.session.RenewToken(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
			return
		}

		rolesJSON, _ := json.Marshal(user.Roles)
		m.session.Put(r.Context(), sessionUsernameKey, user.Username)
		m.session.Put(r.Context(), sessionRolesKey, string(rolesJSON))
		m.session.Remove(r.Context(), sessionMFAPendingUserKey)
		m.session.Remove(r.Context(), sessionMFAPendingDeadlineKey)

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
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

		if allowed, retryAfter := m.rl.Allow(ip, username); !allowed {
			reason := LogReasonTooManyIP
			if username != "" {
				reason = LogReasonTooManyUser
			}
			auditLog(m.db, LogEventRateLimit, username, ip, reason)
			secs := int(retryAfter / time.Second)
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{
				"error": "too many MFA attempts — please wait before trying again",
			})
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

		if err := m.session.RenewToken(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
			return
		}

		rolesJSON, _ := json.Marshal(user.Roles)
		m.session.Put(r.Context(), sessionUsernameKey, user.Username)
		m.session.Put(r.Context(), sessionRolesKey, string(rolesJSON))
		m.session.Remove(r.Context(), sessionMFAPendingUserKey)
		m.session.Remove(r.Context(), sessionMFAPendingDeadlineKey)
		m.writeMFAProof(r)
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

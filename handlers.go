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
	Code string `json:"code"`
}

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

func (m *Manager) verifyMFA(username, code string) (bool, error) {
	code = normalizeMFACode(code)
	if code == "" {
		return false, nil
	}

	encryptedSecret, err := m.Users.GetTOTPSecret(username)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return false, err
	}
	if err == nil && encryptedSecret != "" {
		if totp.Validate(code, encryptedSecret) {
			return true, nil
		}
	}

	consumed, err := m.Users.ConsumeRecoveryCode(username, code)
	if errors.Is(err, ErrUserNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return consumed, nil
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
// Accepts POST /login/mfa/verify with JSON body: {"code":"123456"}
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

		ok, err := m.verifyMFA(username, req.Code)
		if err != nil {
			auditLog(m.db, LogEventFail, username, ip, "mfa_internal_error")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			return
		}
		if !ok {
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
		auditLog(m.db, LogEventSuccess, user.Username, ip, "mfa_verified")

		writeJSON(w, http.StatusOK, map[string]any{
			"username": user.Username,
			"roles":    user.Roles,
		})
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

package goauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// loginRequest is the JSON body expected by LoginHandler.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
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

// LoginHandler returns an http.Handler that accepts POST requests with
// JSON credentials and establishes an authenticated session on success.
//
// Includes:
//   - Per-IP and per-username rate limiting (429 on breach)
//   - Audit logging of every attempt to the auth_log table
//   - Session token rotation on login (prevents session fixation)
//
// On success:  200 {"username":"...","roles":[...]}
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

		// ── Session ───────────────────────────────────────────────────────────
		// Rotate session ID on login to prevent session fixation.
		if err := m.session.RenewToken(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
			return
		}

		rolesJSON, _ := json.Marshal(user.Roles)
		m.session.Put(r.Context(), sessionUsernameKey, user.Username)
		m.session.Put(r.Context(), sessionRolesKey, string(rolesJSON))

		auditLog(m.db, LogEventSuccess, user.Username, ip, "")

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

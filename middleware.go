package goauth

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type contextKey string

const (
	userContextKey contextKey = "goauth_user"
)

// sessionUsernameKey and sessionRolesKey are the keys used inside the scs session.
const (
	sessionUsernameKey                = "goauth.username"
	sessionRolesKey                   = "goauth.roles"
	sessionEpochKey                   = "goauth.epoch"
	sessionMFAPendingUserKey          = "goauth.mfa_pending_user"
	sessionMFAPendingDeadlineKey      = "goauth.mfa_deadline"
	sessionMFAVerifiedAtKey           = "goauth.mfa_verified_at"
	sessionWebAuthnRegChallengeIDKey  = "goauth.webauthn_registration_challenge_id"
	sessionWebAuthnAuthChallengeIDKey = "goauth.webauthn_auth_challenge_id"
	sessionWebAuthnLoginModeKey       = "goauth.webauthn_login_mode"
)

// UserFromContext retrieves the authenticated User from the request context.
// Returns nil, false if the request is not authenticated.
func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userContextKey).(*User)
	return u, ok && u != nil
}

type sessionStatus int

const (
	sessionNone    sessionStatus = iota // no login in this session
	sessionOK                           // logged in, user still entitled
	sessionRevoked                      // user gone, disabled, or sessions revoked
	sessionUnknown                      // the user database could not be read
)

// sessionUser resolves the session's user against the database: the account
// must still exist and be active, and the session must have been created under
// the user's current session epoch. Roles come from the database, not from the
// session, so a role change applies at once.
//
// The session used to be trusted on its own for its whole lifetime: a disabled
// or deleted user, or one whose password had been reset, kept every open
// session, and a demoted admin stayed admin in them.
func (m *Manager) sessionUser(r *http.Request) (*User, sessionStatus) {
	username := m.session.GetString(r.Context(), sessionUsernameKey)
	if username == "" {
		return nil, sessionNone
	}
	st, found, err := m.Users.sessionStateFor(username, false)
	if err != nil {
		log.Printf("goauth: %v", err)
		return nil, sessionUnknown
	}
	if !found || !st.Active || m.session.GetInt64(r.Context(), sessionEpochKey) != st.Epoch {
		return nil, sessionRevoked
	}
	return &User{Username: st.Username, Roles: st.Roles, Active: true}, sessionOK
}

// Require returns a middleware that enforces authentication.
// If roles are given, the user must hold at least one of them.
//
// For browser requests (Accept: text/html) unauthenticated users are
// redirected to the configured LoginPath.
// For API requests a 401 JSON response is returned instead.
//
//	// Any authenticated user:
//	mux.Handle("/dashboard", auth.Require()(dashboardHandler))
//
//	// Admin only:
//	mux.Handle("/admin/", auth.Require("admin")(adminHandler))
func (m *Manager) Require(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, status := m.sessionUser(r)
			if status != sessionOK {
				if status == sessionRevoked {
					_ = m.session.Destroy(r.Context())
				}
				m.denyUnauthenticated(w, r)
				return
			}

			if len(roles) > 0 && !hasAnyRole(u.Roles, roles) {
				m.denyForbidden(w, r, u.Username)
				return
			}

			// Refresh idle timeout on every authenticated request.
			m.session.Put(r.Context(), sessionUsernameKey, u.Username)

			ctx := context.WithValue(r.Context(), userContextKey, u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func hasAnyRole(userRoles, required []string) bool {
	for _, req := range required {
		for _, ur := range userRoles {
			if strings.EqualFold(ur, req) {
				return true
			}
		}
	}
	return false
}

func (m *Manager) denyUnauthenticated(w http.ResponseWriter, r *http.Request) {
	if m.cfg.OnAuthFailure != nil {
		m.cfg.OnAuthFailure(w, r, "unauthenticated")
		return
	}
	if isBrowserRequest(r) {
		http.Redirect(w, r, m.cfg.LoginPath+"?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error":"unauthenticated"}`))
}

func (m *Manager) denyForbidden(w http.ResponseWriter, r *http.Request, username string) {
	if m.cfg.OnAuthFailure != nil {
		m.cfg.OnAuthFailure(w, r, "forbidden")
		return
	}
	if isBrowserRequest(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"error":"forbidden"}`))
}

// IsAuthenticated reports whether the request carries a valid, active session.
// Requires LoadAndSave to have already run (i.e. must be called from within
// the handler chain, not before the mux).
//
// The user must also still exist, be active and not have had their sessions
// revoked (see sessionUser).
func (m *Manager) IsAuthenticated(r *http.Request) bool {
	_, status := m.sessionUser(r)
	return status == sessionOK
}

// isBrowserRequest returns true when the client is likely a browser
// (Accept header contains text/html).
func isBrowserRequest(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

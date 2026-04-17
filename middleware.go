package goauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type contextKey string

const (
	userContextKey contextKey = "goauth_user"
)

// sessionUsernameKey and sessionRolesKey are the keys used inside the scs session.
const (
	sessionUsernameKey           = "goauth.username"
	sessionRolesKey              = "goauth.roles"
	sessionMFAPendingUserKey     = "goauth.mfa_pending_user"
	sessionMFAPendingDeadlineKey = "goauth.mfa_deadline"
	sessionMFAVerifiedAtKey      = "goauth.mfa_verified_at"
)

// UserFromContext retrieves the authenticated User from the request context.
// Returns nil, false if the request is not authenticated.
func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userContextKey).(*User)
	return u, ok && u != nil
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
			username := m.session.GetString(r.Context(), sessionUsernameKey)
			if username == "" {
				m.denyUnauthenticated(w, r)
				return
			}

			rolesJSON := m.session.GetString(r.Context(), sessionRolesKey)
			var userRoles []string
			json.Unmarshal([]byte(rolesJSON), &userRoles)

			if len(roles) > 0 && !hasAnyRole(userRoles, roles) {
				m.denyForbidden(w, r, username)
				return
			}

			// Refresh idle timeout on every authenticated request.
			m.session.Put(r.Context(), sessionUsernameKey, username)

			u := &User{
				Username: username,
				Roles:    userRoles,
				Active:   true,
			}
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
		http.Redirect(w, r, m.cfg.LoginPath+"?next="+r.URL.RequestURI(), http.StatusSeeOther)
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
func (m *Manager) IsAuthenticated(r *http.Request) bool {
	return m.session.GetString(r.Context(), sessionUsernameKey) != ""
}

// isBrowserRequest returns true when the client is likely a browser
// (Accept header contains text/html).
func isBrowserRequest(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

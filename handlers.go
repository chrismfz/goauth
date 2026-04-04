package goauth

import (
	"encoding/json"
	"errors"
	"net/http"
)

// loginRequest is the JSON body expected by LoginHandler.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginHandler returns an http.Handler that accepts POST requests with
// JSON credentials and establishes an authenticated session on success.
//
// On success:  200 {"username":"...","roles":[...]}
// On failure:  401 {"error":"invalid username or password"}
//
// Register it with your router:
//
//	mux.Post("/login", auth.LoginHandler())
func (m *Manager) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
			return
		}

		user, err := m.Users.Authenticate(req.Username, req.Password)
		if err != nil {
			switch {
			case errors.Is(err, ErrBadCredentials):
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
			case errors.Is(err, ErrUserInactive):
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "account is disabled"})
			default:
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
			}
			return
		}

		// Rotate session ID on login to prevent session fixation.
		if err := m.session.RenewToken(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
			return
		}

		rolesJSON, _ := json.Marshal(user.Roles)
		m.session.Put(r.Context(), sessionUsernameKey, user.Username)
		m.session.Put(r.Context(), sessionRolesKey, string(rolesJSON))

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

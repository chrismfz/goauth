// Package goauth provides reusable session-based authentication and
// authorization for Go web applications. It is designed to be imported
// by multiple projects (CFM, Argus, etc.) with a single SQLite file
// per project and a companion CLI for user management.
package goauth

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
	_ "modernc.org/sqlite"
)

// Config holds all options for a Manager instance.
type Config struct {
	// DBPath is the path to the SQLite database file.
	// Both the user table and the session table live here.
	DBPath string

	// SessionTTL is the absolute lifetime of a session (default: 8h).
	SessionTTL time.Duration

	// IdleTimeout is the inactivity timeout. The session is extended on
	// every authenticated request (default: 30m, 0 = disabled).
	IdleTimeout time.Duration

	// CookieName is the session cookie name.
	// Use the "__Host-" prefix for maximum browser hardening (default: "__Host-sid").
	CookieName string

	// SecureCookie sets the Secure flag on the session cookie.
	// Set to false only in local development over HTTP.
	SecureCookie bool

	// SameSite controls the SameSite cookie attribute (default: Strict).
	SameSite http.SameSite

	// LoginPath is the path the Require middleware redirects to for
	// unauthenticated browser requests (default: "/login").
	LoginPath string

	// OnAuthFailure, if set, overrides the default redirect/401 behaviour
	// for the Require middleware. Useful for fully custom error pages.
	OnAuthFailure func(w http.ResponseWriter, r *http.Request, reason string)
}

func (c *Config) withDefaults() {
	if c.SessionTTL == 0 {
		c.SessionTTL = 8 * time.Hour
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 30 * time.Minute
	}
	if c.CookieName == "" {
		c.CookieName = "__Host-sid"
	}
	if c.SameSite == 0 {
		c.SameSite = http.SameSiteStrictMode
	}
	if c.LoginPath == "" {
		c.LoginPath = "/login"
	}
}

// Manager is the central auth object. Create one per project and share it.
type Manager struct {
	cfg     Config
	db      *sql.DB
	Users   *UserStore
	session *scs.SessionManager
}

// New opens (or creates) the SQLite database at cfg.DBPath, runs schema
// migrations, and returns a ready-to-use Manager.
func New(cfg Config) (*Manager, error) {
	cfg.withDefaults()

	db, err := sql.Open("sqlite", cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("goauth: open db: %w", err)
	}

	// SQLite connection pragmas for safety and performance.
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return nil, fmt.Errorf("goauth: pragma %q: %w", p, err)
		}
	}

	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("goauth: migrations: %w", err)
	}

	store := newSQLiteSessionStore(db)

	sm := scs.New()
	sm.Store = store
	sm.Lifetime = cfg.SessionTTL
	sm.IdleTimeout = cfg.IdleTimeout
	sm.Cookie.Name = cfg.CookieName
	sm.Cookie.HttpOnly = true
	sm.Cookie.Secure = cfg.SecureCookie
	sm.Cookie.SameSite = cfg.SameSite
	sm.Cookie.Path = "/"

	m := &Manager{
		cfg:     cfg,
		db:      db,
		Users:   &UserStore{db: db},
		session: sm,
	}
	return m, nil
}

// Close releases the database handle. Call this on graceful shutdown.
func (m *Manager) Close() error {
	return m.db.Close()
}

// LoadAndSave is the top-level middleware that must wrap your entire router.
// It loads the session on every request and saves it on every response.
//
//	mux.Handle("/", auth.LoadAndSave(router))
func (m *Manager) LoadAndSave(next http.Handler) http.Handler {
	return m.session.LoadAndSave(next)
}

// Destroy invalidates the current session. Used when the caller wants to
// handle the HTTP response itself (e.g. redirect instead of JSON).
func (m *Manager) Destroy(r *http.Request) error {
	return m.session.Destroy(r.Context())
}

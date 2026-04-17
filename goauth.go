// Package goauth provides reusable session-based authentication and
// authorization for Go web applications. It is designed to be imported
// by multiple projects (CFM, Argus, etc.) with a single SQLite file
// per project and a companion CLI for user management.
package goauth

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	_ "modernc.org/sqlite"
)

// Config holds all options for a Manager instance.
type Config struct {
	// DBPath is the path to the SQLite database file.
	// User and auth_log tables live here. Sessions also live here when
	// SessionDBPath is not set.
	DBPath string

	// SessionDBPath optionally stores sessions in a separate SQLite file.
	// If empty, sessions share DBPath.
	SessionDBPath string

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

	// LoginRateLimit, if set, enables per-IP and per-username rate limiting
	// on the login endpoint. Defaults to true when using LoginHandler().
	LoginRateLimit bool

	// MFAEncryptionKey is the symmetric key used to encrypt TOTP secrets at rest.
	// When empty, New() falls back to env GOAUTH_MFA_ENCRYPTION_KEY.
	// Accepted formats: raw 16/24/32-byte string, hex, or base64.
	MFAEncryptionKey string

	// MFAIssuer is used as the issuer label in otpauth:// URIs.
	// Defaults to "goauth" when empty.
	MFAIssuer string
}

func (c *Config) withDefaults() {
	if c.SessionTTL == 0 {
		c.SessionTTL = 8 * time.Hour
	}

	//	if c.IdleTimeout == 0 {
	//		c.IdleTimeout = 30 * time.Minute
	//	}
	// IdleTimeout intentionally has no default — leaving it at 0 disables it.
	// When enabled, scs commits the session on every request to update last-access,
	// causing SQLITE_BUSY storms under concurrent load.

	if c.CookieName == "" {
		c.CookieName = "__Host-sid"
	}
	if c.SameSite == 0 {
		c.SameSite = http.SameSiteStrictMode
	}
	if c.LoginPath == "" {
		c.LoginPath = "/login"
	}
	if c.MFAEncryptionKey == "" {
		c.MFAEncryptionKey = os.Getenv("GOAUTH_MFA_ENCRYPTION_KEY")
	}
	if c.MFAIssuer == "" {
		c.MFAIssuer = "goauth"
	}
}

// Manager is the central auth object. Create one per project and share it.
type Manager struct {
	cfg       Config
	db        *sql.DB
	sessionDB *sql.DB
	Users     *UserStore
	session   *scs.SessionManager
	rl        *loginRateLimiter
	mfaKey    []byte
}

// New opens (or creates) SQLite databases, runs schema migrations, and
// returns a ready-to-use Manager.
func New(cfg Config) (*Manager, error) {
	cfg.withDefaults()

	mfaKey, err := decodeEncryptionKey(cfg.MFAEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("goauth: invalid MFA encryption key: %w", err)
	}

	db, err := openSQLiteDB(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("goauth: open auth db: %w", err)
	}

	if err := runAuthMigrations(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("goauth: auth migrations: %w", err)
	}

	sessionDB := db
	if cfg.SessionDBPath != "" && cfg.SessionDBPath != cfg.DBPath {
		sessionDB, err = openSQLiteDB(cfg.SessionDBPath)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("goauth: open session db: %w", err)
		}
	}
	if err := runSessionMigrations(sessionDB); err != nil {
		if sessionDB != db {
			_ = sessionDB.Close()
		}
		_ = db.Close()
		return nil, fmt.Errorf("goauth: session migrations: %w", err)
	}

	store := newSQLiteSessionStore(sessionDB)

	sm := scs.New()
	sm.Store = store
	sm.Lifetime = cfg.SessionTTL
	sm.IdleTimeout = cfg.IdleTimeout
	sm.Cookie.Name = cfg.CookieName
	sm.Cookie.HttpOnly = true
	sm.Cookie.Secure = cfg.SecureCookie
	sm.Cookie.SameSite = cfg.SameSite
	sm.Cookie.Path = "/"

	// Don't let session commit failures return 500 to the client.
	// The request still succeeds; the session just won't be extended this tick.
	sm.ErrorFunc = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("goauth/store: commit: %v", err)
	}

	m := &Manager{
		cfg:       cfg,
		db:        db,
		sessionDB: sessionDB,
		Users:     &UserStore{db: db},
		session:   sm,
		rl:        newLoginRateLimiter(),
		mfaKey:    mfaKey,
	}
	return m, nil
}

func openSQLiteDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("goauth: pragma %q: %w", "PRAGMA busy_timeout=5000", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("goauth: pragma %q: %w", "PRAGMA foreign_keys=ON", err)
	}
	if err := enableWALWithRetry(db, 10, 200*time.Millisecond); err != nil {
		log.Printf("goauth: warning: %v (continuing without forcing WAL)", err)
	}

	return db, nil
}

func enableWALWithRetry(db *sql.DB, attempts int, delay time.Duration) error {
	var lastErr error
	for i := 0; i < attempts; i++ {
		if _, err := db.Exec("PRAGMA journal_mode=WAL"); err == nil {
			return nil
		} else {
			lastErr = err
			if !isSQLiteLockError(err) {
				return fmt.Errorf("goauth: pragma %q: %w", "PRAGMA journal_mode=WAL", err)
			}
			time.Sleep(delay)
		}
	}
	return fmt.Errorf("goauth: pragma %q: %w", "PRAGMA journal_mode=WAL", lastErr)
}

func isSQLiteLockError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") || strings.Contains(msg, "database is busy")
}

// Close releases the database handle. Call this on graceful shutdown.
func (m *Manager) Close() error {
	if m.sessionDB != nil && m.sessionDB != m.db {
		if err := m.sessionDB.Close(); err != nil {
			return err
		}
	}
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

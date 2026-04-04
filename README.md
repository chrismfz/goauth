# goauth

Reusable session-based authentication and authorization for Go services.  
Used by [CFM](https://github.com/chrismfz/cfm), [Argus](https://github.com/chrismfz/argus), and future projects.

## Features

- **Server-side sessions** backed by SQLite (via [alexedwards/scs](https://github.com/alexedwards/scs))
- **Argon2id** password hashing ([alexedwards/argon2id](https://github.com/alexedwards/argon2id))
- **Hardened cookies** — `HttpOnly`, `Secure`, `SameSite=Strict`, `__Host-` prefix support
- **Role-based access control** — `Require("admin")` middleware
- **Zero CGO** — uses `modernc.org/sqlite` (pure Go)
- **`goauth` CLI** — manage users and sessions from the console

---

## Installation

```bash
# As a library
go get github.com/chrismfz/goauth

# CLI binary
go install github.com/chrismfz/goauth/cmd/goauth@latest
```

---

## Library Usage

```go
import "github.com/chrismfz/goauth"

func main() {
    auth, err := goauth.New(goauth.Config{
        DBPath:       "/etc/cfm/auth.db",
        SessionTTL:   8 * time.Hour,
        IdleTimeout:  30 * time.Minute,
        CookieName:   "__Host-cfm-sid",
        SecureCookie: true,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close()

    mux := http.NewServeMux()

    // Auth endpoints
    mux.HandleFunc("POST /login",  auth.LoginHandler())
    mux.HandleFunc("POST /logout", auth.LogoutHandler())
    mux.HandleFunc("GET /me",      auth.Require()(auth.MeHandler()))

    // Protected routes
    mux.Handle("GET /api/status", auth.Require()(statusHandler))
    mux.Handle("GET /admin/",     auth.Require("admin")(adminHandler))

    // LoadAndSave must wrap the entire router
    log.Fatal(http.ListenAndServe(":8080", auth.LoadAndSave(mux)))
}
```

### Reading the current user in handlers

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    user, ok := goauth.UserFromContext(r.Context())
    if !ok {
        http.Error(w, "not logged in", http.StatusUnauthorized)
        return
    }
    fmt.Fprintf(w, "Hello, %s (roles: %v)\n", user.Username, user.Roles)
}
```

### Login endpoint (POST /login)

Accepts JSON:

```json
{ "username": "chris", "password": "hunter2" }
```

Returns on success:

```json
{ "username": "chris", "roles": ["admin"] }
```

---

## CLI Usage

```bash
# Create initial admin user
goauth --db /etc/cfm/auth.db user add -u chris -r admin

# List all users
goauth --db /etc/cfm/auth.db user list

# Detailed info
goauth --db /etc/cfm/auth.db user info -u chris

# Change password (prompted securely)
goauth --db /etc/cfm/auth.db user passwd -u chris

# Update roles
goauth --db /etc/cfm/auth.db user roles -u chris -r admin,viewer

# Disable / re-enable without deleting
goauth --db /etc/cfm/auth.db user deactivate -u someuser
goauth --db /etc/cfm/auth.db user activate   -u someuser

# Delete permanently (requires --force)
goauth --db /etc/cfm/auth.db user delete -u someuser --force

# Session management
goauth --db /etc/cfm/auth.db session list
goauth --db /etc/cfm/auth.db session purge
```

---

## Configuration

| Field | Default | Description |
|---|---|---|
| `DBPath` | — | Path to SQLite file (created if absent) |
| `SessionTTL` | `8h` | Absolute session lifetime |
| `IdleTimeout` | `30m` | Inactivity expiry (0 = disabled) |
| `CookieName` | `__Host-sid` | Cookie name (`__Host-` forces Secure + Path=/) |
| `SecureCookie` | `false` | Set `Secure` flag (enable in production) |
| `SameSite` | `Strict` | `SameSite` cookie attribute |
| `LoginPath` | `/login` | Redirect target for unauthenticated browser requests |
| `OnAuthFailure` | `nil` | Custom handler called on 401/403 (overrides redirect) |

---

## Database Schema

Two tables are created automatically on first run:

```sql
-- User accounts
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    roles         TEXT    NOT NULL DEFAULT '[]',  -- JSON array
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

-- SCS session store
CREATE TABLE sessions (
    token  TEXT    PRIMARY KEY,
    data   BLOB    NOT NULL,
    expiry INTEGER NOT NULL
);
```

---

## Roadmap

- [ ] `golang.org/x/term` for proper no-echo password prompts in CLI
- [ ] TOTP / 2FA support
- [ ] Login attempt audit log
- [ ] Rate limiting on `/login`
- [ ] `session kill <token>` CLI command

# goauth

Reusable session-based authentication and authorization for Go services.
Used by [CFM](https://github.com/chrismfz/cfm), [Argus](https://github.com/chrismfz/argus), and future projects.

## Features

- **Server-side sessions** backed by SQLite (via [alexedwards/scs](https://github.com/alexedwards/scs))
- **Argon2id** password hashing ([alexedwards/argon2id](https://github.com/alexedwards/argon2id))
- **Hardened cookies** — `HttpOnly`, `Secure`, `SameSite=Strict`, `__Host-` prefix support
- **Role-based access control** — `Require("admin")` middleware
- **Zero CGO** — uses `modernc.org/sqlite` (pure Go)
- **Login rate limiting** — per-IP and per-username sliding window, 429 + Retry-After
- **Audit log** — every login attempt recorded to SQLite (SUCCESS, FAIL, RATELIMIT)
- **Embedded CLI** — manage users and sessions from inside your own binary (recommended)
- **`IsAuthenticated()`** — session check for use inside your own middleware
- **`Destroy()`** — session destruction without writing a response body (for custom redirects)

---

## Installation

```bash
go get github.com/chrismfz/goauth
```

---

## Quick start

```go
import "github.com/chrismfz/goauth"

func main() {
    auth, err := goauth.New(goauth.Config{
        DBPath:        "/etc/myapp/auth.db",      // users + auth_log
        SessionDBPath: "/etc/myapp/sessions.db",  // optional; defaults to DBPath
        SessionTTL:    8 * time.Hour,
        IdleTimeout:   30 * time.Minute,
        CookieName:    "__Host-sid",
        SecureCookie:  true,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer auth.Close()

    mux := http.NewServeMux()

    // Public auth endpoints
    mux.HandleFunc("POST /login",  auth.LoginHandler())
    mux.HandleFunc("POST /logout", auth.LogoutHandler())
    mux.HandleFunc("GET /me",      auth.Require()(auth.MeHandler()))

    // Protected routes
    mux.Handle("GET /api/status", auth.Require()(statusHandler))
    mux.Handle("GET /admin/",     auth.Require("admin")(adminHandler))

    // LoadAndSave MUST be the outermost wrapper — it loads and saves the
    // session on every request. Everything beneath it can read session state.
    log.Fatal(http.ListenAndServe(":8080", auth.LoadAndSave(mux)))
}
```

### Reducing SQLite lock contention (no external dependencies)

If you run goauth in high-concurrency environments and want to stay fully
embedded (no Redis/Memcached), use a separate SQLite file for sessions:

```go
auth, err := goauth.New(goauth.Config{
    DBPath:        "/var/lib/myapp/auth.db",      // users + auth_log
    SessionDBPath: "/var/lib/myapp/sessions.db",  // sessions only
})
```

This isolates high-churn session writes from user/audit tables and reduces
`SQLITE_BUSY` contention. If `SessionDBPath` is empty, goauth keeps the
original single-file behavior.

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

### Login endpoint

`POST /login` — accepts JSON:

```json
{ "username": "chris", "password": "hunter2" }
```

Returns on success:

```json
{ "username": "chris", "roles": ["admin"] }
```

---

## Real-world integration: layered auth (Argus / CFM pattern)

Many services already have IP allowlists and Bearer token auth for API/CLI
access, and only need session auth added for browser users — without breaking
existing callers. This is the pattern used in Argus and CFM.

### The problem: nginx makes everything look like loopback

When nginx (or any reverse proxy) sits in front of your Go service, all
requests arrive at the service as `127.0.0.1`. A naive `r.RemoteAddr`
loopback check trusts everything unconditionally — so session enforcement is
never reached for proxied browser requests.

### Solution: realIP + realIPAllowed

Trust `X-Forwarded-For` **only when the direct connection is from loopback**.
External clients cannot inject XFF when they connect directly — only a
trusted local proxy (nginx) can set it.

```go
// realIP returns the true client IP.
// When the direct connection is from loopback (nginx proxying), reads
// X-Forwarded-For to get the actual client address.
// XFF is only trusted from loopback — external clients cannot spoof it.
func realIP(r *http.Request) net.IP {
    host, _, _ := net.SplitHostPort(r.RemoteAddr)
    directIP := net.ParseIP(host)

    if directIP != nil && directIP.IsLoopback() {
        if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
            first := strings.TrimSpace(strings.Split(fwd, ",")[0])
            if ip := net.ParseIP(first); ip != nil {
                return ip
            }
        }
        // Loopback with no XFF = local tool (CLI, curl on server) → still loopback
        return directIP
    }
    return directIP
}

// realIPAllowed checks the true client IP against a CIDR/IP allowlist.
// Use this in all auth middleware instead of checking r.RemoteAddr directly.
func realIPAllowed(r *http.Request, cidrs []string) bool {
    ip := realIP(r)
    if ip == nil {
        return false
    }
    if ip.IsLoopback() {
        return true
    }
    for _, c := range cidrs {
        if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(ip) {
            return true
        }
        if net.ParseIP(c) != nil && ip.Equal(net.ParseIP(c)) {
            return true
        }
    }
    return false
}
```

### sessionAllowed helper

```go
var Auth *goauth.Manager // set at startup from main.go

// sessionAllowed returns true if the request carries a valid goauth session.
// Requires Auth to be non-nil and LoadAndSave to have already run.
func sessionAllowed(r *http.Request) bool {
    return Auth != nil && Auth.IsAuthenticated(r)
}
```

### The middleware stack

```
Request
  → Auth.LoadAndSave()     loads session from cookie into context
  → globalGuard()          rate limiting, ban, body cap  (uses r.RemoteAddr — intentional)
  → mux routing
  → WithMainIPOnly()        per-route: realIP + session check
  → handler
```

`globalGuard` deliberately keeps using `r.RemoteAddr` so local tools (CLI,
curl on the server) are never rate-limited or banned. Only the per-route
middleware uses `realIP`.

### WithMainIPOnly — browser-facing routes

Used for dashboard, telemetry, debug pages. Redirects browsers to `/login`,
returns 403 for non-browser clients.

```go
func WithMainIPOnly(h http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Real client IP — sees through nginx proxy via XFF
        if realIPAllowed(r, config.AllowIPs) {
            h(w, r)
            return
        }
        // Valid session cookie
        if sessionAllowed(r) {
            h(w, r)
            return
        }
        // Unauthenticated — redirect browsers, block API clients
        if strings.Contains(r.Header.Get("Accept"), "text/html") {
            http.Redirect(w, r, "/login?next="+r.URL.RequestURI(), http.StatusSeeOther)
            return
        }
        http.Error(w, "Forbidden", http.StatusForbidden)
    }
}

// WithMainIPOnlyHandler wraps http.Handler instead of http.HandlerFunc.
// Used for pprof.Handler() and similar.
func WithMainIPOnlyHandler(h http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if realIPAllowed(r, config.AllowIPs) {
            h.ServeHTTP(w, r)
            return
        }
        if sessionAllowed(r) {
            h.ServeHTTP(w, r)
            return
        }
        http.Error(w, "Forbidden", http.StatusForbidden)
    })
}
```

### WithAuth — API routes (IP + Bearer token + session)

Used for mutating API endpoints. Accepts any of: trusted IP, valid Bearer
token, or valid session cookie. Fully backwards-compatible with existing
API/CLI callers.

```go
func WithAuth(handler http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Trusted IP (real IP, sees through proxy)
        if realIPAllowed(r, config.AllowIPs) {
            handler(w, r)
            return
        }
        // Bearer token (external API callers, scripts, CFM integration)
        if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
            token := auth[7:]
            for _, t := range config.Tokens {
                if token == t {
                    handler(w, r)
                    return
                }
            }
        }
        // Session cookie (authenticated browser users)
        if sessionAllowed(r) {
            handler(w, r)
            return
        }
        http.Error(w, "Forbidden", http.StatusForbidden)
    }
}
```

> **Critical:** `WithAuth` must use `realIPAllowed`, not `ipAllowed` /
> `r.RemoteAddr`. If it uses `r.RemoteAddr`, all requests through nginx pass
> unconditionally since they appear as `127.0.0.1`, making Bearer token and
> session checks unreachable — i.e. any unauthenticated browser request gets
> through.

### Registering auth routes

```go
// Public — no guard. Must be registered before any catch-all handler.
mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        serveLoginPage(w, r)      // your HTML login form
    case http.MethodPost:
        Auth.LoginHandler()(w, r) // goauth handles credentials + session
    default:
        http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
    }
})
mux.HandleFunc("/logout", handleLogout)

// Wrap the whole stack — LoadAndSave must be outermost
inner := withRecovery(globalGuard(mux))
var handler http.Handler = inner
if Auth != nil {
    handler = Auth.LoadAndSave(inner)
}
```

### Custom logout with redirect

`LogoutHandler()` writes a JSON response body. For a browser logout that
redirects to `/login`, use `Destroy()` directly — it destroys the session
without writing anything to the response:

```go
func handleLogout(w http.ResponseWriter, r *http.Request) {
    if Auth != nil {
        Auth.Destroy(r) // destroys session, writes nothing
    }
    http.Redirect(w, r, "/login", http.StatusSeeOther)
}
```

### nginx configuration

nginx must forward the real client IP via `X-Forwarded-For`. Remove
`auth_basic` entirely — goauth handles authentication.

```nginx
server {
    server_name myapp.example.com;
    # No auth_basic — goauth handles it

    location / {
        proxy_pass            http://127.0.0.1:9600;
        proxy_set_header      Host            $host;
        proxy_set_header      X-Real-IP       $remote_addr;
        proxy_set_header      X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # SSE streams — buffering must be off, XFF still required
    location ~ ^/tel/.*/stream {
        proxy_pass         http://127.0.0.1:9600;
        proxy_buffering    off;
        proxy_cache        off;
        proxy_read_timeout 3600s;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### config.yaml

```yaml
auth:
  db_path:       /opt/myapp/etc/auth.db
  session_ttl:   8h
  idle_timeout:  30m
  secure_cookie: true      # false only for local HTTP testing
  cookie_name:   myapp-sid # use __Host-myapp-sid for extra browser hardening
```

### Initialising in main.go

```go
import "github.com/chrismfz/goauth"

// After config is loaded, before server starts:
if cfg.Auth.DBPath != "" {
    authMgr, err := goauth.New(goauth.Config{
        DBPath:       cfg.Auth.DBPath,
        SessionTTL:   cfg.Auth.SessionTTL,
        IdleTimeout:  cfg.Auth.IdleTimeout,
        CookieName:   cfg.Auth.CookieName,
        SecureCookie: cfg.Auth.SecureCookie,
    })
    if err != nil {
        log.Fatalf("[AUTH] failed to init: %v", err)
    }
    api.Auth = authMgr
    defer authMgr.Close()
    log.Printf("[AUTH] session store: %s", cfg.Auth.DBPath)
} else {
    log.Printf("[AUTH] db_path not configured — browser auth disabled")
}
```

---

## Embedding the CLI in your binary (recommended)

Rather than shipping a separate binary, embed user/session management
directly in your service binary. One binary to deploy, no extra install step,
consistent DB path defaults.

In `cmd/myapp/main.go`, short-circuit before any config or server init:

```go
func main() {
    // Auth CLI — short-circuits before config load or server start.
    // The service does not need to be running.
    if len(os.Args) > 1 && os.Args[1] == "auth" {
        os.Args = append(os.Args[:1], os.Args[2:]...)
        runAuthCLI()
        return
    }
    // ... normal server startup
}
```

Create `cmd/myapp/auth_cli.go` (same package as main.go):

```go
package main

import (
    "fmt"
    "os"
    "strings"
    "syscall"
    "text/tabwriter"
    "time"

    "github.com/chrismfz/goauth"
    "github.com/spf13/cobra"
    "golang.org/x/term"
)

const defaultAuthDB = "/opt/myapp/etc/auth.db"

func runAuthCLI() {
    var dbPath string

    root := &cobra.Command{
        Use:          "myapp auth",
        Short:        "Manage users and sessions",
        SilenceUsage: true,
    }
    root.PersistentFlags().StringVar(&dbPath, "db", defaultAuthDB, "Auth database path")

    userCmd := &cobra.Command{Use: "user", Short: "Manage user accounts"}
    userCmd.AddCommand(
        authCmdUserAdd(&dbPath),
        authCmdUserList(&dbPath),
        authCmdUserPasswd(&dbPath),
        authCmdUserRoles(&dbPath),
        authCmdUserActivate(&dbPath),
        authCmdUserDeactivate(&dbPath),
        authCmdUserDelete(&dbPath),
    )

    sessionCmd := &cobra.Command{Use: "session", Short: "Manage sessions"}
    sessionCmd.AddCommand(
        authCmdSessionList(&dbPath),
        authCmdSessionPurge(&dbPath),
    )

    root.AddCommand(userCmd, sessionCmd)
    if err := root.Execute(); err != nil {
        os.Exit(1)
    }
}

func authOpen(dbPath *string) (*goauth.Manager, error) {
    return goauth.New(goauth.Config{
        DBPath:       *dbPath,
        SessionTTL:   8 * time.Hour,
        SecureCookie: false, // irrelevant for CLI
    })
}

func authPromptPassword(prompt string) (string, error) {
    fmt.Fprint(os.Stderr, prompt)
    if term.IsTerminal(int(syscall.Stdin)) {
        b, err := term.ReadPassword(int(syscall.Stdin))
        fmt.Fprintln(os.Stderr)
        return string(b), err
    }
    var pw string
    _, err := fmt.Scanln(&pw)
    return pw, err
}

func authCmdUserAdd(dbPath *string) *cobra.Command {
    var username, password string
    var roles []string
    cmd := &cobra.Command{
        Use:   "add",
        Short: "Create a new user",
        Example: "  myapp auth user add -u chris -r admin",
        RunE: func(cmd *cobra.Command, args []string) error {
            if password == "" {
                var err error
                password, err = authPromptPassword("Password: ")
                if err != nil { return err }
                confirm, err := authPromptPassword("Confirm password: ")
                if err != nil { return err }
                if password != confirm { return fmt.Errorf("passwords do not match") }
            }
            m, err := authOpen(dbPath)
            if err != nil { return err }
            defer m.Close()
            if err := m.Users.Create(username, password, roles); err != nil { return err }
            fmt.Printf("✓ User %q created with roles: [%s]\n", username, strings.Join(roles, ", "))
            return nil
        },
    }
    cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
    cmd.Flags().StringVarP(&password, "password", "p", "", "Password (prompted securely if omitted)")
    cmd.Flags().StringSliceVarP(&roles, "roles", "r", []string{}, "Comma-separated roles")
    cmd.MarkFlagRequired("username")
    return cmd
}

func authCmdUserList(dbPath *string) *cobra.Command {
    return &cobra.Command{
        Use:     "list",
        Aliases: []string{"ls"},
        Short:   "List all users",
        RunE: func(cmd *cobra.Command, args []string) error {
            m, err := authOpen(dbPath)
            if err != nil { return err }
            defer m.Close()
            users, err := m.Users.List()
            if err != nil { return err }
            if len(users) == 0 { fmt.Println("No users."); return nil }
            tw := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
            fmt.Fprintln(tw, "ID\tUSERNAME\tROLES\tACTIVE\tCREATED")
            fmt.Fprintln(tw, "--\t--------\t-----\t------\t-------")
            for _, u := range users {
                active := "yes"
                if !u.Active { active = "no" }
                fmt.Fprintf(tw, "%d\t%s\t[%s]\t%s\t%s\n",
                    u.ID, u.Username, strings.Join(u.Roles, ", "),
                    active, u.CreatedAt.Format("2006-01-02 15:04"))
            }
            tw.Flush()
            return nil
        },
    }
}

func authCmdUserPasswd(dbPath *string) *cobra.Command {
    var username, password string
    cmd := &cobra.Command{
        Use:   "passwd",
        Short: "Change a user's password",
        RunE: func(cmd *cobra.Command, args []string) error {
            if password == "" {
                var err error
                password, err = authPromptPassword("New password: ")
                if err != nil { return err }
                confirm, err := authPromptPassword("Confirm: ")
                if err != nil { return err }
                if password != confirm { return fmt.Errorf("passwords do not match") }
            }
            m, err := authOpen(dbPath)
            if err != nil { return err }
            defer m.Close()
            if err := m.Users.SetPassword(username, password); err != nil { return err }
            fmt.Printf("✓ Password updated for %q\n", username)
            return nil
        },
    }
    cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
    cmd.Flags().StringVarP(&password, "password", "p", "", "New password (prompted if omitted)")
    cmd.MarkFlagRequired("username")
    return cmd
}

func authCmdUserRoles(dbPath *string) *cobra.Command {
    var username string
    var roles []string
    cmd := &cobra.Command{
        Use:   "roles",
        Short: "Replace role list for a user",
        RunE: func(cmd *cobra.Command, args []string) error {
            m, err := authOpen(dbPath)
            if err != nil { return err }
            defer m.Close()
            if err := m.Users.SetRoles(username, roles); err != nil { return err }
            fmt.Printf("✓ Roles for %q: [%s]\n", username, strings.Join(roles, ", "))
            return nil
        },
    }
    cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
    cmd.Flags().StringSliceVarP(&roles, "roles", "r", nil, "New roles (replaces existing)")
    cmd.MarkFlagRequired("username")
    cmd.MarkFlagRequired("roles")
    return cmd
}

func authCmdUserActivate(dbPath *string) *cobra.Command {
    var username string
    cmd := &cobra.Command{Use: "activate", Short: "Re-enable a disabled user",
        RunE: func(cmd *cobra.Command, args []string) error {
            return authSetActive(dbPath, username, true)
        },
    }
    cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
    cmd.MarkFlagRequired("username")
    return cmd
}

func authCmdUserDeactivate(dbPath *string) *cobra.Command {
    var username string
    cmd := &cobra.Command{Use: "deactivate", Short: "Disable a user account",
        RunE: func(cmd *cobra.Command, args []string) error {
            return authSetActive(dbPath, username, false)
        },
    }
    cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
    cmd.MarkFlagRequired("username")
    return cmd
}

func authSetActive(dbPath *string, username string, active bool) error {
    m, err := authOpen(dbPath)
    if err != nil { return err }
    defer m.Close()
    if err := m.Users.SetActive(username, active); err != nil { return err }
    state := "activated"
    if !active { state = "deactivated" }
    fmt.Printf("✓ User %q %s\n", username, state)
    return nil
}

func authCmdUserDelete(dbPath *string) *cobra.Command {
    var username string
    var force bool
    cmd := &cobra.Command{
        Use:   "delete",
        Short: "Permanently delete a user",
        RunE: func(cmd *cobra.Command, args []string) error {
            if !force {
                fmt.Printf("Pass --force to confirm deletion of %q\n", username)
                return nil
            }
            m, err := authOpen(dbPath)
            if err != nil { return err }
            defer m.Close()
            if err := m.Users.Delete(username); err != nil { return err }
            fmt.Printf("✓ User %q deleted\n", username)
            return nil
        },
    }
    cmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
    cmd.Flags().BoolVar(&force, "force", false, "Confirm permanent deletion")
    cmd.MarkFlagRequired("username")
    return cmd
}

func authCmdSessionList(dbPath *string) *cobra.Command {
    return &cobra.Command{
        Use:   "list",
        Short: "List active sessions",
        RunE: func(cmd *cobra.Command, args []string) error {
            m, err := authOpen(dbPath)
            if err != nil { return err }
            defer m.Close()
            sessions, err := m.ListSessions()
            if err != nil { return err }
            if len(sessions) == 0 { fmt.Println("No active sessions."); return nil }
            tw := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
            fmt.Fprintln(tw, "TOKEN (prefix)\tEXPIRES")
            fmt.Fprintln(tw, "-------------\t-------")
            for _, s := range sessions {
                tok := s.Token
                if len(tok) > 16 { tok = tok[:16] + "…" }
                fmt.Fprintf(tw, "%s\t%s\n", tok, s.Expiry.Format("2006-01-02 15:04:05"))
            }
            tw.Flush()
            return nil
        },
    }
}

func authCmdSessionPurge(dbPath *string) *cobra.Command {
    return &cobra.Command{
        Use:   "purge",
        Short: "Delete all expired sessions",
        RunE: func(cmd *cobra.Command, args []string) error {
            m, err := authOpen(dbPath)
            if err != nil { return err }
            defer m.Close()
            n, err := m.PurgeSessions()
            if err != nil { return err }
            fmt.Printf("✓ Purged %d expired session(s)\n", n)
            return nil
        },
    }
}
```

Usage after embedding:

```bash
myapp auth user add -u chris -r admin
myapp auth user list
myapp auth user passwd -u chris
myapp auth user roles -u chris -r admin,viewer
myapp auth user deactivate -u someuser
myapp auth user activate   -u someuser
myapp auth user delete -u someuser --force
myapp auth session list
myapp auth session purge
myapp auth --db /other/path.db user list   # override default db path
```

---

## Standalone CLI

If you prefer a separate binary (requires Go on the target machine):

```bash
go install github.com/chrismfz/goauth/cmd/goauth@latest
```

Same commands as above but prefixed with `goauth --db /path/to/auth.db`.
For servers without Go, prefer the embedded CLI and cross-compile it
alongside your service binary.

---

---

## Rate limiting

`LoginHandler()` enforces two independent sliding-window rate limits
out of the box — no configuration required:

| Limit | Default | Scope |
|---|---|---|
| Per IP | 10 attempts / 60s | blocks credential stuffing from a single source |
| Per username | 20 attempts / 10min | blocks distributed attacks against one account |

When a limit is breached the handler returns `429 Too Many Requests`
with a `Retry-After` header and writes a `RATELIMIT` entry to `auth_log`.
The in-memory counters are pruned automatically every 5 minutes.

To tune the thresholds, edit `ratelimit.go`:

```go
func newLoginRateLimiter() *loginRateLimiter {
    return &loginRateLimiter{
        windowIP:   time.Minute,
        windowUser: 10 * time.Minute,
        maxPerIP:   10,  // attempts per window per IP
        maxPerUser: 20,  // attempts per window per username
    }
}
```

The client IP is resolved through `X-Forwarded-For` when the connection
comes from loopback (nginx proxy), so the real browser IP is always used
for rate limiting — not `127.0.0.1`.

---

## Audit log

Every login attempt is written to the `auth_log` SQLite table:

| event | reason | meaning |
|---|---|---|
| `SUCCESS` | — | credentials OK, session created |
| `FAIL` | `bad_credentials` | wrong password or unknown user |
| `FAIL` | `user_inactive` | account exists but is disabled |
| `FAIL` | `internal_error` | database or hashing error |
| `RATELIMIT` | `too_many_attempts_ip` | IP limit exceeded |
| `RATELIMIT` | `too_many_attempts_user` | username limit exceeded |

### Querying from Go

```go
// Last 100 entries, newest first
entries, err := auth.QueryAuthLog(100)

// Filter by IP
entries, err := auth.QueryAuthLogByIP("5.5.5.5", 50)

// Purge entries older than 90 days
n, err := auth.PurgeAuthLog(90 * 24 * time.Hour)
```

### Querying from the CLI

```bash
# Show last 50 attempts (default)
myapp auth log tail

# Show last 200 attempts
myapp auth log tail -n 200

# Filter by source IP
myapp auth log tail --ip 5.5.5.5

# Delete entries older than 90 days
myapp auth log purge --days 90
```

Sample output:

```
TIME                  EVENT      USERNAME   IP               REASON
----                  -----      --------   --               ------
2026-04-04 16:05:01   SUCCESS    chris      2.85.101.222
2026-04-04 16:04:58   FAIL       chris      2.85.101.222     bad_credentials
2026-04-04 16:04:55   FAIL       chris      2.85.101.222     bad_credentials
2026-04-04 16:04:40   RATELIMIT  admin      5.5.5.5          too_many_attempts_ip
2026-04-04 16:04:38   FAIL       admin      5.5.5.5          bad_credentials
```

### Wiring the log CLI commands into your embedded CLI

Add to `runAuthCLI()` in `cmd/myapp/auth_cli.go`:

```go
logCmd := &cobra.Command{Use: "log", Short: "View auth audit log"}
logCmd.AddCommand(
    authCmdLogTail(&dbPath),
    authCmdLogPurge(&dbPath),
)
root.AddCommand(userCmd, sessionCmd, logCmd)
```

Then add the two command functions:

```go
func authCmdLogTail(dbPath *string) *cobra.Command {
    var limit int
    var ip string
    cmd := &cobra.Command{
        Use:   "tail",
        Short: "Show recent login attempts",
        RunE: func(cmd *cobra.Command, args []string) error {
            m, err := authOpen(dbPath)
            if err != nil { return err }
            defer m.Close()

            var entries []goauth.AuthLogEntry
            if ip != "" {
                entries, err = m.QueryAuthLogByIP(ip, limit)
            } else {
                entries, err = m.QueryAuthLog(limit)
            }
            if err != nil { return err }
            if len(entries) == 0 { fmt.Println("No auth log entries."); return nil }

            tw := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
            fmt.Fprintln(tw, "TIME\tEVENT\tUSERNAME\tIP\tREASON")
            for _, e := range entries {
                fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
                    e.Time.Format("2006-01-02 15:04:05"),
                    e.Event, e.Username, e.IP, e.Reason,
                )
            }
            tw.Flush()
            return nil
        },
    }
    cmd.Flags().IntVarP(&limit, "count", "n", 50, "Number of entries to show")
    cmd.Flags().StringVar(&ip, "ip", "", "Filter by IP address")
    return cmd
}

func authCmdLogPurge(dbPath *string) *cobra.Command {
    var days int
    cmd := &cobra.Command{
        Use:   "purge",
        Short: "Delete auth log entries older than N days",
        RunE: func(cmd *cobra.Command, args []string) error {
            m, err := authOpen(dbPath)
            if err != nil { return err }
            defer m.Close()
            n, err := m.PurgeAuthLog(time.Duration(days) * 24 * time.Hour)
            if err != nil { return err }
            fmt.Printf("✓ Purged %d auth log entries older than %d days\n", n, days)
            return nil
        },
    }
    cmd.Flags().IntVar(&days, "days", 90, "Delete entries older than this many days")
    return cmd
}
```

## Configuration reference

| Field | Default | Description |
|---|---|---|
| `DBPath` | — | Path to SQLite file (created if absent) |
| `SessionTTL` | `8h` | Absolute session lifetime |
| `IdleTimeout` | `30m` | Inactivity expiry (0 = disabled) |
| `CookieName` | `__Host-sid` | Cookie name (`__Host-` forces Secure + Path=/) |
| `SecureCookie` | `false` | Set `Secure` flag (required in production over HTTPS) |
| `SameSite` | `Strict` | `SameSite` cookie attribute |
| `LoginPath` | `/login` | Redirect target for unauthenticated browser requests |
| `OnAuthFailure` | `nil` | Custom handler called on 401/403 (overrides default behaviour) |

**Cookie name note:** `__Host-` prefix enforces `Secure=true`, `Path=/`, and
no `Domain` at the browser level. Requires `SecureCookie: true`. Use a plain
name (e.g. `myapp-sid`) when running over HTTP locally.

---

## Database schema

Three tables are created automatically on first run:

```sql
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    roles         TEXT    NOT NULL DEFAULT '[]',  -- JSON array
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE sessions (
    token  TEXT    PRIMARY KEY,
    data   BLOB    NOT NULL,
    expiry INTEGER NOT NULL
);

-- Login audit log — every attempt is recorded here
CREATE TABLE auth_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    event    TEXT    NOT NULL,  -- SUCCESS | FAIL | RATELIMIT
    username TEXT    NOT NULL DEFAULT '',
    ip       TEXT    NOT NULL DEFAULT '',
    reason   TEXT    NOT NULL DEFAULT ''  -- bad_credentials | user_inactive | too_many_attempts_ip | too_many_attempts_user
);
```

---

## Deployment checklist

- [ ] `auth.db_path` configured
- [ ] `secure_cookie: true` in production (HTTPS)
- [ ] Cookie name: plain name for HTTP, `__Host-` prefix for HTTPS
- [ ] nginx: `auth_basic` removed, `X-Forwarded-For` header forwarded
- [ ] First user created: `myapp auth user add -u admin -r admin`
- [ ] `WithAuth` uses `realIPAllowed` not `r.RemoteAddr` / `ipAllowed`
- [ ] `WithMainIPOnly` uses `realIPAllowed` not `r.RemoteAddr` / `ipAllowed`
- [ ] `/login` and `/logout` registered without any auth guard
- [ ] `Auth.LoadAndSave()` is the outermost wrapper around the entire mux

---

## Roadmap

- [ ] TOTP / 2FA support
- [ ] `session kill <token>` CLI command
- [ ] `user import` from htpasswd (migration helper)

- [ ] **Pluggable auth backends** — extract `UserStore` into a `UserBackend`
      interface so any credential source can be swapped in without touching
      sessions, cookies, rate limiting or audit log.

      Planned backends:
      - `sqlite` — current default, full CRUD
      - `htpasswd` — read-only, bcrypt comparison, migration bridge
      - `pam` — Linux PAM via CGO, roles derived from Unix groups
      - `ldap` — LDAP / Active Directory, roles from `memberOf`
      - `postgres` / `mysql` — shared auth DB for multi-server deployments
      - `dovecot` — mail account auth via dovecot auth socket
      - `http` — delegate to upstream REST auth API
      - `oidc` — OAuth2 / OpenID Connect (Auth0, Keycloak, Google, GitHub)

      Read-only backends (ldap, dovecot, oidc) return `ErrNotSupported`
      for write ops — the CLI prints a helpful message instead of failing.

      Migration path between backends:
	argus auth migrate export --format json > users.json
	argus auth migrate import --format json < users.json

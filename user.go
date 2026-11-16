package goauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/pquerna/otp/totp"
)

// totpPeriod is the TOTP time step in seconds (the RFC 6238 default, which is
// what totp.Generate and every authenticator app use).
const totpPeriod = 30

// Sentinel errors returned by UserStore operations.
var (
	ErrUserNotFound   = errors.New("goauth: user not found")
	ErrUserExists     = errors.New("goauth: username already exists")
	ErrUserInactive   = errors.New("goauth: user account is inactive")
	ErrBadCredentials = errors.New("goauth: invalid username or password")
)

// User represents a stored user account.
type User struct {
	ID             int64
	Username       string
	Roles          []string
	Active         bool
	MFAEnabled     bool
	MFAType        string
	TOTPVerifiedAt *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// HasRole reports whether the user holds the given role.
func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// UserStore provides user management backed by SQLite.
type UserStore struct {
	db *sql.DB

	stateMu sync.Mutex
	state   map[string]cachedSessionState
}

// foldUsername lowercases ASCII letters only, which is exactly how the users
// table compares names (SQLite NOCASE). Unicode folding would be wider than
// the database: "kate" and "\u212Aate" (Kelvin sign) are two different rows,
// and anything keyed on a Unicode-folded name would treat them as one user.
func foldUsername(username string) string {
	b := []byte(username)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// sameUsername reports whether two names are the same row in the users table.
func sameUsername(a, b string) bool {
	return foldUsername(a) == foldUsername(b)
}

// sessionState is what a request needs to know about its session's user.
type sessionState struct {
	Username string
	Roles    []string
	Active   bool
	Epoch    int64
}

type cachedSessionState struct {
	st    sessionState
	found bool
	at    time.Time
}

const (
	// A change made by another process (the CLI) reaches a running server
	// within this long. Changes made in-process drop the entry at once.
	sessionStateTTL = 5 * time.Second
	// When the database cannot be read, the last answer is used for this
	// long, so a busy database does not bounce every logged-in user.
	sessionStateStaleTTL = time.Minute
)

// sessionStateFor returns the user's current roles, active flag and session
// epoch. fresh skips the cache (used when a session is created).
func (s *UserStore) sessionStateFor(username string, fresh bool) (sessionState, bool, error) {
	key := foldUsername(username)
	now := time.Now()

	s.stateMu.Lock()
	cached, have := s.state[key]
	s.stateMu.Unlock()
	if have && !fresh && now.Sub(cached.at) < sessionStateTTL {
		return cached.st, cached.found, nil
	}

	var (
		st     sessionState
		roles  string
		active int
	)
	err := s.db.QueryRow(
		`SELECT username, roles, active, session_epoch FROM users WHERE username=? COLLATE NOCASE`,
		username,
	).Scan(&st.Username, &roles, &active, &st.Epoch)
	found := true
	switch {
	case errors.Is(err, sql.ErrNoRows):
		found = false
	case err != nil:
		if have && !fresh && now.Sub(cached.at) < sessionStateStaleTTL {
			return cached.st, cached.found, nil
		}
		return sessionState{}, false, fmt.Errorf("goauth: session state: %w", err)
	default:
		if json.Unmarshal([]byte(roles), &st.Roles) != nil {
			st.Roles = []string{}
		}
		st.Active = active == 1
	}

	s.stateMu.Lock()
	if s.state == nil {
		s.state = make(map[string]cachedSessionState)
	}
	s.state[key] = cachedSessionState{st: st, found: found, at: now}
	s.stateMu.Unlock()
	return st, found, nil
}

func (s *UserStore) forgetSessionState(username string) {
	s.stateMu.Lock()
	delete(s.state, foldUsername(username))
	s.stateMu.Unlock()
}

// RevokeSessions ends every session of the user ("log out everywhere"). A
// running server notices within a few seconds when another process calls it.
func (s *UserStore) RevokeSessions(username string) error {
	res, err := s.db.Exec(
		`UPDATE users SET session_epoch=session_epoch+1, updated_at=? WHERE username=? COLLATE NOCASE`,
		time.Now().Unix(), username,
	)
	if err != nil {
		return fmt.Errorf("goauth: revoke sessions: %w", err)
	}
	s.forgetSessionState(username)
	return requireOneRow(res, ErrUserNotFound)
}

const DefaultRecoveryCodeCount = 10

// TOTPEnrollment holds pending TOTP enrollment payload for CLI/UI display.
type TOTPEnrollment struct {
	Issuer     string
	Account    string
	Secret     string
	OTPAuthURI string
}

// --- Write operations ---

// Create adds a new user with the given username, plaintext password, and roles.
// The password is hashed with Argon2id before storage.
func (s *UserStore) Create(username, password string, roles []string) error {
	if roles == nil {
		roles = []string{}
	}
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return fmt.Errorf("goauth: hash password: %w", err)
	}
	rolesJSON, err := json.Marshal(roles)
	if err != nil {
		return err
	}
	now := time.Now()
	// The session epoch starts at a value no earlier account of this name
	// had: a session left over from a deleted user must not fit the user
	// created under the same name later.
	_, err = s.db.Exec(
		`INSERT INTO users (username, password_hash, roles, active, session_epoch, created_at, updated_at)
		 VALUES (?, ?, ?, 1, ?, ?, ?)`,
		username, hash, string(rolesJSON), now.UnixNano(), now.Unix(), now.Unix(),
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return ErrUserExists
		}
		return fmt.Errorf("goauth: create user: %w", err)
	}
	s.forgetSessionState(username)
	return nil
}

// SetPassword replaces the stored password hash for the given username and
// ends every session of the user: whoever held the old password, or a session
// made with it, is out.
func (s *UserStore) SetPassword(username, newPassword string) error {
	hash, err := argon2id.CreateHash(newPassword, argon2id.DefaultParams)
	if err != nil {
		return fmt.Errorf("goauth: hash password: %w", err)
	}
	res, err := s.db.Exec(
		`UPDATE users SET password_hash=?, session_epoch=session_epoch+1, updated_at=? WHERE username=? COLLATE NOCASE`,
		hash, time.Now().Unix(), username,
	)
	if err != nil {
		return fmt.Errorf("goauth: set password: %w", err)
	}
	s.forgetSessionState(username)
	return requireOneRow(res, ErrUserNotFound)
}

// SetActive enables or disables a user account. Disabling ends the user's
// sessions, and enabling the account again does not bring them back.
func (s *UserStore) SetActive(username string, active bool) error {
	val, bump := 0, 1
	if active {
		val, bump = 1, 0
	}
	res, err := s.db.Exec(
		`UPDATE users SET active=?, session_epoch=session_epoch+?, updated_at=? WHERE username=? COLLATE NOCASE`,
		val, bump, time.Now().Unix(), username,
	)
	if err != nil {
		return fmt.Errorf("goauth: set active: %w", err)
	}
	s.forgetSessionState(username)
	return requireOneRow(res, ErrUserNotFound)
}

// SetRoles replaces the role list for the given user. Open sessions get the
// new roles on their next request.
func (s *UserStore) SetRoles(username string, roles []string) error {
	if roles == nil {
		roles = []string{}
	}
	rolesJSON, err := json.Marshal(roles)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(
		`UPDATE users SET roles=?, updated_at=? WHERE username=? COLLATE NOCASE`,
		string(rolesJSON), time.Now().Unix(), username,
	)
	if err != nil {
		return fmt.Errorf("goauth: set roles: %w", err)
	}
	s.forgetSessionState(username)
	return requireOneRow(res, ErrUserNotFound)
}

// Delete permanently removes a user.
func (s *UserStore) Delete(username string) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE username=? COLLATE NOCASE`, username)
	if err != nil {
		return fmt.Errorf("goauth: delete user: %w", err)
	}
	s.forgetSessionState(username)
	return requireOneRow(res, ErrUserNotFound)
}

// SetTOTPSecretUnverified stores an encrypted TOTP secret without enabling MFA.
func (s *UserStore) SetTOTPSecretUnverified(username, encryptedSecret string) error {
	res, err := s.db.Exec(
		`UPDATE users
		 SET mfa_enabled=0, mfa_type='totp', totp_secret_enc=?, totp_verified_at=NULL, updated_at=?
		 WHERE username=? COLLATE NOCASE`,
		encryptedSecret, time.Now().Unix(), username,
	)
	if err != nil {
		return fmt.Errorf("goauth: set totp secret unverified: %w", err)
	}
	return requireOneRow(res, ErrUserNotFound)
}

// ConfirmTOTP marks an existing TOTP secret as enabled/verified.
func (s *UserStore) ConfirmTOTP(username string) error {
	now := time.Now().Unix()
	res, err := s.db.Exec(
		`UPDATE users
		 SET mfa_enabled=1, mfa_type='totp', totp_verified_at=?, updated_at=?
		 WHERE username=? COLLATE NOCASE AND totp_secret_enc IS NOT NULL`,
		now, now, username,
	)
	if err != nil {
		return fmt.Errorf("goauth: confirm totp: %w", err)
	}
	return requireOneRow(res, ErrUserNotFound)
}

// BeginTOTPEnrollment generates a TOTP secret for a user and stores it as
// PENDING. The returned enrollment payload includes the otpauth URI for QR
// generation.
//
// Nothing about the user's current MFA changes until the new secret is
// confirmed with a code. It used to overwrite the active secret and switch
// MFA off on the spot, so starting an enrollment was a way to disable MFA.
func (s *UserStore) BeginTOTPEnrollment(username, issuer string, mfaKey []byte) (*TOTPEnrollment, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
	})
	if err != nil {
		return nil, fmt.Errorf("goauth: begin totp enrollment: %w", err)
	}

	enc, err := encryptSecret(key.Secret(), mfaKey)
	if err != nil {
		return nil, fmt.Errorf("goauth: begin totp enrollment: %w", err)
	}
	res, err := s.db.Exec(
		`UPDATE users SET totp_pending_secret_enc=?, updated_at=? WHERE username=? COLLATE NOCASE`,
		enc, time.Now().Unix(), username,
	)
	if err != nil {
		return nil, fmt.Errorf("goauth: begin totp enrollment: %w", err)
	}
	if err := requireOneRow(res, ErrUserNotFound); err != nil {
		return nil, err
	}

	return &TOTPEnrollment{
		Issuer:     issuer,
		Account:    username,
		Secret:     key.Secret(),
		OTPAuthURI: key.URL(),
	}, nil
}

// matchTOTPStep reports which time step (now, one before or one after) the
// code belongs to. It accepts what totp.Validate accepts, and also says which
// step matched, so that a step can be refused the second time.
func matchTOTPStep(code, secret string, now time.Time) (int64, bool) {
	code = normalizeMFACode(code)
	current := now.Unix() / totpPeriod
	for _, step := range []int64{current, current - 1, current + 1} {
		want, err := totp.GenerateCode(secret, time.Unix(step*totpPeriod, 0))
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// consumeTOTPStep records a matched time step and reports whether it was new.
// A code seen over a shoulder or on the wire cannot be used again, not even
// inside its own 90-second window.
func (s *UserStore) consumeTOTPStep(username string, step int64) (bool, error) {
	res, err := s.db.Exec(
		`UPDATE users SET totp_last_step=? WHERE username=? COLLATE NOCASE AND totp_last_step < ?`,
		step, username, step,
	)
	if err != nil {
		return false, fmt.Errorf("goauth: consume totp step: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// VerifyTOTPEnrollment validates a TOTP code against a pending secret and
// enables TOTP MFA on success: the pending secret becomes the active one.
func (s *UserStore) VerifyTOTPEnrollment(username, code string, mfaKey []byte) (verified bool, pending bool, err error) {
	var (
		pendingEnc, activeEnc sql.NullString
		enabled               int
	)
	err = s.db.QueryRow(
		`SELECT totp_pending_secret_enc, totp_secret_enc, mfa_enabled FROM users WHERE username=? COLLATE NOCASE`,
		username,
	).Scan(&pendingEnc, &activeEnc, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, ErrUserNotFound
	}
	if err != nil {
		return false, false, fmt.Errorf("goauth: verify totp enrollment: %w", err)
	}

	enc := pendingEnc.String
	if enc == "" {
		// An enrollment started by an older version (or SetTOTPSecretUnverified)
		// keeps its secret in the active column with MFA off.
		if enabled == 1 || activeEnc.String == "" {
			return false, false, nil
		}
		enc = activeEnc.String
	}
	pending = true

	secret, err := decryptSecret(enc, mfaKey)
	if err != nil {
		return false, pending, fmt.Errorf("goauth: verify totp enrollment: %w", err)
	}
	step, ok := matchTOTPStep(code, secret, time.Now())
	if !ok {
		return false, pending, nil
	}
	now := time.Now().Unix()
	res, err := s.db.Exec(
		`UPDATE users
		 SET mfa_enabled=1, mfa_type='totp', totp_secret_enc=?, totp_pending_secret_enc=NULL,
		     totp_verified_at=?, totp_last_step=?, updated_at=?
		 WHERE username=? COLLATE NOCASE`,
		enc, now, step, now, username,
	)
	if err != nil {
		return false, pending, fmt.Errorf("goauth: verify totp enrollment: %w", err)
	}
	if err := requireOneRow(res, ErrUserNotFound); err != nil {
		return false, pending, err
	}
	return true, pending, nil
}

// DisableMFA disables all MFA factors for the given user.
func (s *UserStore) DisableMFA(username string) error {
	res, err := s.db.Exec(
		`UPDATE users
		 SET mfa_enabled=0, mfa_type='', totp_secret_enc=NULL, totp_pending_secret_enc=NULL, totp_verified_at=NULL, updated_at=?
		 WHERE username=? COLLATE NOCASE`,
		time.Now().Unix(), username,
	)
	if err != nil {
		return fmt.Errorf("goauth: disable mfa: %w", err)
	}
	return requireOneRow(res, ErrUserNotFound)
}

// ResetMFA clears all MFA factors and pending MFA challenges for a user.
func (s *UserStore) ResetMFA(username string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("goauth: reset mfa: %w", err)
	}
	defer tx.Rollback()

	var userID int64
	if err := tx.QueryRow(
		`SELECT id FROM users WHERE username=? COLLATE NOCASE`,
		username,
	).Scan(&userID); errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	} else if err != nil {
		return fmt.Errorf("goauth: reset mfa: %w", err)
	}

	now := time.Now().Unix()
	if _, err := tx.Exec(
		`UPDATE users
		 SET mfa_enabled=0, mfa_type='', totp_secret_enc=NULL, totp_pending_secret_enc=NULL, totp_verified_at=NULL, updated_at=?
		 WHERE id=?`,
		now, userID,
	); err != nil {
		return fmt.Errorf("goauth: reset mfa: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM mfa_recovery_codes WHERE user_id=?`, userID); err != nil {
		return fmt.Errorf("goauth: reset mfa: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM webauthn_credentials WHERE user_id=?`, userID); err != nil {
		return fmt.Errorf("goauth: reset mfa: %w", err)
	}
	if _, err := tx.Exec(
		`DELETE FROM webauthn_challenges WHERE username=? COLLATE NOCASE`,
		username,
	); err != nil {
		return fmt.Errorf("goauth: reset mfa: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("goauth: reset mfa: %w", err)
	}
	return nil
}

func hashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(normalizeMFACode(code)))
	return hex.EncodeToString(sum[:])
}

func generateRecoveryCode() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	enc := strings.TrimRight(base32.StdEncoding.EncodeToString(buf), "=")
	enc = strings.ToUpper(enc)
	if len(enc) > 12 {
		enc = enc[:12]
	}
	return enc[:4] + "-" + enc[4:8] + "-" + enc[8:12], nil
}

// GenerateRecoveryCodes rotates all recovery codes for a user and returns
// the newly generated plaintext values. Callers must display them once and
// never persist plaintext at rest.
func (s *UserStore) GenerateRecoveryCodes(username string, count int) ([]string, error) {
	if count <= 0 {
		return nil, errors.New("goauth: recovery code count must be positive")
	}

	var userID int64
	if err := s.db.QueryRow(
		`SELECT id FROM users WHERE username=? COLLATE NOCASE`,
		username,
	).Scan(&userID); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	} else if err != nil {
		return nil, fmt.Errorf("goauth: generate recovery codes: %w", err)
	}

	codes := make([]string, 0, count)
	seen := map[string]struct{}{}
	for len(codes) < count {
		code, err := generateRecoveryCode()
		if err != nil {
			return nil, fmt.Errorf("goauth: generate recovery codes: %w", err)
		}
		norm := normalizeMFACode(code)
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		codes = append(codes, code)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("goauth: generate recovery codes: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM mfa_recovery_codes WHERE user_id=?`, userID); err != nil {
		return nil, fmt.Errorf("goauth: generate recovery codes: %w", err)
	}
	now := time.Now().Unix()
	for _, code := range codes {
		if _, err := tx.Exec(
			`INSERT INTO mfa_recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)`,
			userID, hashRecoveryCode(code), now,
		); err != nil {
			return nil, fmt.Errorf("goauth: generate recovery codes: %w", err)
		}
	}
	if _, err := tx.Exec(
		`UPDATE users SET updated_at=? WHERE id=?`,
		now, userID,
	); err != nil {
		return nil, fmt.Errorf("goauth: generate recovery codes: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("goauth: generate recovery codes: %w", err)
	}
	return codes, nil
}

// CountRecoveryCodes returns the number of remaining recovery codes for a user.
func (s *UserStore) CountRecoveryCodes(username string) (int, error) {
	var userID int64
	if err := s.db.QueryRow(
		`SELECT id FROM users WHERE username=? COLLATE NOCASE`,
		username,
	).Scan(&userID); errors.Is(err, sql.ErrNoRows) {
		return 0, ErrUserNotFound
	} else if err != nil {
		return 0, fmt.Errorf("goauth: count recovery codes: %w", err)
	}

	var count int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id=?`,
		userID,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("goauth: count recovery codes: %w", err)
	}
	return count, nil
}

// ConsumeRecoveryCode deletes a single matching MFA recovery code hash for a user.
// It returns true only when a matching code existed and was consumed.
func (s *UserStore) ConsumeRecoveryCode(username, code string) (bool, int, error) {
	var userID int64
	if err := s.db.QueryRow(
		`SELECT id FROM users WHERE username=? COLLATE NOCASE`,
		username,
	).Scan(&userID); errors.Is(err, sql.ErrNoRows) {
		return false, 0, ErrUserNotFound
	} else if err != nil {
		return false, 0, fmt.Errorf("goauth: consume recovery code: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return false, 0, fmt.Errorf("goauth: consume recovery code: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec(
		`DELETE FROM mfa_recovery_codes
		 WHERE user_id=? AND code_hash=?`,
		userID, hashRecoveryCode(code),
	)
	if err != nil {
		return false, 0, fmt.Errorf("goauth: consume recovery code: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, 0, err
	}

	var remaining int
	if err := tx.QueryRow(
		`SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id=?`,
		userID,
	).Scan(&remaining); err != nil {
		return false, 0, fmt.Errorf("goauth: consume recovery code: %w", err)
	}
	if _, err := tx.Exec(
		`UPDATE users SET updated_at=? WHERE id=?`,
		time.Now().Unix(), userID,
	); err != nil {
		return false, 0, fmt.Errorf("goauth: consume recovery code: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, 0, fmt.Errorf("goauth: consume recovery code: %w", err)
	}
	return n > 0, remaining, nil
}

// --- Read operations ---

// GetTOTPSecret fetches the stored TOTP secret for a user.
func (s *UserStore) GetTOTPSecret(username string) (string, error) {
	var secret sql.NullString
	err := s.db.QueryRow(
		`SELECT totp_secret_enc FROM users WHERE username=? COLLATE NOCASE`,
		username,
	).Scan(&secret)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrUserNotFound
	}
	if err != nil {
		return "", fmt.Errorf("goauth: get totp secret: %w", err)
	}
	if !secret.Valid {
		return "", nil
	}
	return secret.String, nil
}

// GetByUsername fetches a user by username (case-insensitive).
func (s *UserStore) GetByUsername(username string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, roles, active, mfa_enabled, mfa_type, totp_verified_at, created_at, updated_at
		 FROM users WHERE username=? COLLATE NOCASE`,
		username,
	)
	return scanUser(row)
}

// List returns all users ordered by username.
func (s *UserStore) List() ([]*User, error) {
	rows, err := s.db.Query(
		`SELECT id, username, roles, active, mfa_enabled, mfa_type, totp_verified_at, created_at, updated_at
		 FROM users ORDER BY username COLLATE NOCASE`,
	)
	if err != nil {
		return nil, fmt.Errorf("goauth: list users: %w", err)
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// Authenticate verifies credentials and returns the User on success.
// Returns ErrBadCredentials for wrong password, ErrUserInactive for disabled accounts.
func (s *UserStore) Authenticate(username, password string) (*User, error) {
	row := s.db.QueryRow(
		`SELECT id, username, password_hash, roles, active, mfa_enabled, mfa_type, totp_verified_at, created_at, updated_at
		 FROM users WHERE username=? COLLATE NOCASE`,
		username,
	)

	var (
		u                    User
		hash                 string
		roles                string
		active               int
		mfaEnabled           int
		totpVerifiedAt       sql.NullInt64
		createdAt, updatedAt int64
	)
	err := row.Scan(&u.ID, &u.Username, &hash, &roles, &active, &mfaEnabled, &u.MFAType, &totpVerifiedAt, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		// Burn the same Argon2 work as a real comparison, so the response time
		// does not say whether the username exists.
		argon2id.ComparePasswordAndHash(password, dummyPasswordHash())
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("goauth: authenticate: %w", err)
	}

	match, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil || !match {
		return nil, ErrBadCredentials
	}

	if active == 0 {
		return nil, ErrUserInactive
	}

	if err := json.Unmarshal([]byte(roles), &u.Roles); err != nil {
		u.Roles = []string{}
	}
	u.Active = true
	u.MFAEnabled = mfaEnabled == 1
	if totpVerifiedAt.Valid {
		t := time.Unix(totpVerifiedAt.Int64, 0)
		u.TOTPVerifiedAt = &t
	}
	u.CreatedAt = time.Unix(createdAt, 0)
	u.UpdatedAt = time.Unix(updatedAt, 0)
	return &u, nil
}

// --- Helpers ---

// dummyPasswordHash returns a real Argon2id hash, made once with the same
// parameters Create and SetPassword use. The literal that stood here before
// was not valid base64, so the comparison failed in microseconds without
// hashing anything: an unknown username answered ~700x faster than a known one.
var dummyPasswordHash = sync.OnceValue(func() string {
	h, err := argon2id.CreateHash("goauth-dummy-password", argon2id.DefaultParams)
	if err != nil {
		panic("goauth: create dummy password hash: " + err.Error())
	}
	return h
})

type scanner interface {
	Scan(dest ...any) error
}

func scanUser(s scanner) (*User, error) {
	var (
		u                    User
		active               int
		mfaEnabled           int
		rolesJSON            string
		totpVerifiedAt       sql.NullInt64
		createdAt, updatedAt int64
	)
	err := s.Scan(&u.ID, &u.Username, &rolesJSON, &active, &mfaEnabled, &u.MFAType, &totpVerifiedAt, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("goauth: scan user: %w", err)
	}
	if err := json.Unmarshal([]byte(rolesJSON), &u.Roles); err != nil {
		u.Roles = []string{}
	}
	u.Active = active == 1
	u.MFAEnabled = mfaEnabled == 1
	if totpVerifiedAt.Valid {
		t := time.Unix(totpVerifiedAt.Int64, 0)
		u.TOTPVerifiedAt = &t
	}
	u.CreatedAt = time.Unix(createdAt, 0)
	u.UpdatedAt = time.Unix(updatedAt, 0)
	return &u, nil
}

func requireOneRow(res sql.Result, notFoundErr error) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return notFoundErr
	}
	return nil
}

// isUniqueConstraint detects SQLite UNIQUE constraint violations without
// importing the driver's error types directly.
func isUniqueConstraint(err error) bool {
	if err == nil {
		return false
	}
	// modernc.org/sqlite and mattn/go-sqlite3 both surface this string.
	return containsAny(err.Error(), "UNIQUE constraint failed", "SQLITE_CONSTRAINT_UNIQUE")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

package goauth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/alexedwards/argon2id"
)

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
	now := time.Now().Unix()
	_, err = s.db.Exec(
		`INSERT INTO users (username, password_hash, roles, active, created_at, updated_at)
		 VALUES (?, ?, ?, 1, ?, ?)`,
		username, hash, string(rolesJSON), now, now,
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return ErrUserExists
		}
		return fmt.Errorf("goauth: create user: %w", err)
	}
	return nil
}

// SetPassword replaces the stored password hash for the given username.
func (s *UserStore) SetPassword(username, newPassword string) error {
	hash, err := argon2id.CreateHash(newPassword, argon2id.DefaultParams)
	if err != nil {
		return fmt.Errorf("goauth: hash password: %w", err)
	}
	res, err := s.db.Exec(
		`UPDATE users SET password_hash=?, updated_at=? WHERE username=? COLLATE NOCASE`,
		hash, time.Now().Unix(), username,
	)
	if err != nil {
		return fmt.Errorf("goauth: set password: %w", err)
	}
	return requireOneRow(res, ErrUserNotFound)
}

// SetActive enables or disables a user account.
func (s *UserStore) SetActive(username string, active bool) error {
	val := 0
	if active {
		val = 1
	}
	res, err := s.db.Exec(
		`UPDATE users SET active=?, updated_at=? WHERE username=? COLLATE NOCASE`,
		val, time.Now().Unix(), username,
	)
	if err != nil {
		return fmt.Errorf("goauth: set active: %w", err)
	}
	return requireOneRow(res, ErrUserNotFound)
}

// SetRoles replaces the role list for the given user.
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
	return requireOneRow(res, ErrUserNotFound)
}

// Delete permanently removes a user.
func (s *UserStore) Delete(username string) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE username=? COLLATE NOCASE`, username)
	if err != nil {
		return fmt.Errorf("goauth: delete user: %w", err)
	}
	return requireOneRow(res, ErrUserNotFound)
}

// EnableTOTP enables TOTP MFA for the given user and stores the encrypted secret.
func (s *UserStore) EnableTOTP(username, encryptedSecret string) error {
	now := time.Now().Unix()
	res, err := s.db.Exec(
		`UPDATE users
		 SET mfa_enabled=1, mfa_type='totp', totp_secret_enc=?, totp_verified_at=?, updated_at=?
		 WHERE username=? COLLATE NOCASE`,
		encryptedSecret, now, now, username,
	)
	if err != nil {
		return fmt.Errorf("goauth: enable totp: %w", err)
	}
	return requireOneRow(res, ErrUserNotFound)
}

// DisableMFA disables all MFA factors for the given user.
func (s *UserStore) DisableMFA(username string) error {
	res, err := s.db.Exec(
		`UPDATE users
		 SET mfa_enabled=0, mfa_type='', totp_secret_enc=NULL, totp_verified_at=NULL, updated_at=?
		 WHERE username=? COLLATE NOCASE`,
		time.Now().Unix(), username,
	)
	if err != nil {
		return fmt.Errorf("goauth: disable mfa: %w", err)
	}
	return requireOneRow(res, ErrUserNotFound)
}

// ConsumeRecoveryCode deletes a single matching MFA recovery code hash for a user.
// It returns true only when a matching code existed and was consumed.
func (s *UserStore) ConsumeRecoveryCode(username, code string) (bool, error) {
	var userID int64
	if err := s.db.QueryRow(
		`SELECT id FROM users WHERE username=? COLLATE NOCASE`,
		username,
	).Scan(&userID); errors.Is(err, sql.ErrNoRows) {
		return false, ErrUserNotFound
	} else if err != nil {
		return false, fmt.Errorf("goauth: consume recovery code: %w", err)
	}

	sum := sha256.Sum256([]byte(code))
	codeHash := hex.EncodeToString(sum[:])
	res, err := s.db.Exec(
		`DELETE FROM mfa_recovery_codes
		 WHERE user_id=? AND code_hash=?`,
		userID, codeHash,
	)
	if err != nil {
		return false, fmt.Errorf("goauth: consume recovery code: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
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
		// Perform a dummy hash to prevent timing-based username enumeration.
		argon2id.ComparePasswordAndHash(password, "$argon2id$v=19$m=65536,t=3,p=2$dummysaltdummysalt$dummyhash")
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

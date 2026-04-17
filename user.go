package goauth

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/pquerna/otp/totp"
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

// BeginTOTPEnrollment generates and stores a pending TOTP secret for a user.
// The returned enrollment payload includes the otpauth URI for QR generation.
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
	if err := s.SetTOTPSecretUnverified(username, enc); err != nil {
		return nil, err
	}

	return &TOTPEnrollment{
		Issuer:     issuer,
		Account:    username,
		Secret:     key.Secret(),
		OTPAuthURI: key.URL(),
	}, nil
}

// VerifyTOTPEnrollment validates a TOTP code against a pending secret and
// enables TOTP MFA on success.
func (s *UserStore) VerifyTOTPEnrollment(username, code string, mfaKey []byte) (verified bool, pending bool, err error) {
	enc, err := s.GetTOTPSecret(username)
	if err != nil {
		return false, false, err
	}
	if enc == "" {
		return false, false, nil
	}
	pending = true

	secret, err := decryptSecret(enc, mfaKey)
	if err != nil {
		return false, pending, fmt.Errorf("goauth: verify totp enrollment: %w", err)
	}
	if !totp.Validate(normalizeMFACode(code), secret) {
		return false, pending, nil
	}
	if err := s.ConfirmTOTP(username); err != nil {
		return false, pending, err
	}
	return true, pending, nil
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
		 SET mfa_enabled=0, mfa_type='', totp_secret_enc=NULL, totp_verified_at=NULL, updated_at=?
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

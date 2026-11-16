package goauth

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	webauthnprotocol "github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
)

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (s *UserStore) GetOrCreateWebAuthnUserHandle(username string) ([]byte, error) {
	var (
		id     int64
		handle []byte
	)
	err := s.db.QueryRow(
		`SELECT id, webauthn_user_handle FROM users WHERE username=? COLLATE NOCASE`,
		username,
	).Scan(&id, &handle)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("goauth: get webauthn user handle: %w", err)
	}
	if len(handle) > 0 {
		return handle, nil
	}

	handle, err = randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("goauth: generate webauthn user handle: %w", err)
	}
	if _, err := s.db.Exec(
		`UPDATE users SET webauthn_user_handle=?, updated_at=? WHERE id=?`,
		handle, time.Now().Unix(), id,
	); err != nil {
		return nil, fmt.Errorf("goauth: store webauthn user handle: %w", err)
	}
	return handle, nil
}

// Authenticator flag bits as stored in webauthn_credentials.flags.
const (
	credFlagUserPresent    = 1
	credFlagUserVerified   = 2
	credFlagBackupEligible = 4
	credFlagBackupState    = 8
)

func encodeCredentialFlags(f webauthnlib.CredentialFlags) int64 {
	var v int64
	if f.UserPresent {
		v |= credFlagUserPresent
	}
	if f.UserVerified {
		v |= credFlagUserVerified
	}
	if f.BackupEligible {
		v |= credFlagBackupEligible
	}
	if f.BackupState {
		v |= credFlagBackupState
	}
	return v
}

func decodeCredentialFlags(v int64) webauthnlib.CredentialFlags {
	return webauthnlib.CredentialFlags{
		UserPresent:    v&credFlagUserPresent != 0,
		UserVerified:   v&credFlagUserVerified != 0,
		BackupEligible: v&credFlagBackupEligible != 0,
		BackupState:    v&credFlagBackupState != 0,
	}
}

func (s *UserStore) ListWebAuthnCredentials(username string) ([]webauthnlib.Credential, error) {
	creds, _, err := s.listWebAuthnCredentials(username)
	return creds, err
}

// listWebAuthnCredentials also returns, per credential, whether its
// authenticator flags are on record (false for rows stored before they were).
func (s *UserStore) listWebAuthnCredentials(username string) ([]webauthnlib.Credential, []bool, error) {
	rows, err := s.db.Query(
		`SELECT c.credential_id, c.public_key, c.sign_count, c.transports, c.flags
		 FROM webauthn_credentials c
		 JOIN users u ON u.id = c.user_id
		 WHERE u.username=? COLLATE NOCASE
		 ORDER BY c.id`,
		username,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("goauth: list webauthn credentials: %w", err)
	}
	defer rows.Close()

	var (
		creds      []webauthnlib.Credential
		flagsKnown []bool
	)
	for rows.Next() {
		var (
			cred      webauthnlib.Credential
			signCount int64
			trJSON    string
			flags     sql.NullInt64
		)
		if err := rows.Scan(&cred.ID, &cred.PublicKey, &signCount, &trJSON, &flags); err != nil {
			return nil, nil, fmt.Errorf("goauth: list webauthn credentials: %w", err)
		}
		cred.Authenticator.SignCount = uint32(signCount)
		if flags.Valid {
			cred.Flags = decodeCredentialFlags(flags.Int64)
		}

		var transports []string
		if err := json.Unmarshal([]byte(trJSON), &transports); err == nil {
			cred.Transport = make([]webauthnprotocol.AuthenticatorTransport, 0, len(transports))
			for _, t := range transports {
				cred.Transport = append(cred.Transport, webauthnprotocol.AuthenticatorTransport(t))
			}
		}
		creds = append(creds, cred)
		flagsKnown = append(flagsKnown, flags.Valid)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("goauth: list webauthn credentials: %w", err)
	}
	return creds, flagsKnown, nil
}

func (s *UserStore) UpsertWebAuthnCredential(username string, userHandle []byte, cred *webauthnlib.Credential) error {
	if cred == nil {
		return errors.New("goauth: credential must not be nil")
	}
	var userID int64
	if err := s.db.QueryRow(`SELECT id FROM users WHERE username=? COLLATE NOCASE`, username).Scan(&userID); errors.Is(err, sql.ErrNoRows) {
		return ErrUserNotFound
	} else if err != nil {
		return fmt.Errorf("goauth: upsert webauthn credential: %w", err)
	}
	tr := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		tr = append(tr, string(t))
	}
	trJSON, err := json.Marshal(tr)
	if err != nil {
		return fmt.Errorf("goauth: upsert webauthn credential: %w", err)
	}
	now := time.Now().Unix()
	_, err = s.db.Exec(
		`INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, transports, user_handle, flags, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(user_id, credential_id)
		 DO UPDATE SET public_key=excluded.public_key, sign_count=excluded.sign_count, transports=excluded.transports, user_handle=excluded.user_handle, flags=excluded.flags, updated_at=excluded.updated_at`,
		userID, cred.ID, cred.PublicKey, cred.Authenticator.SignCount, string(trJSON), userHandle, encodeCredentialFlags(cred.Flags), now, now,
	)
	if err != nil {
		return fmt.Errorf("goauth: upsert webauthn credential: %w", err)
	}
	return nil
}

func (s *UserStore) UpdateWebAuthnSignCount(username string, credentialID []byte, signCount uint32) error {
	res, err := s.db.Exec(
		`UPDATE webauthn_credentials
		 SET sign_count=?, updated_at=?
		 WHERE credential_id=?
		   AND user_id=(SELECT id FROM users WHERE username=? COLLATE NOCASE)`,
		signCount, time.Now().Unix(), credentialID, username,
	)
	if err != nil {
		return fmt.Errorf("goauth: update webauthn sign count: %w", err)
	}
	return requireOneRow(res, ErrUserNotFound)
}

// recordWebAuthnLogin stores what a successful assertion reported: the new
// signature counter and the authenticator flags.
func (s *UserStore) recordWebAuthnLogin(username string, cred *webauthnlib.Credential) error {
	res, err := s.db.Exec(
		`UPDATE webauthn_credentials
		 SET sign_count=?, flags=?, updated_at=?
		 WHERE credential_id=?
		   AND user_id=(SELECT id FROM users WHERE username=? COLLATE NOCASE)`,
		cred.Authenticator.SignCount, encodeCredentialFlags(cred.Flags), time.Now().Unix(), cred.ID, username,
	)
	if err != nil {
		return fmt.Errorf("goauth: record webauthn login: %w", err)
	}
	return requireOneRow(res, ErrUserNotFound)
}

func (s *UserStore) SaveWebAuthnChallenge(challengeID, ceremony, username, sessionData string, expiresAt time.Time) error {
	// Abandoned ceremonies were never removed: the login-begin endpoint is
	// unauthenticated and left one row per call, forever.
	if _, err := s.db.Exec(`DELETE FROM webauthn_challenges WHERE expires_at < ?`, time.Now().Unix()); err != nil {
		return fmt.Errorf("goauth: prune webauthn challenges: %w", err)
	}
	_, err := s.db.Exec(
		`INSERT INTO webauthn_challenges (challenge_id, challenge_type, username, session_data, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		challengeID, ceremony, username, sessionData, expiresAt.Unix(), time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("goauth: save webauthn challenge: %w", err)
	}
	return nil
}

func (s *UserStore) ConsumeWebAuthnChallenge(challengeID, ceremony string) (*webAuthnChallengeRecord, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("goauth: consume webauthn challenge: %w", err)
	}
	defer tx.Rollback()

	var (
		username, sessionData string
		expiresAtUnix         int64
	)
	err = tx.QueryRow(
		`SELECT username, session_data, expires_at
		 FROM webauthn_challenges
		 WHERE challenge_id=? AND challenge_type=?`,
		challengeID, ceremony,
	).Scan(&username, &sessionData, &expiresAtUnix)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("goauth: consume webauthn challenge: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM webauthn_challenges WHERE challenge_id=?`, challengeID); err != nil {
		return nil, fmt.Errorf("goauth: consume webauthn challenge: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("goauth: consume webauthn challenge: %w", err)
	}
	var sd webauthnlib.SessionData
	if err := json.Unmarshal([]byte(sessionData), &sd); err != nil {
		return nil, fmt.Errorf("goauth: consume webauthn challenge: decode session: %w", err)
	}
	return &webAuthnChallengeRecord{
		ChallengeID: challengeID,
		Username:    username,
		SessionData: sd,
		ExpiresAt:   time.Unix(expiresAtUnix, 0),
	}, nil
}

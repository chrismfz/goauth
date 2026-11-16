package goauth

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// sqliteSessionStore implements the scs.Store interface using the shared
// SQLite database. Sessions are stored in the `sessions` table.
type sqliteSessionStore struct {
	db *sql.DB
}

func newSQLiteSessionStore(db *sql.DB) *sqliteSessionStore {
	s := &sqliteSessionStore{db: db}
	// Start background cleanup goroutine.
	go s.cleanup(10 * time.Minute)
	return s
}

// hashSessionToken is what the sessions table stores in place of the token.
// The cookie holds the token; the table only its SHA-256, so reading the
// database (a backup, a stray copy, the CLI's session list) no longer yields
// usable sessions. The token is 256 random bits, so a plain hash is enough.
func hashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// hashLegacySessionTokens rewrites rows written before tokens were hashed, so
// an upgrade does not log everyone out. A hash is 64 hex characters and an scs
// token 43, so the length tells them apart and a second run changes nothing.
func hashLegacySessionTokens(db *sql.DB) error {
	rows, err := db.Query(`SELECT token FROM sessions WHERE length(token) <> 64`)
	if err != nil {
		return err
	}
	var tokens []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return err
		}
		tokens = append(tokens, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(tokens) == 0 {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range tokens {
		if _, err := tx.Exec(`UPDATE OR REPLACE sessions SET token=? WHERE token=?`, hashSessionToken(t), t); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Find returns the session data for the given token, if it exists and has not expired.
func (s *sqliteSessionStore) Find(token string) ([]byte, bool, error) {
	var data []byte
	var expiry int64
	err := s.db.QueryRow(
		`SELECT data, expiry FROM sessions WHERE token=?`, hashSessionToken(token),
	).Scan(&data, &expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("goauth/store: find: %w", err)
	}
	if time.Now().Unix() > expiry {
		return nil, false, nil
	}
	return data, true, nil
}

// Commit upserts a session record.
func (s *sqliteSessionStore) Commit(token string, data []byte, expiry time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO sessions (token, data, expiry) VALUES (?, ?, ?)
		 ON CONFLICT(token) DO UPDATE SET data=excluded.data, expiry=excluded.expiry`,
		hashSessionToken(token), data, expiry.Unix(),
	)
	if err != nil {
		return fmt.Errorf("goauth/store: commit: %w", err)
	}
	return nil
}

// Delete removes a session record immediately (used on logout / token rotation).
func (s *sqliteSessionStore) Delete(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token=?`, hashSessionToken(token))
	if err != nil {
		return fmt.Errorf("goauth/store: delete: %w", err)
	}
	return nil
}

// cleanup runs periodically and removes expired session rows.
func (s *sqliteSessionStore) cleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		s.db.Exec(`DELETE FROM sessions WHERE expiry < ?`, time.Now().Unix())
	}
}

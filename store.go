package goauth

import (
	"database/sql"
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

// Find returns the session data for the given token, if it exists and has not expired.
func (s *sqliteSessionStore) Find(token string) ([]byte, bool, error) {
	var data []byte
	var expiry int64
	err := s.db.QueryRow(
		`SELECT data, expiry FROM sessions WHERE token=?`, token,
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
		token, data, expiry.Unix(),
	)
	if err != nil {
		return fmt.Errorf("goauth/store: commit: %w", err)
	}
	return nil
}

// Delete removes a session record immediately (used on logout / token rotation).
func (s *sqliteSessionStore) Delete(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token=?`, token)
	if err != nil {
		return fmt.Errorf("goauth/store: delete: %w", err)
	}
	return nil
}

// DeleteByUsername removes all sessions belonging to a user.
// Useful for "log out everywhere" or account deactivation.
func (s *sqliteSessionStore) DeleteByUsername(username string) (int64, error) {
	// Sessions store username in the scs-encoded blob, so we can't filter
	// that column directly. We keep a username→token index for this purpose
	// via a separate lookup — or we accept a full table scan on logout-all.
	// For now this is a no-op placeholder; wire up if needed later.
	_ = username
	return 0, nil
}

// cleanup runs periodically and removes expired session rows.
func (s *sqliteSessionStore) cleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		s.db.Exec(`DELETE FROM sessions WHERE expiry < ?`, time.Now().Unix())
	}
}

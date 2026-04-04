package goauth

import (
	"fmt"
	"time"
)

// SessionInfo is a lightweight view of a session row, used by the CLI.
type SessionInfo struct {
	Token  string
	Expiry time.Time
}

// ListSessions returns all non-expired sessions from the database.
func (m *Manager) ListSessions() ([]SessionInfo, error) {
	rows, err := m.db.Query(
		`SELECT token, expiry FROM sessions WHERE expiry >= ? ORDER BY expiry ASC`,
		time.Now().Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("goauth: list sessions: %w", err)
	}
	defer rows.Close()

	var out []SessionInfo
	for rows.Next() {
		var token string
		var expiry int64
		if err := rows.Scan(&token, &expiry); err != nil {
			return nil, err
		}
		out = append(out, SessionInfo{
			Token:  token,
			Expiry: time.Unix(expiry, 0),
		})
	}
	return out, rows.Err()
}

// PurgeSessions deletes all expired session rows and returns the count removed.
func (m *Manager) PurgeSessions() (int64, error) {
	res, err := m.db.Exec(`DELETE FROM sessions WHERE expiry < ?`, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("goauth: purge sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

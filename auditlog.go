package goauth

import (
	"database/sql"
	"fmt"
	"time"
)

// LogEvent constants for the auth_log.event column.
const (
	LogEventSuccess   = "SUCCESS"
	LogEventFail      = "FAIL"
	LogEventRateLimit = "RATELIMIT"
)

// LogReason constants for the auth_log.reason column.
const (
	LogReasonBadCredentials  = "bad_credentials"
	LogReasonUserInactive    = "user_inactive"
	LogReasonTooManyIP       = "too_many_attempts_ip"
	LogReasonTooManyUser     = "too_many_attempts_user"
	LogReasonMFARecoveryUsed = "mfa_recovery_code_used"
)

// AuthLogEntry is a single row from the auth_log table.
type AuthLogEntry struct {
	ID       int64
	Time     time.Time
	Event    string
	Username string
	IP       string
	Reason   string
}

// auditLog writes a single event row to the auth_log table.
// Non-blocking — failures are logged to stderr but never propagated to the caller.
func auditLog(db *sql.DB, event, username, ip, reason string) {
	if db == nil {
		return
	}
	_, err := db.Exec(
		`INSERT INTO auth_log (ts, event, username, ip, reason) VALUES (?, ?, ?, ?, ?)`,
		time.Now().Unix(), event, username, ip, reason,
	)
	if err != nil {
		// Don't block login flow over an audit write failure.
		fmt.Printf("goauth/audit: write failed: %v\n", err)
	}
}

// QueryAuthLog returns recent auth log entries, newest first.
// limit caps the number of rows returned (0 = default 100).
func (m *Manager) QueryAuthLog(limit int) ([]AuthLogEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := m.db.Query(
		`SELECT id, ts, event, username, ip, reason
		 FROM auth_log ORDER BY ts DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("goauth: query auth_log: %w", err)
	}
	defer rows.Close()

	var out []AuthLogEntry
	for rows.Next() {
		var e AuthLogEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Event, &e.Username, &e.IP, &e.Reason); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// QueryAuthLogByIP returns recent auth log entries for a specific IP.
func (m *Manager) QueryAuthLogByIP(ip string, limit int) ([]AuthLogEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := m.db.Query(
		`SELECT id, ts, event, username, ip, reason
		 FROM auth_log WHERE ip=? ORDER BY ts DESC LIMIT ?`,
		ip, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("goauth: query auth_log by ip: %w", err)
	}
	defer rows.Close()

	var out []AuthLogEntry
	for rows.Next() {
		var e AuthLogEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Event, &e.Username, &e.IP, &e.Reason); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PurgeAuthLog deletes auth log entries older than the given duration.
// Returns the number of rows deleted.
func (m *Manager) PurgeAuthLog(olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan).Unix()
	res, err := m.db.Exec(`DELETE FROM auth_log WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("goauth: purge auth_log: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

package goauth

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// LogEvent constants for the auth_log.event column.
const (
	LogEventSuccess           = "SUCCESS"
	LogEventFail              = "FAIL"
	LogEventRateLimit         = "RATELIMIT"
	LogEventMFAEnableInit     = "MFA_ENABLE_INIT"
	LogEventMFAEnableConfirm  = "MFA_ENABLE_CONFIRM"
	LogEventMFADisable        = "MFA_DISABLE"
	LogEventMFAReset          = "MFA_RESET"
	LogEventMFARecoveryRotate = "MFA_RECOVERY_ROTATE"
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
	Actor    string
	Target   string
	Host     string
	Ticket   string
}

// AdminAuditContext is metadata captured for admin-initiated MFA operations.
type AdminAuditContext struct {
	Actor  string
	Target string
	IP     string
	Host   string
	Reason string
	Ticket string
}

// MFAAdminQueryFilter filters MFA admin events in auth_log.
type MFAAdminQueryFilter struct {
	Actor  string
	Target string
	Host   string
	IP     string
	Limit  int
}

// auditLog writes a single event row to the auth_log table.
// Non-blocking — failures are logged to stderr but never propagated to the caller.
func auditLog(db *sql.DB, event, username, ip, reason string) {
	auditLogWithContext(db, event, username, ip, reason, "", "", "", "")
}

func auditLogWithContext(db *sql.DB, event, username, ip, reason, actor, target, host, ticket string) {
	if db == nil {
		return
	}
	_, err := db.Exec(
		`INSERT INTO auth_log (ts, event, username, ip, reason, actor, target, host, ticket)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now().Unix(),
		normalizeAuditValue(event),
		normalizeAuditValue(username),
		normalizeAuditValue(ip),
		normalizeAuditValue(reason),
		normalizeAuditValue(actor),
		normalizeAuditValue(target),
		normalizeAuditValue(host),
		normalizeAuditValue(ticket),
	)
	if err != nil {
		// Don't block login flow over an audit write failure.
		fmt.Printf("goauth/audit: write failed: %v\n", err)
	}
}

func normalizeAuditValue(v string) string {
	return strings.TrimSpace(v)
}

// AuditMFAAdminEvent writes an MFA admin event row into auth_log.
func (m *Manager) AuditMFAAdminEvent(event string, ctx AdminAuditContext) {
	auditLogWithContext(
		m.db,
		event,
		ctx.Target,
		ctx.IP,
		ctx.Reason,
		ctx.Actor,
		ctx.Target,
		ctx.Host,
		ctx.Ticket,
	)
}

// QueryAuthLog returns recent auth log entries, newest first.
// limit caps the number of rows returned (0 = default 100).
func (m *Manager) QueryAuthLog(limit int) ([]AuthLogEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := m.db.Query(
		`SELECT id, ts, event, username, ip, reason, actor, target, host, ticket
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
		if err := rows.Scan(&e.ID, &ts, &e.Event, &e.Username, &e.IP, &e.Reason, &e.Actor, &e.Target, &e.Host, &e.Ticket); err != nil {
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
		`SELECT id, ts, event, username, ip, reason, actor, target, host, ticket
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
		if err := rows.Scan(&e.ID, &ts, &e.Event, &e.Username, &e.IP, &e.Reason, &e.Actor, &e.Target, &e.Host, &e.Ticket); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// QueryAuthLogMFAAdmin returns MFA administration events with optional actor/target filters.
func (m *Manager) QueryAuthLogMFAAdmin(filter MFAAdminQueryFilter) ([]AuthLogEntry, error) {
	if filter.Limit <= 0 {
		filter.Limit = 100
	}
	rows, err := m.db.Query(
		`SELECT id, ts, event, username, ip, reason, actor, target, host, ticket
		 FROM auth_log
		 WHERE event IN (?, ?, ?, ?, ?)
		   AND (?='' OR actor=? COLLATE NOCASE)
		   AND (?='' OR target=? COLLATE NOCASE)
		   AND (?='' OR host=? COLLATE NOCASE)
		   AND (?='' OR ip=?)
		 ORDER BY ts DESC LIMIT ?`,
		LogEventMFAEnableInit,
		LogEventMFAEnableConfirm,
		LogEventMFADisable,
		LogEventMFAReset,
		LogEventMFARecoveryRotate,
		filter.Actor, filter.Actor,
		filter.Target, filter.Target,
		filter.Host, filter.Host,
		filter.IP, filter.IP,
		filter.Limit,
	)
	if err != nil {
		return nil, fmt.Errorf("goauth: query auth_log mfa admin: %w", err)
	}
	defer rows.Close()

	var out []AuthLogEntry
	for rows.Next() {
		var e AuthLogEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Event, &e.Username, &e.IP, &e.Reason, &e.Actor, &e.Target, &e.Host, &e.Ticket); err != nil {
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

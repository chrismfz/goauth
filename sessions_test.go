package goauth

import (
	"path/filepath"
	"testing"
	"time"
)

func TestListAndPurgeSessionsUseSessionDBPath(t *testing.T) {
	tmp := t.TempDir()
	authDBPath := filepath.Join(tmp, "auth.db")
	sessionDBPath := filepath.Join(tmp, "sessions.db")

	m, err := New(Config{
		DBPath:           authDBPath,
		SessionDBPath:    sessionDBPath,
		MFAEncryptionKey: "0123456789abcdef",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer m.Close()

	if _, err := m.db.Query(`SELECT token FROM sessions`); err == nil {
		t.Fatal("auth DB unexpectedly has a sessions table")
	}

	now := time.Now()
	activeExpiry := now.Add(time.Hour).Unix()
	expiredExpiry := now.Add(-time.Hour).Unix()
	if _, err := m.sessionDB.Exec(
		`INSERT INTO sessions (token, data, expiry) VALUES (?, ?, ?), (?, ?, ?)`,
		"active-token", []byte("active-data"), activeExpiry,
		"expired-token", []byte("expired-data"), expiredExpiry,
	); err != nil {
		t.Fatalf("insert sessions into session DB: %v", err)
	}

	sessions, err := m.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions() error = %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("ListSessions() returned %d sessions, want 1: %#v", len(sessions), sessions)
	}
	if sessions[0].Token != "active-token" {
		t.Fatalf("ListSessions() token = %q, want active-token", sessions[0].Token)
	}
	if got := sessions[0].Expiry.Unix(); got != activeExpiry {
		t.Fatalf("ListSessions() expiry = %d, want %d", got, activeExpiry)
	}

	purged, err := m.PurgeSessions()
	if err != nil {
		t.Fatalf("PurgeSessions() error = %v", err)
	}
	if purged != 1 {
		t.Fatalf("PurgeSessions() deleted %d rows, want 1", purged)
	}

	var remaining int
	if err := m.sessionDB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token = ?`, "expired-token").Scan(&remaining); err != nil {
		t.Fatalf("count expired sessions in session DB: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expired sessions remaining in session DB = %d, want 0", remaining)
	}
	if err := m.sessionDB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE token = ?`, "active-token").Scan(&remaining); err != nil {
		t.Fatalf("count active sessions in session DB: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("active sessions remaining in session DB = %d, want 1", remaining)
	}
}

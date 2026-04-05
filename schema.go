package goauth

import "database/sql"

// runMigrations applies the schema idempotently. Extend this list for future
// schema changes — do NOT modify existing statements.
func runMigrations(db *sql.DB) error {
	if err := runAuthMigrations(db); err != nil {
		return err
	}
	return runSessionMigrations(db)
}

func runAuthMigrations(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			username     TEXT    NOT NULL UNIQUE COLLATE NOCASE,
			password_hash TEXT   NOT NULL,
			roles        TEXT    NOT NULL DEFAULT '[]',
			active       INTEGER NOT NULL DEFAULT 1,
			created_at   INTEGER NOT NULL,
			updated_at   INTEGER NOT NULL
		)`,

		// Auth audit log — records every login attempt and rate-limit hit.
		`CREATE TABLE IF NOT EXISTS auth_log (
			id       INTEGER PRIMARY KEY AUTOINCREMENT,
			ts       INTEGER NOT NULL,
			event    TEXT    NOT NULL,
			username TEXT    NOT NULL DEFAULT '',
			ip       TEXT    NOT NULL DEFAULT '',
			reason   TEXT    NOT NULL DEFAULT ''
		)`,

		`CREATE INDEX IF NOT EXISTS auth_log_ts_idx ON auth_log(ts)`,
		`CREATE INDEX IF NOT EXISTS auth_log_ip_idx ON auth_log(ip)`,
	}

	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

func runSessionMigrations(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS sessions (
			token      TEXT    PRIMARY KEY,
			data       BLOB    NOT NULL,
			expiry     INTEGER NOT NULL
		)`,

		`CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expiry)`,
	}

	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

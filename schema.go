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

	additiveStmts := []string{
		`ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN mfa_type TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN totp_secret_enc TEXT`,
		`ALTER TABLE users ADD COLUMN totp_verified_at INTEGER`,
		`ALTER TABLE users ADD COLUMN webauthn_user_handle BLOB`,
		`CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id    INTEGER NOT NULL,
			code_hash  TEXT    NOT NULL,
			created_at INTEGER NOT NULL,
			UNIQUE(user_id, code_hash),
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS mfa_recovery_codes_user_id_idx ON mfa_recovery_codes(user_id)`,
		`CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id       INTEGER NOT NULL,
			credential_id BLOB    NOT NULL,
			public_key    BLOB    NOT NULL,
			sign_count    INTEGER NOT NULL DEFAULT 0,
			transports    TEXT    NOT NULL DEFAULT '[]',
			user_handle   BLOB    NOT NULL,
			created_at    INTEGER NOT NULL,
			updated_at    INTEGER NOT NULL,
			UNIQUE(user_id, credential_id),
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS webauthn_credentials_credential_id_idx ON webauthn_credentials(credential_id)`,
		`CREATE INDEX IF NOT EXISTS webauthn_credentials_user_id_idx ON webauthn_credentials(user_id)`,
		`CREATE TABLE IF NOT EXISTS webauthn_challenges (
			challenge_id   TEXT PRIMARY KEY,
			challenge_type TEXT NOT NULL,
			username       TEXT NOT NULL DEFAULT '',
			session_data   TEXT NOT NULL,
			expires_at     INTEGER NOT NULL,
			created_at     INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS webauthn_challenges_expires_idx ON webauthn_challenges(expires_at)`,
	}

	for _, s := range additiveStmts {
		if _, err := db.Exec(s); err != nil && !isDuplicateColumnErr(err) {
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

func isDuplicateColumnErr(err error) bool {
	if err == nil {
		return false
	}
	return containsAny(err.Error(), "duplicate column name")
}

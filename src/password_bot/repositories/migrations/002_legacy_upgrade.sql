-- Run inside a single transaction by the migrator.
-- Users table: rename + add columns.
ALTER TABLE users RENAME COLUMN salted_hash TO passphrase_hash;
ALTER TABLE users ADD COLUMN autolock_minutes INTEGER NOT NULL DEFAULT 15;
ALTER TABLE users ADD COLUMN autolock_reset_on_activity INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN alert_days INTEGER NOT NULL DEFAULT 180;
ALTER TABLE users ADD COLUMN crypto_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN legacy_salt TEXT;
ALTER TABLE users ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
UPDATE users SET legacy_salt = salt WHERE legacy_salt IS NULL;
ALTER TABLE users DROP COLUMN salt;

-- Accounts table: add new columns.
ALTER TABLE accounts ADD COLUMN url_enc TEXT;
ALTER TABLE accounts ADD COLUMN note_enc TEXT;
ALTER TABLE accounts ADD COLUMN category_id TEXT REFERENCES categories(id) ON DELETE SET NULL;
ALTER TABLE accounts ADD COLUMN password_hmac TEXT NOT NULL DEFAULT '';
ALTER TABLE accounts ADD COLUMN crypto_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE accounts ADD COLUMN password_changed_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE accounts ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
-- Rename legacy `username` column to `username_enc` (already base64-CFB ciphertext).
ALTER TABLE accounts RENAME COLUMN username TO username_enc;
ALTER TABLE accounts RENAME COLUMN password TO password_enc;

CREATE INDEX IF NOT EXISTS idx_accounts_chat ON accounts(chat_id);
CREATE INDEX IF NOT EXISTS idx_accounts_name ON accounts(chat_id, name);
CREATE INDEX IF NOT EXISTS idx_accounts_category ON accounts(category_id);

CREATE TABLE IF NOT EXISTS categories (
    id        TEXT PRIMARY KEY,
    chat_id   INTEGER NOT NULL REFERENCES users(chat_id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    color     TEXT,
    UNIQUE(chat_id, name)
);

CREATE TABLE IF NOT EXISTS password_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    password_enc    TEXT NOT NULL,
    crypto_version  INTEGER NOT NULL DEFAULT 2,
    replaced_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_history_account ON password_history(account_id, replaced_at);

CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);
INSERT OR REPLACE INTO schema_version (version) VALUES (1);

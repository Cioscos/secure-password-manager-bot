CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);

CREATE TABLE IF NOT EXISTS users (
    chat_id                       INTEGER PRIMARY KEY,
    name                          TEXT NOT NULL,
    passphrase_hash               TEXT NOT NULL,
    autolock_minutes              INTEGER NOT NULL DEFAULT 15,
    autolock_reset_on_activity    INTEGER NOT NULL DEFAULT 1,
    alert_days                    INTEGER NOT NULL DEFAULT 180,
    crypto_version                INTEGER NOT NULL DEFAULT 2,
    legacy_salt                   TEXT,
    created_at                    INTEGER NOT NULL,
    updated_at                    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS categories (
    id        TEXT PRIMARY KEY,
    chat_id   INTEGER NOT NULL REFERENCES users(chat_id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    color     TEXT,
    UNIQUE(chat_id, name)
);

CREATE TABLE IF NOT EXISTS accounts (
    id                   TEXT PRIMARY KEY,
    chat_id              INTEGER NOT NULL REFERENCES users(chat_id) ON DELETE CASCADE,
    name                 TEXT NOT NULL,
    username_enc         TEXT,
    password_enc         TEXT NOT NULL,
    url_enc              TEXT,
    note_enc             TEXT,
    category_id          TEXT REFERENCES categories(id) ON DELETE SET NULL,
    password_hmac        TEXT NOT NULL DEFAULT '',
    crypto_version       INTEGER NOT NULL DEFAULT 2,
    password_changed_at  INTEGER NOT NULL,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_accounts_chat ON accounts(chat_id);
CREATE INDEX IF NOT EXISTS idx_accounts_name ON accounts(chat_id, name);
CREATE INDEX IF NOT EXISTS idx_accounts_category ON accounts(category_id);

CREATE TABLE IF NOT EXISTS password_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id      TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    password_enc    TEXT NOT NULL,
    crypto_version  INTEGER NOT NULL DEFAULT 2,
    replaced_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_history_account ON password_history(account_id, replaced_at);

-- Legacy v1 → v2 upgrade. SQLite has no ALTER COLUMN, so we rebuild the two
-- legacy tables (`users`, `accounts`) with the exact v2 schema (matches
-- 001_init.sql) and copy data across. PRAGMA foreign_keys is OFF for the whole
-- script (set by the migrator) so the rebuild order does not violate FKs.

BEGIN;

-- --- users -----------------------------------------------------------------
CREATE TABLE users_new (
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

INSERT INTO users_new (
    chat_id, name, passphrase_hash, autolock_minutes, autolock_reset_on_activity,
    alert_days, crypto_version, legacy_salt, created_at, updated_at
)
SELECT
    chat_id,
    name,
    salted_hash,
    15, 1, 180,
    1,
    salt,
    0, 0
FROM users;

DROP TABLE users;
ALTER TABLE users_new RENAME TO users;

-- --- accounts --------------------------------------------------------------
-- Categories must exist first because accounts.category_id references it.
CREATE TABLE IF NOT EXISTS categories (
    id        TEXT PRIMARY KEY,
    chat_id   INTEGER NOT NULL REFERENCES users(chat_id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    color     TEXT,
    UNIQUE(chat_id, name)
);

CREATE TABLE accounts_new (
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

INSERT INTO accounts_new (
    id, chat_id, name, username_enc, password_enc, url_enc, note_enc,
    category_id, password_hmac, crypto_version, password_changed_at,
    created_at, updated_at
)
SELECT
    id,
    chat_id,
    name,
    username,
    password,
    NULL, NULL, NULL,
    '',
    1,
    0, 0, 0
FROM accounts;

DROP TABLE accounts;
ALTER TABLE accounts_new RENAME TO accounts;

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

COMMIT;

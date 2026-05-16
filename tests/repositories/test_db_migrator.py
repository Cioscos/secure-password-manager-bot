import sqlite3
from pathlib import Path

import pytest

from password_bot.repositories.migrator import migrate_to_latest


@pytest.mark.asyncio
async def test_migrate_fresh_db(tmp_db_path: Path):
    await migrate_to_latest(tmp_db_path)
    with sqlite3.connect(tmp_db_path) as conn:
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
    assert {"users", "accounts", "categories", "password_history", "schema_version"} <= tables
    assert version == 1


def _create_legacy_db(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE users (
                chat_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                salted_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            );
            CREATE TABLE accounts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                username TEXT,
                password TEXT NOT NULL,
                chat_id INTEGER NOT NULL REFERENCES users(chat_id)
            );
            INSERT INTO users VALUES (42, 'me', 'deadbeef', 'cafebabe');
            INSERT INTO accounts VALUES ('a1', 'GitHub', 'u_enc', 'p_enc', 42);
        """)


@pytest.mark.asyncio
async def test_migrate_legacy_db(tmp_db_path: Path):
    _create_legacy_db(tmp_db_path)
    await migrate_to_latest(tmp_db_path)
    with sqlite3.connect(tmp_db_path) as conn:
        u = conn.execute(
            "SELECT passphrase_hash, legacy_salt, crypto_version, "
            "autolock_minutes FROM users WHERE chat_id=42"
        ).fetchone()
        a = conn.execute(
            "SELECT username_enc, password_enc, password_hmac, crypto_version "
            "FROM accounts WHERE id='a1'"
        ).fetchone()
        version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
    assert u == ("deadbeef", "cafebabe", 1, 15)
    assert a == ("u_enc", "p_enc", "", 1)
    assert version == 1


@pytest.mark.asyncio
async def test_migrate_idempotent(tmp_db_path: Path):
    await migrate_to_latest(tmp_db_path)
    await migrate_to_latest(tmp_db_path)
    with sqlite3.connect(tmp_db_path) as conn:
        version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
    assert version == 1

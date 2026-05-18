import sqlite3
from pathlib import Path

import pytest

from password_bot.repositories.migrator import migrate_to_latest


def _columns(conn: sqlite3.Connection, table: str) -> dict[str, tuple]:
    """Return {column_name: (type, notnull, dflt_value, pk)} for a table."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return {r[1]: (r[2].upper(), r[3], r[4], r[5]) for r in rows}


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
    assert version == 2


def _create_legacy_db(path: Path) -> None:
    """Seed a v1 DB matching the real `master` branch schema exactly.

    Mirrors `master:src/account_repository.py:create_database`.
    """
    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE accounts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                chat_id  INTEGER,
                FOREIGN KEY (chat_id) REFERENCES users(chat_id),
                UNIQUE (id, name)
            );
            CREATE TABLE users (
                chat_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                salted_hash TEXT,
                salt TEXT
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
    assert version == 2


@pytest.mark.asyncio
async def test_migrated_schema_matches_fresh(tmp_db_path: Path, tmp_path: Path):
    """Migrated DB must have identical column definitions to a freshly initialized DB."""
    _create_legacy_db(tmp_db_path)
    await migrate_to_latest(tmp_db_path)

    fresh_path = tmp_path / "fresh.db"
    await migrate_to_latest(fresh_path)

    with sqlite3.connect(tmp_db_path) as migrated, sqlite3.connect(fresh_path) as fresh:
        for table in ("users", "accounts", "categories", "password_history"):
            mig_cols = _columns(migrated, table)
            fresh_cols = _columns(fresh, table)
            assert mig_cols == fresh_cols, (
                f"Schema drift in `{table}`: migrated={mig_cols!r}  fresh={fresh_cols!r}"
            )


@pytest.mark.asyncio
async def test_migrate_idempotent(tmp_db_path: Path):
    await migrate_to_latest(tmp_db_path)
    await migrate_to_latest(tmp_db_path)
    with sqlite3.connect(tmp_db_path) as conn:
        version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
    assert version == 2


@pytest.mark.asyncio
async def test_pw_prefs_column_exists(tmp_db_path: Path):
    await migrate_to_latest(tmp_db_path)
    with sqlite3.connect(tmp_db_path) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    assert "pw_prefs" in cols


@pytest.mark.asyncio
async def test_migrate_v1_to_v2(tmp_db_path: Path):
    # simulate db at v1 (no pw_prefs column)
    with sqlite3.connect(tmp_db_path) as conn:
        conn.executescript("""
            CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
            INSERT INTO schema_version (version) VALUES (1);
            CREATE TABLE users (
                chat_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                passphrase_hash TEXT NOT NULL,
                autolock_minutes INTEGER NOT NULL DEFAULT 15,
                autolock_reset_on_activity INTEGER NOT NULL DEFAULT 1,
                alert_days INTEGER NOT NULL DEFAULT 180,
                crypto_version INTEGER NOT NULL DEFAULT 2,
                legacy_salt TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
        """)
    await migrate_to_latest(tmp_db_path)
    with sqlite3.connect(tmp_db_path) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
    assert "pw_prefs" in cols
    assert version == 2

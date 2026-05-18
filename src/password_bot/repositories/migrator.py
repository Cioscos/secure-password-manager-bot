"""Schema migrator. Detects legacy v0 schema and upgrades step-by-step to TARGET_VERSION."""

from __future__ import annotations

from pathlib import Path

import aiosqlite

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
TARGET_VERSION = 2


async def _table_exists(conn: aiosqlite.Connection, name: str) -> bool:
    cur = await conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return await cur.fetchone() is not None


async def _column_exists(conn: aiosqlite.Connection, table: str, column: str) -> bool:
    cur = await conn.execute(f"PRAGMA table_info({table})")
    rows = await cur.fetchall()
    return any(r[1] == column for r in rows)


async def _current_version(conn: aiosqlite.Connection) -> int:
    if not await _table_exists(conn, "schema_version"):
        return 0
    cur = await conn.execute("SELECT version FROM schema_version")
    row = await cur.fetchone()
    return row[0] if row else 0


async def _is_legacy(conn: aiosqlite.Connection) -> bool:
    return await _table_exists(conn, "users") and await _column_exists(conn, "users", "salted_hash")


async def _set_version(conn: aiosqlite.Connection, version: int) -> None:
    if not await _table_exists(conn, "schema_version"):
        await conn.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY)")
    await conn.execute("DELETE FROM schema_version")
    await conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))


async def migrate_to_latest(db_path: Path) -> None:
    conn = await aiosqlite.connect(db_path)
    try:
        await conn.execute("PRAGMA foreign_keys = OFF")
        version = await _current_version(conn)
        if version >= TARGET_VERSION:
            return

        if version < 1:
            if await _is_legacy(conn):
                sql = (MIGRATIONS_DIR / "002_legacy_upgrade.sql").read_text()
            else:
                sql = (MIGRATIONS_DIR / "001_init.sql").read_text()
            await conn.executescript(sql)
            await _set_version(conn, 1)
            version = 1

        if version < 2:
            if not await _column_exists(conn, "users", "pw_prefs"):
                sql = (MIGRATIONS_DIR / "003_user_pw_prefs.sql").read_text()
                await conn.executescript(sql)
            await _set_version(conn, 2)

        await conn.commit()
    finally:
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.close()

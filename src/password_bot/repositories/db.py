"""aiosqlite connection helper."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite


@asynccontextmanager
async def connect(db_path: Path) -> AsyncIterator[aiosqlite.Connection]:
    conn = await aiosqlite.connect(db_path)
    try:
        await conn.execute("PRAGMA foreign_keys = ON")
        conn.row_factory = aiosqlite.Row
        yield conn
        await conn.commit()
    finally:
        await conn.close()

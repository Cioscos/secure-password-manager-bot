"""Password history CRUD with retention pruning."""

from __future__ import annotations

from pathlib import Path

import aiosqlite

from password_bot.models.password_history import PasswordHistoryEntry
from password_bot.repositories.db import connect


def _row_to_entry(row: aiosqlite.Row) -> PasswordHistoryEntry:
    return PasswordHistoryEntry(
        id=row["id"],
        account_id=row["account_id"],
        password_enc=row["password_enc"],
        crypto_version=row["crypto_version"],
        replaced_at=row["replaced_at"],
    )


class HistoryRepo:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    async def push(
        self, account_id: str, *, password_enc: str, crypto_version: int, replaced_at: int
    ) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                """
                INSERT INTO password_history (account_id, password_enc, crypto_version, replaced_at)
                VALUES (?, ?, ?, ?)
                """,
                (account_id, password_enc, crypto_version, replaced_at),
            )

    async def list_for_account(self, account_id: str) -> list[PasswordHistoryEntry]:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                """
                SELECT * FROM password_history
                 WHERE account_id=? ORDER BY replaced_at DESC, id DESC
                """,
                (account_id,),
            )
            return [_row_to_entry(r) for r in await cur.fetchall()]

    async def prune(self, account_id: str, *, keep: int) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                """
                DELETE FROM password_history
                 WHERE account_id=? AND id NOT IN (
                     SELECT id FROM password_history
                      WHERE account_id=?
                      ORDER BY replaced_at DESC, id DESC LIMIT ?
                 )
                """,
                (account_id, account_id, keep),
            )

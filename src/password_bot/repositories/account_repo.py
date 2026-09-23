"""Account CRUD + fuzzy search + stale-password query."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import aiosqlite
from thefuzz import fuzz

from password_bot.models.account import AccountRow
from password_bot.repositories.db import connect


def _row_to_account_row(row: aiosqlite.Row) -> AccountRow:
    return AccountRow(
        id=row["id"],
        chat_id=row["chat_id"],
        name=row["name"],
        username_enc=row["username_enc"],
        password_enc=row["password_enc"],
        url_enc=row["url_enc"],
        note_enc=row["note_enc"],
        category_id=row["category_id"],
        password_hmac=row["password_hmac"],
        crypto_version=row["crypto_version"],
        password_changed_at=row["password_changed_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


_ALLOWED_UPDATE_FIELDS = {"username_enc", "url_enc", "note_enc", "category_id", "name"}


class AccountRepo:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    async def insert(self, row: AccountRow) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                """
                INSERT INTO accounts (id, chat_id, name, username_enc, password_enc,
                                      url_enc, note_enc, category_id, password_hmac,
                                      crypto_version, password_changed_at,
                                      created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row.id,
                    row.chat_id,
                    row.name,
                    row.username_enc,
                    row.password_enc,
                    row.url_enc,
                    row.note_enc,
                    row.category_id,
                    row.password_hmac,
                    row.crypto_version,
                    row.password_changed_at,
                    row.created_at,
                    row.updated_at,
                ),
            )

    async def get(self, account_id: str) -> AccountRow | None:
        async with connect(self._db_path) as conn:
            cur = await conn.execute("SELECT * FROM accounts WHERE id=?", (account_id,))
            row = await cur.fetchone()
            return _row_to_account_row(row) if row else None

    async def list_for_chat(self, chat_id: int) -> list[AccountRow]:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM accounts WHERE chat_id=? ORDER BY name COLLATE NOCASE",
                (chat_id,),
            )
            return [_row_to_account_row(r) for r in await cur.fetchall()]

    async def update_fields(self, account_id: str, **fields: Any) -> None:
        bad = set(fields) - _ALLOWED_UPDATE_FIELDS
        if bad:
            raise ValueError(f"Cannot update fields via update_fields: {bad}")
        if not fields:
            return
        assignments = ", ".join(f"{k}=?" for k in fields)
        params = [*fields.values(), int(time.time()), account_id]
        async with connect(self._db_path) as conn:
            await conn.execute(
                f"UPDATE accounts SET {assignments}, updated_at=? WHERE id=?",
                params,
            )

    async def update_password(
        self,
        account_id: str,
        *,
        password_enc: str,
        password_hmac: str,
        crypto_version: int,
        password_changed_at: int,
    ) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                """
                UPDATE accounts
                   SET password_enc=?, password_hmac=?, crypto_version=?,
                       password_changed_at=?, updated_at=?
                 WHERE id=?
                """,
                (
                    password_enc,
                    password_hmac,
                    crypto_version,
                    password_changed_at,
                    int(time.time()),
                    account_id,
                ),
            )

    async def delete(self, account_id: str) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute("DELETE FROM accounts WHERE id=?", (account_id,))

    async def search(
        self, chat_id: int, query: str, *, threshold: int = 60
    ) -> list[tuple[AccountRow, int]]:
        rows = await self.list_for_chat(chat_id)
        scored: list[tuple[AccountRow, int]] = []
        for r in rows:
            score = fuzz.partial_ratio(query.lower(), r.name.lower())
            if score >= threshold:
                scored.append((r, score))
        scored.sort(key=lambda t: t[1], reverse=True)
        return scored

    async def list_reuse_clusters(self, chat_id: int) -> list[list[AccountRow]]:
        """Groups of 2+ accounts sharing a password (same HMAC). Legacy rows have no HMAC."""
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                """
                SELECT * FROM accounts
                 WHERE chat_id=? AND password_hmac != ''
                   AND password_hmac IN (
                       SELECT password_hmac FROM accounts
                        WHERE chat_id=? AND password_hmac != ''
                        GROUP BY password_hmac HAVING COUNT(*) >= 2
                   )
                 ORDER BY password_hmac, name COLLATE NOCASE
                """,
                (chat_id, chat_id),
            )
            rows = [_row_to_account_row(r) for r in await cur.fetchall()]
        clusters: dict[str, list[AccountRow]] = {}
        for r in rows:
            clusters.setdefault(r.password_hmac, []).append(r)
        return list(clusters.values())

    async def list_stale(self, chat_id: int, *, older_than_epoch: int) -> list[AccountRow]:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM accounts WHERE chat_id=? AND password_changed_at < ?",
                (chat_id, older_than_epoch),
            )
            return [_row_to_account_row(r) for r in await cur.fetchall()]

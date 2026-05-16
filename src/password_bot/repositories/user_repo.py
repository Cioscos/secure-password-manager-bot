"""User CRUD."""

from __future__ import annotations

import time
from pathlib import Path

import aiosqlite

from password_bot.models.pw_prefs import PwPrefs
from password_bot.models.user import User
from password_bot.repositories.db import connect


def _row_to_user(row: aiosqlite.Row) -> User:
    return User(
        chat_id=row["chat_id"],
        name=row["name"],
        passphrase_hash=row["passphrase_hash"],
        autolock_minutes=row["autolock_minutes"],
        autolock_reset_on_activity=bool(row["autolock_reset_on_activity"]),
        alert_days=row["alert_days"],
        crypto_version=row["crypto_version"],
        legacy_salt=row["legacy_salt"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class UserRepo:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    async def get(self, chat_id: int) -> User | None:
        async with connect(self._db_path) as conn:
            cur = await conn.execute("SELECT * FROM users WHERE chat_id=?", (chat_id,))
            row = await cur.fetchone()
            return _row_to_user(row) if row else None

    async def create(self, user: User) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                """
                INSERT INTO users (chat_id, name, passphrase_hash, autolock_minutes,
                                   autolock_reset_on_activity, alert_days, crypto_version,
                                   legacy_salt, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user.chat_id,
                    user.name,
                    user.passphrase_hash,
                    user.autolock_minutes,
                    int(user.autolock_reset_on_activity),
                    user.alert_days,
                    user.crypto_version,
                    user.legacy_salt,
                    user.created_at,
                    user.updated_at,
                ),
            )

    async def update_passphrase(self, chat_id: int, new_hash: str, *, crypto_version: int) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                """
                UPDATE users
                   SET passphrase_hash=?, crypto_version=?, legacy_salt=NULL, updated_at=?
                 WHERE chat_id=?
                """,
                (new_hash, crypto_version, int(time.time()), chat_id),
            )

    async def update_autolock(self, chat_id: int, *, minutes: int, reset_on_activity: bool) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                """
                UPDATE users
                   SET autolock_minutes=?, autolock_reset_on_activity=?, updated_at=?
                 WHERE chat_id=?
                """,
                (minutes, int(reset_on_activity), int(time.time()), chat_id),
            )

    async def update_alert_days(self, chat_id: int, days: int) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                "UPDATE users SET alert_days=?, updated_at=? WHERE chat_id=?",
                (days, int(time.time()), chat_id),
            )

    async def get_pw_prefs(self, chat_id: int) -> PwPrefs:
        async with connect(self._db_path) as conn:
            cur = await conn.execute("SELECT pw_prefs FROM users WHERE chat_id=?", (chat_id,))
            row = await cur.fetchone()
            if row is None:
                return PwPrefs()
            return PwPrefs.from_json(row["pw_prefs"])

    async def set_pw_prefs(self, chat_id: int, prefs: PwPrefs) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                "UPDATE users SET pw_prefs=?, updated_at=? WHERE chat_id=?",
                (prefs.to_json(), int(time.time()), chat_id),
            )

"""Category CRUD."""

from __future__ import annotations

from pathlib import Path

import aiosqlite

from password_bot.models.category import Category
from password_bot.repositories.db import connect


def _row_to_category(row: aiosqlite.Row) -> Category:
    return Category(id=row["id"], chat_id=row["chat_id"], name=row["name"], icon=row["color"])


class CategoryRepo:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    async def create(self, cat: Category) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                "INSERT INTO categories (id, chat_id, name, color) VALUES (?, ?, ?, ?)",
                (cat.id, cat.chat_id, cat.name, cat.icon),
            )

    async def get(self, cat_id: str) -> Category | None:
        async with connect(self._db_path) as conn:
            cur = await conn.execute("SELECT * FROM categories WHERE id=?", (cat_id,))
            row = await cur.fetchone()
            return _row_to_category(row) if row else None

    async def get_by_name(self, chat_id: int, name: str) -> Category | None:
        key = name.casefold()
        return next(
            (cat for cat in await self.list_for_chat(chat_id) if cat.name.casefold() == key),
            None,
        )

    async def list_for_chat(self, chat_id: int) -> list[Category]:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM categories WHERE chat_id=? ORDER BY name COLLATE NOCASE",
                (chat_id,),
            )
            return [_row_to_category(r) for r in await cur.fetchall()]

    async def rename(self, cat_id: str, new_name: str) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute("UPDATE categories SET name=? WHERE id=?", (new_name, cat_id))

    async def delete(self, cat_id: str) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute("DELETE FROM categories WHERE id=?", (cat_id,))

    async def set_icon(self, cat_id: str, icon: str | None) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute("UPDATE categories SET color=? WHERE id=?", (icon, cat_id))

    async def list_with_counts(self, chat_id: int) -> list[tuple[Category, int]]:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                """
                SELECT c.*, COUNT(a.id) AS n
                  FROM categories c
                  LEFT JOIN accounts a ON a.category_id = c.id AND a.chat_id = c.chat_id
                 WHERE c.chat_id=?
                 GROUP BY c.id
                 ORDER BY c.name COLLATE NOCASE
                """,
                (chat_id,),
            )
            return [(_row_to_category(r), r["n"]) for r in await cur.fetchall()]

    async def count_uncategorized(self, chat_id: int) -> int:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT COUNT(*) FROM accounts WHERE chat_id=? AND category_id IS NULL",
                (chat_id,),
            )
            row = await cur.fetchone()
            return int(row[0]) if row else 0

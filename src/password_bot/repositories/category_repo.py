"""Category CRUD."""

from __future__ import annotations

from pathlib import Path

import aiosqlite

from password_bot.models.category import Category
from password_bot.repositories.db import connect


def _row_to_category(row: aiosqlite.Row) -> Category:
    return Category(id=row["id"], chat_id=row["chat_id"], name=row["name"], color=row["color"])


class CategoryRepo:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    async def create(self, cat: Category) -> None:
        async with connect(self._db_path) as conn:
            await conn.execute(
                "INSERT INTO categories (id, chat_id, name, color) VALUES (?, ?, ?, ?)",
                (cat.id, cat.chat_id, cat.name, cat.color),
            )

    async def get(self, cat_id: str) -> Category | None:
        async with connect(self._db_path) as conn:
            cur = await conn.execute("SELECT * FROM categories WHERE id=?", (cat_id,))
            row = await cur.fetchone()
            return _row_to_category(row) if row else None

    async def get_by_name(self, chat_id: int, name: str) -> Category | None:
        async with connect(self._db_path) as conn:
            cur = await conn.execute(
                "SELECT * FROM categories WHERE chat_id=? AND lower(name)=lower(?)",
                (chat_id, name),
            )
            row = await cur.fetchone()
            return _row_to_category(row) if row else None

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

import time
from pathlib import Path

import pytest

from password_bot.models.category import Category
from password_bot.models.user import User
from password_bot.repositories.category_repo import CategoryRepo
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo


@pytest.fixture
async def repo(tmp_db_path: Path) -> CategoryRepo:
    await migrate_to_latest(tmp_db_path)
    now = int(time.time())
    await UserRepo(tmp_db_path).create(
        User(
            chat_id=1,
            name="me",
            passphrase_hash="h",
            autolock_minutes=15,
            autolock_reset_on_activity=True,
            alert_days=180,
            crypto_version=2,
            legacy_salt=None,
            created_at=now,
            updated_at=now,
        )
    )
    return CategoryRepo(tmp_db_path)


@pytest.mark.asyncio
async def test_create_and_list(repo: CategoryRepo):
    await repo.create(Category(id="c1", chat_id=1, name="Work", color=None))
    await repo.create(Category(id="c2", chat_id=1, name="Personal", color="🟢"))
    listed = await repo.list_for_chat(1)
    assert {c.name for c in listed} == {"Work", "Personal"}


@pytest.mark.asyncio
async def test_get_by_name(repo: CategoryRepo):
    await repo.create(Category(id="c1", chat_id=1, name="Work", color=None))
    got = await repo.get_by_name(1, "work")
    assert got is not None
    assert got.id == "c1"


@pytest.mark.asyncio
async def test_rename(repo: CategoryRepo):
    await repo.create(Category(id="c1", chat_id=1, name="Work", color=None))
    await repo.rename("c1", "Job")
    got = await repo.get("c1")
    assert got is not None
    assert got.name == "Job"


@pytest.mark.asyncio
async def test_delete(repo: CategoryRepo):
    await repo.create(Category(id="c1", chat_id=1, name="Work", color=None))
    await repo.delete("c1")
    assert await repo.get("c1") is None

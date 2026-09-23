import time
from pathlib import Path

import pytest

from password_bot.models.account import AccountRow
from password_bot.models.category import Category
from password_bot.models.user import User
from password_bot.repositories.account_repo import AccountRepo
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
    await repo.create(Category(id="c1", chat_id=1, name="Work", icon=None))
    await repo.create(Category(id="c2", chat_id=1, name="Personal", icon="🟢"))
    listed = await repo.list_for_chat(1)
    assert {c.name for c in listed} == {"Work", "Personal"}


@pytest.mark.asyncio
async def test_get_by_name(repo: CategoryRepo):
    await repo.create(Category(id="c1", chat_id=1, name="Work", icon=None))
    got = await repo.get_by_name(1, "work")
    assert got is not None
    assert got.id == "c1"


@pytest.mark.asyncio
async def test_rename(repo: CategoryRepo):
    await repo.create(Category(id="c1", chat_id=1, name="Work", icon=None))
    await repo.rename("c1", "Job")
    got = await repo.get("c1")
    assert got is not None
    assert got.name == "Job"


@pytest.mark.asyncio
async def test_delete(repo: CategoryRepo):
    await repo.create(Category(id="c1", chat_id=1, name="Work", icon=None))
    await repo.delete("c1")
    assert await repo.get("c1") is None


def _row(account_id: str, category_id: str | None) -> AccountRow:
    return AccountRow(
        id=account_id,
        chat_id=1,
        name=account_id,
        username_enc=None,
        password_enc="p",
        url_enc=None,
        note_enc=None,
        category_id=category_id,
        password_hmac="h",
        crypto_version=2,
        password_changed_at=1,
        created_at=1,
        updated_at=1,
    )


@pytest.mark.asyncio
async def test_icon_roundtrip_and_set_icon(repo: CategoryRepo):
    await repo.create(Category(id="c1", chat_id=1, name="Work", icon="💼"))
    got = await repo.get("c1")
    assert got is not None and got.icon == "💼"
    await repo.set_icon("c1", None)
    got = await repo.get("c1")
    assert got is not None and got.icon is None


@pytest.mark.asyncio
async def test_list_with_counts_and_uncategorized(repo: CategoryRepo, tmp_db_path: Path):
    await repo.create(Category(id="c1", chat_id=1, name="Work", icon=None))
    await repo.create(Category(id="c2", chat_id=1, name="Home", icon=None))
    accounts = AccountRepo(tmp_db_path)
    await accounts.insert(_row("a1", "c1"))
    await accounts.insert(_row("a2", "c1"))
    await accounts.insert(_row("a3", None))
    counts = await repo.list_with_counts(1)
    assert [(c.name, n) for c, n in counts] == [("Home", 0), ("Work", 2)]
    assert await repo.count_uncategorized(1) == 1


async def test_category_lookup_is_unicode_case_insensitive(repo):
    await repo.create(Category(id="unicode", chat_id=1, name="Èlite", icon=None))
    found = await repo.get_by_name(1, "ÈLITE")
    assert found is not None and found.id == "unicode"
    found = await repo.get_by_name(1, "èlite")
    assert found is not None and found.id == "unicode"

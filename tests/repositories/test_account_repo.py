import time
from pathlib import Path

import pytest

from password_bot.models.account import AccountRow
from password_bot.models.user import User
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo


def _make_row(account_id: str, chat_id: int = 1, name: str = "GitHub") -> AccountRow:
    now = int(time.time())
    return AccountRow(
        id=account_id,
        chat_id=chat_id,
        name=name,
        username_enc=None,
        password_enc="p_enc",
        url_enc=None,
        note_enc=None,
        category_id=None,
        password_hmac="hmac",
        crypto_version=2,
        password_changed_at=now,
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
async def repos(tmp_db_path: Path):
    await migrate_to_latest(tmp_db_path)
    users = UserRepo(tmp_db_path)
    now = int(time.time())
    await users.create(
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
    return AccountRepo(tmp_db_path)


@pytest.mark.asyncio
async def test_insert_and_get(repos: AccountRepo):
    row = _make_row("a1")
    await repos.insert(row)
    got = await repos.get("a1")
    assert got == row


@pytest.mark.asyncio
async def test_list_for_chat(repos: AccountRepo):
    await repos.insert(_make_row("a1", name="GitHub"))
    await repos.insert(_make_row("a2", name="GitLab"))
    rows = await repos.list_for_chat(1)
    assert {r.id for r in rows} == {"a1", "a2"}


@pytest.mark.asyncio
async def test_update_fields(repos: AccountRepo):
    await repos.insert(_make_row("a1"))
    await repos.update_fields("a1", username_enc="new_u_enc", url_enc="url_enc")
    got = await repos.get("a1")
    assert got is not None
    assert got.username_enc == "new_u_enc"
    assert got.url_enc == "url_enc"


@pytest.mark.asyncio
async def test_update_password(repos: AccountRepo):
    await repos.insert(_make_row("a1"))
    await repos.update_password(
        "a1", password_enc="newp", password_hmac="newh", crypto_version=2, password_changed_at=999
    )
    got = await repos.get("a1")
    assert got is not None
    assert got.password_enc == "newp"
    assert got.password_hmac == "newh"
    assert got.password_changed_at == 999


@pytest.mark.asyncio
async def test_delete(repos: AccountRepo):
    await repos.insert(_make_row("a1"))
    await repos.delete("a1")
    assert await repos.get("a1") is None


@pytest.mark.asyncio
async def test_search_by_name_fuzzy(repos: AccountRepo):
    await repos.insert(_make_row("a1", name="GitHub"))
    await repos.insert(_make_row("a2", name="GitLab"))
    await repos.insert(_make_row("a3", name="Twitter"))
    results = await repos.search(1, "githb", threshold=60)
    names = {r.name for r, _ in results}
    assert "GitHub" in names
    assert "Twitter" not in names


@pytest.mark.asyncio
async def test_list_stale(repos: AccountRepo):
    old = _make_row("a1")
    old.password_changed_at = 100
    new = _make_row("a2")
    new.password_changed_at = 10_000
    await repos.insert(old)
    await repos.insert(new)
    stale = await repos.list_stale(1, older_than_epoch=5_000)
    assert {r.id for r in stale} == {"a1"}


@pytest.mark.asyncio
async def test_list_reuse_clusters_groups_by_hmac(repos: AccountRepo):
    for account_id, name, hmac in [
        ("a1", "GitHub", "same"),
        ("a2", "GitLab", "same"),
        ("a3", "Twitter", "unique"),
        ("a4", "Legacy1", ""),
        ("a5", "Legacy2", ""),
    ]:
        row = _make_row(account_id, name=name)
        row.password_hmac = hmac
        await repos.insert(row)
    clusters = await repos.list_reuse_clusters(1)
    assert [[r.name for r in c] for c in clusters] == [["GitHub", "GitLab"]]


@pytest.mark.asyncio
async def test_list_reuse_clusters_is_per_chat(repos: AccountRepo, tmp_db_path: Path):
    users = UserRepo(tmp_db_path)
    now = int(time.time())
    await users.create(
        User(
            chat_id=2,
            name="other",
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
    await repos.insert(_make_row("a1", chat_id=1))
    await repos.insert(_make_row("a2", chat_id=2))
    assert await repos.list_reuse_clusters(1) == []

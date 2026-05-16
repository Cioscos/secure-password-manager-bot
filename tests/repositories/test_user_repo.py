import time
from pathlib import Path

import pytest

from password_bot.models.user import User
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo


@pytest.fixture
async def repo(tmp_db_path: Path) -> UserRepo:
    await migrate_to_latest(tmp_db_path)
    return UserRepo(tmp_db_path)


@pytest.mark.asyncio
async def test_create_and_get(repo: UserRepo):
    now = int(time.time())
    u = User(
        chat_id=42,
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
    await repo.create(u)
    got = await repo.get(42)
    assert got == u


@pytest.mark.asyncio
async def test_get_missing_returns_none(repo: UserRepo):
    assert await repo.get(999) is None


@pytest.mark.asyncio
async def test_update_passphrase_and_version(repo: UserRepo):
    now = int(time.time())
    await repo.create(
        User(
            chat_id=1,
            name="x",
            passphrase_hash="old",
            autolock_minutes=15,
            autolock_reset_on_activity=True,
            alert_days=180,
            crypto_version=1,
            legacy_salt="abc",
            created_at=now,
            updated_at=now,
        )
    )
    await repo.update_passphrase(1, "new", crypto_version=2)
    got = await repo.get(1)
    assert got is not None
    assert got.passphrase_hash == "new"
    assert got.crypto_version == 2
    assert got.legacy_salt is None


@pytest.mark.asyncio
async def test_update_autolock(repo: UserRepo):
    now = int(time.time())
    await repo.create(
        User(
            chat_id=1,
            name="x",
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
    await repo.update_autolock(1, minutes=30, reset_on_activity=False)
    got = await repo.get(1)
    assert got is not None
    assert got.autolock_minutes == 30
    assert got.autolock_reset_on_activity is False


@pytest.mark.asyncio
async def test_update_alert_days(repo: UserRepo):
    now = int(time.time())
    await repo.create(
        User(
            chat_id=1,
            name="x",
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
    await repo.update_alert_days(1, 365)
    got = await repo.get(1)
    assert got is not None
    assert got.alert_days == 365


@pytest.mark.asyncio
async def test_pw_prefs_default_when_unset(repo: UserRepo):
    from password_bot.models.pw_prefs import PwPrefs

    now = int(time.time())
    await repo.create(
        User(
            chat_id=7,
            name="x",
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
    prefs = await repo.get_pw_prefs(7)
    assert prefs == PwPrefs()


@pytest.mark.asyncio
async def test_pw_prefs_roundtrip(repo: UserRepo):
    from password_bot.models.pw_prefs import PwPrefs

    now = int(time.time())
    await repo.create(
        User(
            chat_id=8,
            name="x",
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
    p = PwPrefs(
        length=32,
        upper=False,
        lower=True,
        digits=True,
        symbols=False,
        exclude_ambiguous=True,
        no_duplicates=True,
    )
    await repo.set_pw_prefs(8, p)
    got = await repo.get_pw_prefs(8)
    assert got == p

import time
from pathlib import Path

import pytest
from freezegun import freeze_time  # noqa: F401

from password_bot.models.account import AccountRow
from password_bot.models.user import User
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.alert_service import AlertService


@pytest.fixture
async def setup(tmp_db_path: Path):
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
    accounts = AccountRepo(tmp_db_path)

    async def insert(account_id: str, changed_at: int):
        await accounts.insert(
            AccountRow(
                id=account_id,
                chat_id=1,
                name=account_id,
                username_enc=None,
                password_enc="p",
                url_enc=None,
                note_enc=None,
                category_id=None,
                password_hmac="h",
                crypto_version=2,
                password_changed_at=changed_at,
                created_at=changed_at,
                updated_at=changed_at,
            )
        )

    await insert("old", changed_at=int(time.time()) - 200 * 86400)
    await insert("fresh", changed_at=int(time.time()) - 10 * 86400)
    return AlertService(users=users, accounts=accounts)


@pytest.mark.asyncio
async def test_stale_returns_old_only(setup: AlertService):
    stale = await setup.find_stale(chat_id=1)
    assert [a.id for a in stale] == ["old"]


@pytest.mark.asyncio
async def test_stale_threshold_changes_with_user_setting(setup: AlertService, tmp_db_path: Path):
    users = UserRepo(tmp_db_path)
    await users.update_alert_days(1, 365)
    stale = await setup.find_stale(chat_id=1)
    assert stale == []

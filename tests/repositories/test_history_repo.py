import time
from pathlib import Path

import pytest

from password_bot.models.account import AccountRow
from password_bot.models.user import User
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.history_repo import HistoryRepo
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo


@pytest.fixture
async def setup(tmp_db_path: Path):
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
    accounts = AccountRepo(tmp_db_path)
    await accounts.insert(
        AccountRow(
            id="a1",
            chat_id=1,
            name="GitHub",
            username_enc=None,
            password_enc="p0",
            url_enc=None,
            note_enc=None,
            category_id=None,
            password_hmac="h",
            crypto_version=2,
            password_changed_at=now,
            created_at=now,
            updated_at=now,
        )
    )
    return HistoryRepo(tmp_db_path)


@pytest.mark.asyncio
async def test_push_and_list(setup: HistoryRepo):
    await setup.push("a1", password_enc="p0", crypto_version=2, replaced_at=10)
    await setup.push("a1", password_enc="p1", crypto_version=2, replaced_at=20)
    rows = await setup.list_for_account("a1")
    assert [r.password_enc for r in rows] == ["p1", "p0"]


@pytest.mark.asyncio
async def test_prune_keeps_latest_n(setup: HistoryRepo):
    for i in range(8):
        await setup.push("a1", password_enc=f"p{i}", crypto_version=2, replaced_at=i)
    await setup.prune("a1", keep=5)
    rows = await setup.list_for_account("a1")
    assert [r.password_enc for r in rows] == ["p7", "p6", "p5", "p4", "p3"]

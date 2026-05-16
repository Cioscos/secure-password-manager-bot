import time
from pathlib import Path

import pytest

from password_bot.crypto.cipher import GcmCipher
from password_bot.models.user import User
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.history_repo import HistoryRepo
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.vault_service import NewAccount, UpdatedFields, VaultService


@pytest.fixture
async def vault(tmp_db_path: Path):
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
    return VaultService(
        account_repo=AccountRepo(tmp_db_path),
        history_repo=HistoryRepo(tmp_db_path),
        cipher=GcmCipher(),
        history_max=5,
    )


@pytest.mark.asyncio
async def test_add_account_with_username(vault: VaultService, aes_key):
    new = NewAccount(
        chat_id=1,
        name="GitHub",
        username="claudio",
        password="s3cr3t",
        url="https://github.com",
        note=None,
        category_id=None,
    )
    acc = await vault.add(new, aes_key=aes_key, hmac_key=b"\x10" * 32)
    assert acc.id
    fetched = await vault.get_decrypted(acc.id, aes_key=aes_key)
    assert fetched is not None
    assert fetched.username == "claudio"
    assert fetched.password == "s3cr3t"


@pytest.mark.asyncio
async def test_add_account_without_username(vault: VaultService, aes_key):
    new = NewAccount(
        chat_id=1,
        name="GitHub",
        username=None,
        password="s3cr3t",
        url=None,
        note=None,
        category_id=None,
    )
    acc = await vault.add(new, aes_key=aes_key, hmac_key=b"\x10" * 32)
    fetched = await vault.get_decrypted(acc.id, aes_key=aes_key)
    assert fetched is not None
    assert fetched.username is None


@pytest.mark.asyncio
async def test_update_field(vault: VaultService, aes_key):
    new = NewAccount(
        chat_id=1, name="GitHub", username="a", password="p", url=None, note=None, category_id=None
    )
    acc = await vault.add(new, aes_key=aes_key, hmac_key=b"\x10" * 32)
    await vault.update_fields(acc.id, UpdatedFields(username="b", url="https://x"), aes_key=aes_key)
    fetched = await vault.get_decrypted(acc.id, aes_key=aes_key)
    assert fetched is not None
    assert fetched.username == "b"
    assert fetched.url == "https://x"


@pytest.mark.asyncio
async def test_update_password_pushes_history(vault: VaultService, aes_key):
    new = NewAccount(
        chat_id=1,
        name="GitHub",
        username=None,
        password="p0",
        url=None,
        note=None,
        category_id=None,
    )
    acc = await vault.add(new, aes_key=aes_key, hmac_key=b"\x10" * 32)
    await vault.update_password(acc.id, "p1", aes_key=aes_key, hmac_key=b"\x10" * 32)
    await vault.update_password(acc.id, "p2", aes_key=aes_key, hmac_key=b"\x10" * 32)
    history = await vault.list_history(acc.id, aes_key=aes_key)
    assert [h.password for h in history] == ["p1", "p0"]
    fetched = await vault.get_decrypted(acc.id, aes_key=aes_key)
    assert fetched is not None
    assert fetched.password == "p2"


@pytest.mark.asyncio
async def test_history_pruned_to_max(vault: VaultService, aes_key):
    new = NewAccount(
        chat_id=1,
        name="GitHub",
        username=None,
        password="p0",
        url=None,
        note=None,
        category_id=None,
    )
    acc = await vault.add(new, aes_key=aes_key, hmac_key=b"\x10" * 32)
    for i in range(1, 10):
        await vault.update_password(acc.id, f"p{i}", aes_key=aes_key, hmac_key=b"\x10" * 32)
    history = await vault.list_history(acc.id, aes_key=aes_key)
    assert len(history) == 5
    assert [h.password for h in history] == ["p8", "p7", "p6", "p5", "p4"]


@pytest.mark.asyncio
async def test_duplicate_account(vault: VaultService, aes_key):
    new = NewAccount(
        chat_id=1, name="GitHub", username="u", password="p", url=None, note=None, category_id=None
    )
    acc = await vault.add(new, aes_key=aes_key, hmac_key=b"\x10" * 32)
    copy = await vault.duplicate(acc.id, aes_key=aes_key, hmac_key=b"\x10" * 32)
    assert copy.id != acc.id
    assert copy.name == "GitHub (copia)"
    assert copy.password == "p"

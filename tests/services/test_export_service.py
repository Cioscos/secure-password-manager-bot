import json
import time
from pathlib import Path

import pytest

from password_bot.config import Argon2Params
from password_bot.crypto.cipher import GcmCipher
from password_bot.crypto.kdf import Argon2idKdf
from password_bot.models.user import User
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.category_repo import CategoryRepo
from password_bot.repositories.history_repo import HistoryRepo
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.errors import InvalidExportFileError, InvalidPassphraseError
from password_bot.services.export_service import ExportService, MergeStrategy
from password_bot.services.vault_service import NewAccount, VaultService


@pytest.fixture
def kdf():
    p = Argon2Params(memory_cost=8192, time_cost=1, parallelism=1)
    return Argon2idKdf(hash_params=p, derive_params=p)


@pytest.fixture
async def setup(tmp_db_path: Path, kdf: Argon2idKdf, aes_key: bytes):
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
    vault = VaultService(
        account_repo=AccountRepo(tmp_db_path),
        history_repo=HistoryRepo(tmp_db_path),
        cipher=GcmCipher(),
        history_max=5,
    )
    await vault.add(
        NewAccount(
            chat_id=1,
            name="GitHub",
            username="u",
            password="p",
            url=None,
            note=None,
            category_id=None,
        ),
        aes_key=aes_key,
        hmac_key=b"\x10" * 32,
    )
    export = ExportService(
        accounts=AccountRepo(tmp_db_path),
        categories=CategoryRepo(tmp_db_path),
        vault=vault,
        cipher=GcmCipher(),
        kdf=kdf,
    )
    return export, aes_key, vault


@pytest.mark.asyncio
async def test_export_then_import_roundtrip(setup, tmp_db_path: Path, kdf, aes_key):
    export, vault_key, vault = setup
    payload = await export.export(chat_id=1, vault_key=vault_key, export_passphrase="exp")
    data = json.loads(payload)
    assert data["format"] == "password-bot-vault"
    assert data["version"] == 1
    assert len(data["items"]) == 1

    # Clear and re-import.
    accs = await vault.list_decrypted(1, aes_key=vault_key)
    for a in accs:
        await vault.delete(a.id)

    report = await export.import_payload(
        payload,
        chat_id=1,
        vault_key=vault_key,
        hmac_key=b"\x10" * 32,
        export_passphrase="exp",
        strategy=MergeStrategy.OVERWRITE,
    )
    assert report.added == 1
    restored = await vault.list_decrypted(1, aes_key=vault_key)
    assert restored[0].password == "p"


@pytest.mark.asyncio
async def test_import_wrong_passphrase(setup, aes_key):
    export, vault_key, _ = setup
    payload = await export.export(chat_id=1, vault_key=vault_key, export_passphrase="exp")
    with pytest.raises(InvalidPassphraseError):
        await export.import_payload(
            payload,
            chat_id=1,
            vault_key=vault_key,
            hmac_key=b"\x10" * 32,
            export_passphrase="wrong",
            strategy=MergeStrategy.OVERWRITE,
        )


@pytest.mark.asyncio
async def test_import_invalid_schema(setup, aes_key):
    export, vault_key, _ = setup
    with pytest.raises(InvalidExportFileError):
        await export.import_payload(
            '{"format": "wrong"}',
            chat_id=1,
            vault_key=vault_key,
            hmac_key=b"\x10" * 32,
            export_passphrase="x",
            strategy=MergeStrategy.OVERWRITE,
        )

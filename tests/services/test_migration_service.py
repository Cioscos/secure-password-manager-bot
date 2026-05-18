import base64
import hashlib
import os
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from password_bot.config import Argon2Params
from password_bot.crypto.cipher import GcmCipher
from password_bot.crypto.kdf import Argon2idKdf
from password_bot.crypto.legacy import LegacyCfbDecryptor, legacy_derive_key
from password_bot.models.account import AccountRow
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.history_repo import HistoryRepo
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.auth_service import AuthService
from password_bot.services.migration_service import MigrationService


def _seed_legacy_db(path: Path, passphrase: str = "hunter2") -> None:
    """Seed a v1 DB matching the real `master` branch schema exactly.

    Mirrors `master:src/account_repository.py:create_database` and
    `master:src/crypto_service.py` for hash + cipher format.
    """
    salt = os.urandom(16)
    salt_hex = salt.hex()
    hexhash = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 100_000).hex()
    key = legacy_derive_key(passphrase, salt_hex)

    def enc(plain: str) -> str:
        iv = os.urandom(16)
        e = Cipher(algorithms.AES(key), modes.CFB(iv)).encryptor()
        ct = e.update(plain.encode()) + e.finalize()
        return base64.b64encode(iv + ct).decode()

    with sqlite3.connect(path) as conn:
        conn.executescript("""
            CREATE TABLE accounts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                chat_id  INTEGER,
                FOREIGN KEY (chat_id) REFERENCES users(chat_id),
                UNIQUE (id, name)
            );
            CREATE TABLE users (
                chat_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                salted_hash TEXT,
                salt TEXT
            );
        """)
        conn.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?)",
            (1, "me", hexhash, salt_hex),
        )
        conn.execute(
            "INSERT INTO accounts VALUES (?, ?, ?, ?, ?)",
            ("a1", "GitHub", enc("claudio"), enc("legacy-secret"), 1),
        )


@pytest.fixture
def kdf():
    p = Argon2Params(memory_cost=8192, time_cost=1, parallelism=1)
    return Argon2idKdf(hash_params=p, derive_params=p)


@pytest.mark.asyncio
async def test_unlock_legacy_and_migrate(tmp_db_path: Path, kdf: Argon2idKdf):
    _seed_legacy_db(tmp_db_path)
    await migrate_to_latest(tmp_db_path)
    users = UserRepo(tmp_db_path)
    accounts = AccountRepo(tmp_db_path)
    cipher = GcmCipher()
    svc = MigrationService(
        users=users,
        accounts=accounts,
        kdf=kdf,
        cipher=cipher,
        legacy_decryptor=LegacyCfbDecryptor(),
    )

    session_r = await svc.unlock_legacy(chat_id=1, passphrase="hunter2")
    assert session_r.ok
    session = session_r.value
    await svc.migrate_user(chat_id=1, passphrase="hunter2", session=session)

    user = await users.get(1)
    assert user is not None
    assert user.crypto_version == 2
    assert user.legacy_salt is None

    row = await accounts.get("a1")
    assert row is not None
    assert row.crypto_version == 2
    # New ciphertext starts with version byte 2.
    blob = base64.b64decode(row.password_enc)
    assert blob[0] == 2

    auth = AuthService(user_repo=users, kdf=kdf)
    r = await auth.unlock(chat_id=1, passphrase="hunter2")
    assert r.ok


@pytest.mark.asyncio
async def test_unlock_legacy_wrong_passphrase(tmp_db_path: Path, kdf: Argon2idKdf):
    _seed_legacy_db(tmp_db_path)
    await migrate_to_latest(tmp_db_path)
    svc = MigrationService(
        users=UserRepo(tmp_db_path),
        accounts=AccountRepo(tmp_db_path),
        kdf=kdf,
        cipher=GcmCipher(),
        legacy_decryptor=LegacyCfbDecryptor(),
    )
    r = await svc.unlock_legacy(chat_id=1, passphrase="nope")
    assert not r.ok


@pytest.mark.asyncio
async def test_insert_nullable_username_after_migration(tmp_db_path: Path, kdf: Argon2idKdf):
    """Regression: after migrating a real-v1 DB, a new account with NULL
    username_enc (the user hit /skip on the username step) must INSERT cleanly.

    Before the 12-step rebuild in 002_legacy_upgrade.sql, RENAME COLUMN kept the
    v1 `username NOT NULL` constraint and this insert failed with
    `IntegrityError: NOT NULL constraint failed: accounts.username_enc`.
    """
    _seed_legacy_db(tmp_db_path)
    await migrate_to_latest(tmp_db_path)
    users = UserRepo(tmp_db_path)
    accounts = AccountRepo(tmp_db_path)
    cipher = GcmCipher()
    svc = MigrationService(
        users=users,
        accounts=accounts,
        kdf=kdf,
        cipher=cipher,
        legacy_decryptor=LegacyCfbDecryptor(),
    )
    session_r = await svc.unlock_legacy(chat_id=1, passphrase="hunter2")
    assert session_r.ok
    await svc.migrate_user(chat_id=1, passphrase="hunter2", session=session_r.value)

    # Insert a fresh account with username_enc=NULL — the /skip flow output.
    new_row = AccountRow(
        id="a2",
        chat_id=1,
        name="NoUserSite",
        username_enc=None,
        password_enc=cipher.encrypt(b"pw", session_r.value.aes_key),
        url_enc=None,
        note_enc=None,
        category_id=None,
        password_hmac="0" * 64,
        crypto_version=2,
        password_changed_at=0,
        created_at=0,
        updated_at=0,
    )
    await accounts.insert(new_row)
    fetched = await accounts.get("a2")
    assert fetched is not None
    assert fetched.username_enc is None


@pytest.mark.asyncio
async def test_history_table_usable_after_migration(tmp_db_path: Path, kdf: Argon2idKdf):
    """password_history must accept inserts referencing migrated account ids."""
    _seed_legacy_db(tmp_db_path)
    await migrate_to_latest(tmp_db_path)
    history = HistoryRepo(tmp_db_path)
    await history.push(account_id="a1", password_enc="anything", crypto_version=2, replaced_at=1)
    rows = await history.list_for_account("a1")
    assert len(rows) == 1

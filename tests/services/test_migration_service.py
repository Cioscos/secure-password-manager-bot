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
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.auth_service import AuthService
from password_bot.services.migration_service import MigrationService


def _seed_legacy_db(path: Path, passphrase: str = "hunter2") -> None:
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
            CREATE TABLE users (
                chat_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                salted_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            );
            CREATE TABLE accounts (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                username TEXT,
                password TEXT NOT NULL,
                chat_id INTEGER NOT NULL REFERENCES users(chat_id)
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

from pathlib import Path

import pytest

from password_bot.config import Argon2Params
from password_bot.crypto.kdf import Argon2idKdf
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.auth_service import AuthService, Session
from password_bot.services.errors import InvalidPassphraseError


@pytest.fixture
def kdf():
    p = Argon2Params(memory_cost=8192, time_cost=1, parallelism=1)
    return Argon2idKdf(hash_params=p, derive_params=p)


@pytest.fixture
async def auth(tmp_db_path: Path, kdf: Argon2idKdf):
    await migrate_to_latest(tmp_db_path)
    return AuthService(user_repo=UserRepo(tmp_db_path), kdf=kdf)


@pytest.mark.asyncio
async def test_register_creates_user_and_returns_session(auth: AuthService):
    r = await auth.register(chat_id=1, name="me", passphrase="hunter2")
    assert r.ok
    session = r.value
    assert isinstance(session, Session)
    assert len(session.aes_key) == 32
    assert len(session.hmac_key) == 32


@pytest.mark.asyncio
async def test_unlock_correct_passphrase(auth: AuthService):
    await auth.register(chat_id=1, name="me", passphrase="hunter2")
    r = await auth.unlock(chat_id=1, passphrase="hunter2")
    assert r.ok
    assert r.value is not None


@pytest.mark.asyncio
async def test_unlock_wrong_passphrase(auth: AuthService):
    await auth.register(chat_id=1, name="me", passphrase="hunter2")
    r = await auth.unlock(chat_id=1, passphrase="nope")
    assert not r.ok
    assert isinstance(r.error, InvalidPassphraseError)


@pytest.mark.asyncio
async def test_change_passphrase(auth: AuthService):
    await auth.register(chat_id=1, name="me", passphrase="hunter2")
    r = await auth.change_passphrase(chat_id=1, current="hunter2", new="newpass")
    assert r.ok
    # Two-phase: commit AFTER simulated rotation succeeds.
    await auth.commit_passphrase_change(chat_id=1, new_passphrase="newpass")
    bad = await auth.unlock(chat_id=1, passphrase="hunter2")
    good = await auth.unlock(chat_id=1, passphrase="newpass")
    assert not bad.ok
    assert good.ok


@pytest.mark.asyncio
async def test_change_passphrase_without_commit_keeps_old(auth: AuthService):
    await auth.register(chat_id=1, name="me", passphrase="hunter2")
    r = await auth.change_passphrase(chat_id=1, current="hunter2", new="newpass")
    assert r.ok
    # No commit yet -> old passphrase must still unlock
    still_works = await auth.unlock(chat_id=1, passphrase="hunter2")
    assert still_works.ok
    new_does_not_yet = await auth.unlock(chat_id=1, passphrase="newpass")
    assert not new_does_not_yet.ok


@pytest.mark.asyncio
async def test_change_passphrase_wrong_current(auth: AuthService):
    await auth.register(chat_id=1, name="me", passphrase="hunter2")
    r = await auth.change_passphrase(chat_id=1, current="x", new="y")
    assert not r.ok
    assert isinstance(r.error, InvalidPassphraseError)

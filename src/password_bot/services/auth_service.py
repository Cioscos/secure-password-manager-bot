"""Auth service: register, unlock, lock, change passphrase."""

from __future__ import annotations

import time
from dataclasses import dataclass

from password_bot.crypto.hkdf import derive_subkey
from password_bot.crypto.kdf import Argon2idKdf
from password_bot.models.user import User
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.errors import InvalidPassphraseError
from password_bot.services.result import Result

SESSION_LEN_SECONDS_DEFAULT = 15 * 60


@dataclass(slots=True)
class Session:
    chat_id: int
    aes_key: bytes
    hmac_key: bytes
    expires_at: int


def _derive_salt_from_hash(passphrase_hash: str) -> bytes:
    # argon2-cffi encoded hash format: $argon2id$v=19$m=...,t=...,p=...$<b64-salt>$<b64-hash>
    parts = passphrase_hash.split("$")
    if len(parts) < 6:
        raise ValueError("Unexpected Argon2 hash format")
    salt_b64 = parts[4]
    salt_b64 += "=" * (-len(salt_b64) % 4)
    import base64

    return base64.b64decode(salt_b64)


class AuthService:
    def __init__(self, *, user_repo: UserRepo, kdf: Argon2idKdf) -> None:
        self._users = user_repo
        self._kdf = kdf

    def _make_session(self, chat_id: int, aes_key: bytes, ttl: int) -> Session:
        hmac_key = derive_subkey(aes_key, info=b"reuse-detection")
        return Session(
            chat_id=chat_id,
            aes_key=aes_key,
            hmac_key=hmac_key,
            expires_at=int(time.time()) + ttl,
        )

    async def register(
        self,
        *,
        chat_id: int,
        name: str,
        passphrase: str,
        autolock_minutes: int = 15,
        alert_days: int = 180,
    ) -> Result[Session]:
        now = int(time.time())
        passphrase_hash = self._kdf.hash_passphrase(passphrase)
        user = User(
            chat_id=chat_id,
            name=name,
            passphrase_hash=passphrase_hash,
            autolock_minutes=autolock_minutes,
            autolock_reset_on_activity=True,
            alert_days=alert_days,
            crypto_version=2,
            legacy_salt=None,
            created_at=now,
            updated_at=now,
        )
        await self._users.create(user)
        salt = _derive_salt_from_hash(passphrase_hash)
        aes_key = self._kdf.derive_key(passphrase, salt)
        ttl = autolock_minutes * 60 if autolock_minutes > 0 else SESSION_LEN_SECONDS_DEFAULT
        return Result.success(self._make_session(chat_id, aes_key, ttl))

    async def unlock(self, *, chat_id: int, passphrase: str) -> Result[Session]:
        user = await self._users.get(chat_id)
        if user is None:
            return Result.err(InvalidPassphraseError())
        if user.crypto_version != 2:
            return Result.err(InvalidPassphraseError())
        if not self._kdf.verify(passphrase, user.passphrase_hash):
            return Result.err(InvalidPassphraseError())
        salt = _derive_salt_from_hash(user.passphrase_hash)
        aes_key = self._kdf.derive_key(passphrase, salt)
        ttl = (
            user.autolock_minutes * 60 if user.autolock_minutes > 0 else SESSION_LEN_SECONDS_DEFAULT
        )
        return Result.success(self._make_session(chat_id, aes_key, ttl))

    async def change_passphrase(
        self, *, chat_id: int, current: str, new: str
    ) -> Result[tuple[Session, bytes]]:
        """Returns the new session and the OLD aes_key (needed by VaultService to re-encrypt)."""
        user = await self._users.get(chat_id)
        if user is None or not self._kdf.verify(current, user.passphrase_hash):
            return Result.err(InvalidPassphraseError())
        old_salt = _derive_salt_from_hash(user.passphrase_hash)
        old_key = self._kdf.derive_key(current, old_salt)
        new_hash = self._kdf.hash_passphrase(new)
        new_salt = _derive_salt_from_hash(new_hash)
        new_key = self._kdf.derive_key(new, new_salt)
        return Result.success(
            (
                Session(
                    chat_id=chat_id,
                    aes_key=new_key,
                    hmac_key=derive_subkey(new_key, info=b"reuse-detection"),
                    expires_at=int(time.time())
                    + (
                        user.autolock_minutes * 60
                        if user.autolock_minutes > 0
                        else SESSION_LEN_SECONDS_DEFAULT
                    ),
                ),
                old_key,
            )
        )

    async def commit_passphrase_change(self, *, chat_id: int, new_passphrase: str) -> None:
        """Persist the new passphrase hash. Called after re-encryption completes."""
        new_hash = self._kdf.hash_passphrase(new_passphrase)
        await self._users.update_passphrase(chat_id, new_hash, crypto_version=2)

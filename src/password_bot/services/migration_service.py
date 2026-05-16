"""Lazy migration from legacy (v1) to current (v2) crypto."""

from __future__ import annotations

import time

from password_bot.crypto.cipher import CRYPTO_VERSION_GCM, GcmCipher
from password_bot.crypto.hkdf import derive_subkey
from password_bot.crypto.kdf import Argon2idKdf
from password_bot.crypto.legacy import (
    LegacyCfbDecryptor,
    legacy_derive_key,
    legacy_verify_passphrase,
)
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.user_repo import UserRepo
from password_bot.services.auth_service import Session, _derive_salt_from_hash
from password_bot.services.errors import InvalidPassphraseError
from password_bot.services.result import Result
from password_bot.services.reuse_detector import compute_password_hmac


class MigrationService:
    def __init__(
        self,
        *,
        users: UserRepo,
        accounts: AccountRepo,
        kdf: Argon2idKdf,
        cipher: GcmCipher,
        legacy_decryptor: LegacyCfbDecryptor,
    ) -> None:
        self._users = users
        self._accounts = accounts
        self._kdf = kdf
        self._cipher = cipher
        self._legacy = legacy_decryptor

    async def unlock_legacy(self, *, chat_id: int, passphrase: str) -> Result[Session]:
        user = await self._users.get(chat_id)
        if user is None or user.crypto_version != 1 or user.legacy_salt is None:
            return Result.err(InvalidPassphraseError())
        if not legacy_verify_passphrase(passphrase, user.passphrase_hash, user.legacy_salt):
            return Result.err(InvalidPassphraseError())
        legacy_key = legacy_derive_key(passphrase, user.legacy_salt)
        new_hash = self._kdf.hash_passphrase(passphrase)
        new_salt = _derive_salt_from_hash(new_hash)
        new_key = self._kdf.derive_key(passphrase, new_salt)
        ttl = user.autolock_minutes * 60 if user.autolock_minutes > 0 else 15 * 60
        session = Session(
            chat_id=chat_id,
            aes_key=new_key,
            hmac_key=derive_subkey(new_key, info=b"reuse-detection"),
            expires_at=int(time.time()) + ttl,
            _legacy_key=legacy_key,
            _new_passphrase_hash=new_hash,
        )
        return Result.success(session)

    async def migrate_user(self, *, chat_id: int, passphrase: str, session: Session) -> None:
        user = await self._users.get(chat_id)
        if user is None:
            return
        if session._legacy_key is None:
            raise RuntimeError("Session is not the result of unlock_legacy")
        legacy_key = session._legacy_key
        if session._new_passphrase_hash is None:
            raise RuntimeError("Session is missing new_passphrase_hash")
        new_hash = session._new_passphrase_hash

        rows = await self._accounts.list_for_chat(chat_id)
        now = int(time.time())
        for row in rows:
            if row.crypto_version != 1:
                continue
            username_plain = (
                self._legacy.decrypt(row.username_enc, legacy_key) if row.username_enc else None
            )
            password_plain = self._legacy.decrypt(row.password_enc, legacy_key)
            new_username_enc = (
                self._cipher.encrypt(username_plain.encode("utf-8"), session.aes_key)
                if username_plain is not None
                else None
            )
            new_password_enc = self._cipher.encrypt(password_plain.encode("utf-8"), session.aes_key)
            new_hmac = compute_password_hmac(password_plain, session.hmac_key)
            await self._accounts.update_fields(row.id, username_enc=new_username_enc)
            await self._accounts.update_password(
                row.id,
                password_enc=new_password_enc,
                password_hmac=new_hmac,
                crypto_version=CRYPTO_VERSION_GCM,
                password_changed_at=row.password_changed_at or now,
            )
        await self._users.update_passphrase(chat_id, new_hash, crypto_version=CRYPTO_VERSION_GCM)

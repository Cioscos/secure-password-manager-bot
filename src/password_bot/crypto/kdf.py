"""Argon2id KDF wrapper."""

from __future__ import annotations

from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw

from password_bot.config import Argon2Params


class Argon2idKdf:
    def __init__(self, hash_params: Argon2Params, derive_params: Argon2Params) -> None:
        self._hash_params = hash_params
        self._derive_params = derive_params
        self._hasher = PasswordHasher(
            time_cost=hash_params.time_cost,
            memory_cost=hash_params.memory_cost,
            parallelism=hash_params.parallelism,
            hash_len=hash_params.hash_len,
            salt_len=hash_params.salt_len,
            type=Type.ID,
        )

    def hash_passphrase(self, passphrase: str) -> str:
        return self._hasher.hash(passphrase)

    def verify(self, passphrase: str, encoded_hash: str) -> bool:
        try:
            return self._hasher.verify(encoded_hash, passphrase)
        except VerifyMismatchError:
            return False

    def derive_key(self, passphrase: str, salt: bytes) -> bytes:
        p = self._derive_params
        return hash_secret_raw(
            secret=passphrase.encode("utf-8"),
            salt=salt,
            time_cost=p.time_cost,
            memory_cost=p.memory_cost,
            parallelism=p.parallelism,
            hash_len=p.hash_len,
            type=Type.ID,
        )

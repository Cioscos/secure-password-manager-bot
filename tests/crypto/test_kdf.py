import secrets

import pytest

from password_bot.config import Argon2Params
from password_bot.crypto.kdf import Argon2idKdf


@pytest.fixture
def kdf():
    return Argon2idKdf(
        hash_params=Argon2Params(memory_cost=8192, time_cost=1, parallelism=1),
        derive_params=Argon2Params(memory_cost=8192, time_cost=1, parallelism=1),
    )


def test_hash_and_verify_roundtrip(kdf):
    h = kdf.hash_passphrase("hunter2")
    assert kdf.verify("hunter2", h) is True


def test_verify_rejects_wrong_passphrase(kdf):
    h = kdf.hash_passphrase("hunter2")
    assert kdf.verify("nope", h) is False


def test_derive_key_deterministic(kdf):
    salt = secrets.token_bytes(16)
    k1 = kdf.derive_key("pw", salt)
    k2 = kdf.derive_key("pw", salt)
    assert k1 == k2
    assert len(k1) == 32


def test_derive_key_salt_sensitive(kdf):
    k1 = kdf.derive_key("pw", b"\x00" * 16)
    k2 = kdf.derive_key("pw", b"\x01" * 16)
    assert k1 != k2

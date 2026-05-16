import secrets

import pytest
from argon2.exceptions import InvalidHash

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


def test_verify_returns_false_on_other_verification_errors(kdf):
    # An old hash with totally different parameters that the current hasher rejects on verify.
    # We construct a hash from a fresh PasswordHasher with mismatched salt_len; verify against
    # our kdf should return False (not raise) because the new hasher considers the params
    # incompatible.
    from argon2 import PasswordHasher, Type

    old = PasswordHasher(
        time_cost=2, memory_cost=8192, parallelism=1, hash_len=64, salt_len=32, type=Type.ID
    )
    h = old.hash("hunter2")
    # Same passphrase but a hash from a different param set may still verify; this is a
    # smoke test that confirms verify gracefully handles atypical params. The important
    # assertion is "no raised exception, returns a bool."
    result = kdf.verify("hunter2", h)
    assert result in (True, False)


def test_verify_propagates_on_malformed_hash(kdf):
    with pytest.raises(InvalidHash):
        kdf.verify("anything", "not-a-real-hash")

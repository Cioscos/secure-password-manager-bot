import base64
import secrets

import pytest
from cryptography.exceptions import InvalidTag
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from password_bot.crypto.cipher import CRYPTO_VERSION_GCM, GcmCipher


@pytest.fixture
def cipher():
    return GcmCipher()


def test_encrypt_decrypt_roundtrip(cipher, aes_key):
    ct = cipher.encrypt(b"hello", aes_key)
    assert cipher.decrypt(ct, aes_key) == b"hello"


def test_ciphertext_starts_with_version_byte(cipher, aes_key):
    ct = cipher.encrypt(b"x", aes_key)
    blob = base64.b64decode(ct)
    assert blob[0] == CRYPTO_VERSION_GCM


def test_nonce_uniqueness(cipher, aes_key):
    seen = set()
    for _ in range(2000):
        blob = base64.b64decode(cipher.encrypt(b"x", aes_key))
        nonce = blob[1:13]
        seen.add(nonce)
    assert len(seen) == 2000


def test_tamper_raises_invalid_tag(cipher, aes_key):
    ct = cipher.encrypt(b"hello", aes_key)
    blob = bytearray(base64.b64decode(ct))
    blob[-1] ^= 0xFF
    bad = base64.b64encode(bytes(blob)).decode()
    with pytest.raises(InvalidTag):
        cipher.decrypt(bad, aes_key)


def test_empty_plaintext(cipher, aes_key):
    ct = cipher.encrypt(b"", aes_key)
    assert cipher.decrypt(ct, aes_key) == b""


def test_wrong_key_raises(cipher, aes_key):
    ct = cipher.encrypt(b"hello", aes_key)
    other = secrets.token_bytes(32)
    with pytest.raises(InvalidTag):
        cipher.decrypt(ct, other)


@given(plaintext=st.binary(max_size=4096))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_property_roundtrip(plaintext, aes_key):
    c = GcmCipher()
    assert c.decrypt(c.encrypt(plaintext, aes_key), aes_key) == plaintext

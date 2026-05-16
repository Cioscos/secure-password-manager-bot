import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from password_bot.crypto.legacy import (
    LegacyCfbDecryptor,
    legacy_derive_key,
    legacy_verify_passphrase,
)


def legacy_encrypt_inline(plaintext: str, key: bytes) -> str:
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(key), modes.CFB(iv)).encryptor()
    ct = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()


def legacy_hash_inline(passphrase: str) -> tuple[str, str]:
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 100_000)
    return h.hex(), salt.hex()


def test_legacy_verify_passphrase():
    hexhash, salt_hex = legacy_hash_inline("hunter2")
    assert legacy_verify_passphrase("hunter2", hexhash, salt_hex) is True
    assert legacy_verify_passphrase("nope", hexhash, salt_hex) is False


def test_legacy_decrypt_roundtrip():
    salt_hex = os.urandom(16).hex()
    key = legacy_derive_key("hunter2", salt_hex)
    ct = legacy_encrypt_inline("secret", key)
    dec = LegacyCfbDecryptor()
    assert dec.decrypt(ct, key) == "secret"


def test_legacy_derive_key_matches_v1_format():
    """Cross-check legacy_derive_key against an inline reimplementation of v1.
    v1 uses base64.b64decode(salt_hex_string_from_db) as the actual PBKDF2 salt bytes."""
    import base64 as _b64

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    # Use a hex string that the real v1 might produce (32 hex chars).
    salt_hex = "abcdef0123456789abcdef0123456789"
    expected_salt = _b64.b64decode(salt_hex)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=expected_salt,
        iterations=100_000,
    )
    expected_key = kdf.derive(b"hunter2")
    assert legacy_derive_key("hunter2", salt_hex) == expected_key

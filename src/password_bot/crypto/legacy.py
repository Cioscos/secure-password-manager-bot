"""Read-only access to the v1 (PBKDF2 + AES-CFB) format for migration."""

from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

LEGACY_PBKDF2_ITERATIONS = 100_000


def legacy_verify_passphrase(passphrase: str, stored_hex_hash: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    candidate = hashlib.pbkdf2_hmac(
        "sha256", passphrase.encode("utf-8"), salt, LEGACY_PBKDF2_ITERATIONS
    )
    return candidate.hex() == stored_hex_hash


def legacy_derive_key(passphrase: str, salt_hex: str) -> bytes:
    """v1 derivation: salt_hex is base64-encoded before being fed to PBKDF2HMAC."""
    salt_b64 = base64.b64encode(salt_hex.encode("utf-8"))
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_b64,
        iterations=LEGACY_PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


class LegacyCfbDecryptor:
    def decrypt(self, ciphertext_b64: str, key: bytes) -> str:
        blob = base64.b64decode(ciphertext_b64)
        iv, ct = blob[:16], blob[16:]
        decryptor = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
        return (decryptor.update(ct) + decryptor.finalize()).decode("utf-8")

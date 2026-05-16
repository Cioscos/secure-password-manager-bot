"""AES-256-GCM cipher with a 1-byte version prefix."""

from __future__ import annotations

import base64
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CRYPTO_VERSION_GCM = 2
NONCE_LEN = 12


class GcmCipher:
    def encrypt(self, plaintext: bytes, key: bytes) -> str:
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        nonce = secrets.token_bytes(NONCE_LEN)
        ct = AESGCM(key).encrypt(nonce, plaintext, associated_data=None)
        blob = bytes([CRYPTO_VERSION_GCM]) + nonce + ct
        return base64.b64encode(blob).decode("ascii")

    def decrypt(self, ciphertext_b64: str, key: bytes) -> bytes:
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        blob = base64.b64decode(ciphertext_b64.encode("ascii"))
        if not blob or blob[0] != CRYPTO_VERSION_GCM:
            raise ValueError(f"Unexpected crypto version byte: {blob[:1]!r}")
        nonce = blob[1 : 1 + NONCE_LEN]
        ct = blob[1 + NONCE_LEN :]
        return AESGCM(key).decrypt(nonce, ct, associated_data=None)

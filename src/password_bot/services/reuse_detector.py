"""HMAC of a password, keyed per user. Equal HMACs mean a reused password."""

from __future__ import annotations

import hashlib
import hmac


def compute_password_hmac(password: str, hmac_key: bytes) -> str:
    return hmac.new(hmac_key, password.encode("utf-8"), hashlib.sha256).hexdigest()

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class User:
    chat_id: int
    name: str
    passphrase_hash: str
    autolock_minutes: int
    autolock_reset_on_activity: bool
    alert_days: int
    crypto_version: int
    legacy_salt: str | None
    created_at: int
    updated_at: int

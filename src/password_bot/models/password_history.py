from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class PasswordHistoryEntry:
    id: int
    account_id: str
    password_enc: str
    crypto_version: int
    replaced_at: int

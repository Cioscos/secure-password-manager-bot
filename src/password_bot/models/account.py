from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class Account:
    """Decrypted, domain-level account."""

    id: str
    chat_id: int
    name: str
    username: str | None
    password: str
    url: str | None
    note: str | None
    category_id: str | None
    password_hmac: str
    crypto_version: int
    password_changed_at: int
    created_at: int
    updated_at: int


@dataclass(slots=True)
class AccountRow:
    """Raw DB row — all secret fields still encrypted."""

    id: str
    chat_id: int
    name: str
    username_enc: str | None
    password_enc: str
    url_enc: str | None
    note_enc: str | None
    category_id: str | None
    password_hmac: str
    crypto_version: int
    password_changed_at: int
    created_at: int
    updated_at: int

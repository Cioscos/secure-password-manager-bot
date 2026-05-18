"""Vault service: account CRUD wrapped around encrypt/decrypt."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

from password_bot.crypto.cipher import CRYPTO_VERSION_GCM, GcmCipher
from password_bot.models.account import Account, AccountRow
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.history_repo import HistoryRepo
from password_bot.services.reuse_detector import compute_password_hmac


@dataclass(slots=True, frozen=True)
class NewAccount:
    chat_id: int
    name: str
    username: str | None
    password: str
    url: str | None
    note: str | None
    category_id: str | None


@dataclass(slots=True, frozen=True)
class UpdatedFields:
    name: str | None = None
    username: str | None = None
    url: str | None = None
    note: str | None = None
    category_id: str | None = None
    # Sentinel: None means "leave unchanged". To clear a value, pass an explicit
    # empty string for str fields. Category cleared via category_id="".


@dataclass(slots=True, frozen=True)
class HistoryItem:
    id: int
    password: str
    replaced_at: int


class VaultService:
    def __init__(
        self,
        *,
        account_repo: AccountRepo,
        history_repo: HistoryRepo,
        cipher: GcmCipher,
        history_max: int,
    ) -> None:
        self._accounts = account_repo
        self._history = history_repo
        self._cipher = cipher
        self._history_max = history_max

    def _enc(self, value: str | None, key: bytes) -> str | None:
        if value is None:
            return None
        return self._cipher.encrypt(value.encode("utf-8"), key)

    def _dec(self, value: str | None, key: bytes) -> str | None:
        if value is None:
            return None
        return self._cipher.decrypt(value, key).decode("utf-8")

    def _decrypt_row(self, row: AccountRow, key: bytes) -> Account:
        return Account(
            id=row.id,
            chat_id=row.chat_id,
            name=row.name,
            username=self._dec(row.username_enc, key),
            password=self._cipher.decrypt(row.password_enc, key).decode("utf-8"),
            url=self._dec(row.url_enc, key),
            note=self._dec(row.note_enc, key),
            category_id=row.category_id,
            password_hmac=row.password_hmac,
            crypto_version=row.crypto_version,
            password_changed_at=row.password_changed_at,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    async def add(self, new: NewAccount, *, aes_key: bytes, hmac_key: bytes) -> Account:
        now = int(time.time())
        row = AccountRow(
            id=str(uuid.uuid4()),
            chat_id=new.chat_id,
            name=new.name,
            username_enc=self._enc(new.username, aes_key),
            password_enc=self._cipher.encrypt(new.password.encode("utf-8"), aes_key),
            url_enc=self._enc(new.url, aes_key),
            note_enc=self._enc(new.note, aes_key),
            category_id=new.category_id,
            password_hmac=compute_password_hmac(new.password, hmac_key),
            crypto_version=CRYPTO_VERSION_GCM,
            password_changed_at=now,
            created_at=now,
            updated_at=now,
        )
        await self._accounts.insert(row)
        return self._decrypt_row(row, aes_key)

    async def get_decrypted(self, account_id: str, *, aes_key: bytes) -> Account | None:
        row = await self._accounts.get(account_id)
        if row is None:
            return None
        return self._decrypt_row(row, aes_key)

    async def list_decrypted(self, chat_id: int, *, aes_key: bytes) -> list[Account]:
        rows = await self._accounts.list_for_chat(chat_id)
        return [self._decrypt_row(r, aes_key) for r in rows]

    async def update_fields(
        self, account_id: str, updates: UpdatedFields, *, aes_key: bytes
    ) -> None:
        fields: dict[str, str | None] = {}
        if updates.name is not None:
            fields["name"] = updates.name
        if updates.username is not None:
            fields["username_enc"] = self._enc(updates.username or None, aes_key)
        if updates.url is not None:
            fields["url_enc"] = self._enc(updates.url or None, aes_key)
        if updates.note is not None:
            fields["note_enc"] = self._enc(updates.note or None, aes_key)
        if updates.category_id is not None:
            fields["category_id"] = updates.category_id or None
        if fields:
            await self._accounts.update_fields(account_id, **fields)

    async def update_password(
        self, account_id: str, new_password: str, *, aes_key: bytes, hmac_key: bytes
    ) -> None:
        current = await self._accounts.get(account_id)
        if current is None:
            return
        now = int(time.time())
        await self._history.push(
            account_id,
            password_enc=current.password_enc,
            crypto_version=current.crypto_version,
            replaced_at=now,
        )
        await self._history.prune(account_id, keep=self._history_max)
        new_enc = self._cipher.encrypt(new_password.encode("utf-8"), aes_key)
        new_hmac = compute_password_hmac(new_password, hmac_key)
        await self._accounts.update_password(
            account_id,
            password_enc=new_enc,
            password_hmac=new_hmac,
            crypto_version=CRYPTO_VERSION_GCM,
            password_changed_at=now,
        )

    async def list_history(self, account_id: str, *, aes_key: bytes) -> list[HistoryItem]:
        entries = await self._history.list_for_account(account_id)
        return [
            HistoryItem(
                id=e.id,
                password=self._cipher.decrypt(e.password_enc, aes_key).decode("utf-8"),
                replaced_at=e.replaced_at,
            )
            for e in entries
        ]

    async def duplicate(self, account_id: str, *, aes_key: bytes, hmac_key: bytes) -> Account:
        original = await self._accounts.get(account_id)
        if original is None:
            raise ValueError(f"Account {account_id} not found")
        plain = self._decrypt_row(original, aes_key)
        new = NewAccount(
            chat_id=plain.chat_id,
            name=f"{plain.name} (copia)",
            username=plain.username,
            password=plain.password,
            url=plain.url,
            note=plain.note,
            category_id=plain.category_id,
        )
        return await self.add(new, aes_key=aes_key, hmac_key=hmac_key)

    async def delete(self, account_id: str) -> None:
        await self._accounts.delete(account_id)

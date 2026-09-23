"""Encrypted JSON export/import."""

from __future__ import annotations

import base64
import binascii
import json
import secrets
import time
import uuid
from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, ValidationError

from password_bot.crypto.cipher import GcmCipher
from password_bot.crypto.kdf import Argon2idKdf
from password_bot.models.category import Category
from password_bot.repositories.account_repo import AccountRepo
from password_bot.repositories.category_repo import CategoryRepo
from password_bot.services.errors import InvalidExportFileError, InvalidPassphraseError
from password_bot.services.vault_service import NewAccount, VaultService

EXPORT_FORMAT = "password-bot-vault"
EXPORT_VERSION = 1
SALT_LEN = 16


class MergeStrategy(StrEnum):
    SKIP = "skip"
    OVERWRITE = "overwrite"
    KEEP_BOTH = "keep_both"


@dataclass(slots=True, frozen=True)
class ImportReport:
    added: int
    skipped: int
    overwritten: int


class _ExportItem(BaseModel):
    name: str
    username_enc: str | None = None
    password_enc: str
    url_enc: str | None = None
    note_enc: str | None = None
    category: str | None = None
    password_changed_at: int


class _ExportSchema(BaseModel):
    format: str
    version: int
    exported_at: str
    kdf: dict
    cipher: str
    salt: str
    items: list[_ExportItem]
    categories: list[str]


class ExportService:
    def __init__(
        self,
        *,
        accounts: AccountRepo,
        categories: CategoryRepo,
        vault: VaultService,
        cipher: GcmCipher,
        kdf: Argon2idKdf,
    ) -> None:
        self._accounts = accounts
        self._categories = categories
        self._vault = vault
        self._cipher = cipher
        self._kdf = kdf

    async def export(self, *, chat_id: int, vault_key: bytes, export_passphrase: str) -> str:
        salt = secrets.token_bytes(SALT_LEN)
        export_key = self._kdf.derive_key(export_passphrase, salt)
        accounts_plain = await self._vault.list_decrypted(chat_id, aes_key=vault_key)
        cats = await self._categories.list_for_chat(chat_id)
        cat_name_by_id = {c.id: c.name for c in cats}
        items = []
        for a in accounts_plain:
            items.append(
                {
                    "name": a.name,
                    "username_enc": (
                        self._cipher.encrypt(a.username.encode(), export_key)
                        if a.username
                        else None
                    ),
                    "password_enc": self._cipher.encrypt(a.password.encode(), export_key),
                    "url_enc": (
                        self._cipher.encrypt(a.url.encode(), export_key) if a.url else None
                    ),
                    "note_enc": (
                        self._cipher.encrypt(a.note.encode(), export_key) if a.note else None
                    ),
                    "category": cat_name_by_id.get(a.category_id) if a.category_id else None,
                    "password_changed_at": a.password_changed_at,
                }
            )
        payload = {
            "format": EXPORT_FORMAT,
            "version": EXPORT_VERSION,
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "kdf": {"name": "argon2id"},
            "cipher": "aes-256-gcm",
            "salt": base64.b64encode(salt).decode(),
            "items": items,
            "categories": [c.name for c in cats],
        }
        return json.dumps(payload, indent=2)

    async def import_payload(
        self,
        payload: str,
        *,
        chat_id: int,
        vault_key: bytes,
        hmac_key: bytes,
        export_passphrase: str,
        strategy: MergeStrategy,
    ) -> ImportReport:
        try:
            schema = _ExportSchema.model_validate_json(payload)
        except ValidationError as e:
            raise InvalidExportFileError() from e
        if schema.format != EXPORT_FORMAT or schema.version != EXPORT_VERSION:
            raise InvalidExportFileError()
        try:
            salt = base64.b64decode(schema.salt, validate=True)
        except (ValueError, binascii.Error) as e:
            raise InvalidExportFileError() from e
        if len(salt) != SALT_LEN:
            raise InvalidExportFileError()
        export_key = self._kdf.derive_key(export_passphrase, salt)

        try:
            existing = {
                a.name.lower(): a
                for a in await self._vault.list_decrypted(chat_id, aes_key=vault_key)
            }
        except Exception as e:
            raise InvalidPassphraseError() from e

        category_names = [*schema.categories, *(i.category for i in schema.items if i.category)]
        if any(not name.strip() for name in category_names):
            raise InvalidExportFileError()

        decrypted = []
        for item in schema.items:
            try:
                password = self._cipher.decrypt(item.password_enc, export_key).decode("utf-8")
                username = (
                    self._cipher.decrypt(item.username_enc, export_key).decode("utf-8")
                    if item.username_enc
                    else None
                )
                url = (
                    self._cipher.decrypt(item.url_enc, export_key).decode("utf-8")
                    if item.url_enc
                    else None
                )
                note = (
                    self._cipher.decrypt(item.note_enc, export_key).decode("utf-8")
                    if item.note_enc
                    else None
                )
            except Exception as e:
                raise InvalidPassphraseError() from e
            decrypted.append((item, password, username, url, note))

        category_ids = {
            c.name.casefold(): c.id for c in await self._categories.list_for_chat(chat_id)
        }

        async def category_id_for(name: str | None) -> str | None:
            clean = (name or "").strip()  # preflight rejected blank names; never truncate names
            if not clean:
                return None
            key = clean.casefold()
            if key not in category_ids:
                cat = Category(id=str(uuid.uuid4()), chat_id=chat_id, name=clean, icon=None)
                await self._categories.create(cat)
                category_ids[key] = cat.id
            return category_ids[key]

        for cat_name in schema.categories:
            await category_id_for(cat_name)

        added = skipped = overwritten = 0
        for item, password, username, url, note in decrypted:
            existing_match = existing.get(item.name.lower())
            if existing_match and strategy == MergeStrategy.SKIP:
                skipped += 1
                continue
            if existing_match and strategy == MergeStrategy.OVERWRITE:
                await self._vault.delete(existing_match.id)
                overwritten += 1
                target_name = item.name
            elif existing_match and strategy == MergeStrategy.KEEP_BOTH:
                target_name = f"{item.name} (importato)"
                added += 1
            else:
                target_name = item.name
                added += 1

            await self._vault.add(
                NewAccount(
                    chat_id=chat_id,
                    name=target_name,
                    username=username,
                    password=password,
                    url=url,
                    note=note,
                    category_id=await category_id_for(item.category),
                ),
                aes_key=vault_key,
                hmac_key=hmac_key,
            )
        return ImportReport(added=added, skipped=skipped, overwritten=overwritten)

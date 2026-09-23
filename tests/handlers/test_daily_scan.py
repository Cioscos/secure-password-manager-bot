"""The daily stale scan must survive unreachable users and skip legacy ones."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest
from telegram.error import Forbidden

from password_bot.bot import _daily_stale_scan
from password_bot.config import AppConfig
from password_bot.container import Container
from password_bot.models.account import AccountRow
from password_bot.models.user import User
from password_bot.repositories.migrator import migrate_to_latest


def _user(chat_id: int, *, crypto_version: int = 2) -> User:
    now = int(time.time())
    return User(
        chat_id=chat_id,
        name=str(chat_id),
        passphrase_hash="h",
        autolock_minutes=15,
        autolock_reset_on_activity=True,
        alert_days=180,
        crypto_version=crypto_version,
        legacy_salt="s" if crypto_version == 1 else None,
        created_at=now,
        updated_at=now,
    )


def _stale_row(account_id: str, chat_id: int) -> AccountRow:
    return AccountRow(
        id=account_id,
        chat_id=chat_id,
        name=account_id,
        username_enc=None,
        password_enc="p",
        url_enc=None,
        note_enc=None,
        category_id=None,
        password_hmac="h",
        crypto_version=2,
        password_changed_at=0,
        created_at=0,
        updated_at=0,
    )


@pytest.fixture
async def container(tmp_path, monkeypatch) -> Container:
    monkeypatch.setenv("KEYRING", str(tmp_path))
    config = AppConfig.load(base_dir=tmp_path)
    await migrate_to_latest(config.db_path)
    c = Container.build(config, dev_chat_id=None)
    await c.users.create(_user(1))
    await c.users.create(_user(2))
    await c.users.create(_user(3, crypto_version=1))
    for chat_id in (1, 2, 3):
        await c.accounts.insert(_stale_row(f"acc{chat_id}", chat_id))
    return c


def _context(container: Container, send_message: AsyncMock) -> MagicMock:
    context = MagicMock()
    context.application.bot_data = {"container": container}
    context.bot.send_message = send_message
    return context


@pytest.mark.asyncio
async def test_forbidden_user_does_not_stop_scan(container: Container):
    async def send(chat_id, *_args, **_kwargs):
        if chat_id == 1:
            raise Forbidden("Forbidden: user is deactivated")

    send_message = AsyncMock(side_effect=send)
    await _daily_stale_scan(_context(container, send_message))
    notified = [c.args[0] for c in send_message.await_args_list]
    assert notified == [1, 2]


@pytest.mark.asyncio
async def test_legacy_users_are_skipped(container: Container):
    send_message = AsyncMock()
    await _daily_stale_scan(_context(container, send_message))
    notified = [c.args[0] for c in send_message.await_args_list]
    assert 3 not in notified

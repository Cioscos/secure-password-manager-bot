"""Real services on a temp DB, an unlocked session and a Ctx factory for screen tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from password_bot.config import AppConfig
from password_bot.container import Container
from password_bot.models.account import Account
from password_bot.models.category import Category
from password_bot.repositories.migrator import migrate_to_latest
from password_bot.services.auth_service import Session
from password_bot.services.vault_service import NewAccount
from password_bot.state.keys import ChatDataKey
from password_bot.ui.screen import Ctx

PASSPHRASE = "correct horse battery"


@dataclass
class Env:
    container: Container
    session: Session
    chat_data: dict[str, Any] = field(default_factory=dict)
    bot: Any = field(default_factory=AsyncMock)
    application: Any = field(default_factory=MagicMock)

    def ctx(
        self, args: dict | None = None, *, back_label: str | None = "Home", chat_id: int = 1
    ) -> Ctx:
        return Ctx(
            container=self.container,
            chat_id=chat_id,
            chat_data=self.chat_data,
            args=dict(args or {}),
            back_label=back_label,
            bot=self.bot,
            application=self.application,
            user_name="Me",
        )

    async def add(
        self,
        name: str,
        *,
        username: str | None = None,
        password: str = "Pw-123456!",
        url: str | None = None,
        note: str | None = None,
        category_id: str | None = None,
    ) -> Account:
        return await self.container.vault.add(
            NewAccount(
                chat_id=1,
                name=name,
                username=username,
                password=password,
                url=url,
                note=note,
                category_id=category_id,
            ),
            aes_key=self.session.aes_key,
            hmac_key=self.session.hmac_key,
        )

    async def category(self, name: str, icon: str | None = None) -> Category:
        cat = Category(id=f"cat-{name.lower()}", chat_id=1, name=name, icon=icon)
        await self.container.categories.create(cat)
        return cat


@pytest.fixture
async def env(tmp_path, monkeypatch) -> Env:
    monkeypatch.setenv("KEYRING", str(tmp_path))
    config = AppConfig.load(base_dir=tmp_path)
    await migrate_to_latest(config.db_path)
    container = Container.build(config, dev_chat_id=None)
    result = await container.auth.register(
        chat_id=1, name="me", passphrase=PASSPHRASE, autolock_minutes=15, alert_days=180
    )
    assert result.value is not None
    env = Env(container=container, session=result.value)
    env.chat_data[ChatDataKey.SESSION.value] = result.value
    return env

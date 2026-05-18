"""Lightweight integration tests for categories handler."""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock

import pytest

from password_bot.handlers.categories import _list_keyboard, cmd_categories, handle_pending_name
from password_bot.state.keys import ChatDataKey


@dataclass
class _FakeCat:
    id: str
    chat_id: int
    name: str
    color: str | None = None


def _mock_update(text: str | None = None, chat_id: int = 42) -> MagicMock:
    update = MagicMock()
    if text is not None:
        update.message.text = text
    update.effective_chat.id = chat_id
    update.effective_chat.send_message = AsyncMock()
    return update


def _mock_context(chat_data: dict, container_categories) -> MagicMock:
    context = MagicMock()
    context.chat_data = chat_data
    context.application.bot_data = {"container": MagicMock(categories=container_categories)}
    return context


def test_list_keyboard_has_back_and_menu():
    cats = [_FakeCat(id="1", chat_id=42, name="lavoro")]
    kb = _list_keyboard(cats)
    rows = kb.inline_keyboard
    callback_data = {b.callback_data for row in rows for b in row}
    assert "cat:select:1" in callback_data
    assert "cat:new" in callback_data
    assert "nav:back" in callback_data
    assert "nav:menu" in callback_data


@pytest.mark.asyncio
async def test_categories_locked_session():
    update = _mock_update()
    context = _mock_context({}, MagicMock())  # no session
    await cmd_categories(update, context)
    update.effective_chat.send_message.assert_called_once()


@pytest.mark.asyncio
async def test_categories_empty_vault():
    update = _mock_update()
    categories_repo = MagicMock()
    categories_repo.list_for_chat = AsyncMock(return_value=[])
    chat_data = {ChatDataKey.SESSION.value: MagicMock()}
    context = _mock_context(chat_data, categories_repo)
    await cmd_categories(update, context)
    update.effective_chat.send_message.assert_called_once()


@pytest.mark.asyncio
async def test_categories_with_items():
    update = _mock_update()
    categories_repo = MagicMock()
    categories_repo.list_for_chat = AsyncMock(
        return_value=[_FakeCat(id="x", chat_id=42, name="lavoro")]
    )
    chat_data = {ChatDataKey.SESSION.value: MagicMock()}
    context = _mock_context(chat_data, categories_repo)
    await cmd_categories(update, context)
    update.effective_chat.send_message.assert_called_once()


@pytest.mark.asyncio
async def test_handle_pending_name_empty_aborts():
    update = _mock_update(text="   ")
    categories_repo = MagicMock()
    categories_repo.list_for_chat = AsyncMock(return_value=[])
    chat_data = {ChatDataKey.PENDING_INPUT.value: {"field": "_cat_new_name"}}
    context = _mock_context(chat_data, categories_repo)
    await handle_pending_name(update, context)
    assert ChatDataKey.PENDING_INPUT.value not in chat_data

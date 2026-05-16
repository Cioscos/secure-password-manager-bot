"""Integration-style tests for password_gen handler using lightweight mocks."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from password_bot.handlers.password_gen import handle_pending_length
from password_bot.state.keys import ChatDataKey


def _mock_update(text: str) -> MagicMock:
    update = MagicMock()
    update.message.text = text
    update.effective_chat.send_message = AsyncMock()
    return update


def _mock_context(chat_data: dict) -> MagicMock:
    context = MagicMock()
    context.chat_data = chat_data
    return context


@pytest.mark.asyncio
async def test_length_invalid_text():
    update = _mock_update("abc")
    chat_data = {ChatDataKey.PENDING_INPUT.value: {"field": "_pwgen_length"}}
    context = _mock_context(chat_data)
    await handle_pending_length(update, context)
    update.effective_chat.send_message.assert_called_once()
    assert ChatDataKey.PENDING_INPUT.value not in chat_data


@pytest.mark.asyncio
async def test_length_out_of_range():
    update = _mock_update("3")  # below MIN_LENGTH=4
    chat_data = {ChatDataKey.PENDING_INPUT.value: {"field": "_pwgen_length"}}
    context = _mock_context(chat_data)
    await handle_pending_length(update, context)
    update.effective_chat.send_message.assert_called_once()


@pytest.mark.asyncio
async def test_length_valid_updates_draft():
    update = _mock_update("16")
    chat_data = {
        ChatDataKey.PENDING_INPUT.value: {"field": "_pwgen_length"},
        ChatDataKey.PW_GEN_DRAFT.value: {
            "length": 20,
            "upper": True,
            "lower": True,
            "digits": True,
            "symbols": True,
            "exclude_ambiguous": False,
            "no_duplicates": False,
        },
    }
    context = _mock_context(chat_data)
    await handle_pending_length(update, context)
    assert chat_data[ChatDataKey.PW_GEN_DRAFT.value]["length"] == 16
    update.effective_chat.send_message.assert_called_once()


@pytest.mark.asyncio
async def test_length_too_big():
    update = _mock_update("999")
    chat_data = {ChatDataKey.PENDING_INPUT.value: {"field": "_pwgen_length"}}
    context = _mock_context(chat_data)
    await handle_pending_length(update, context)
    update.effective_chat.send_message.assert_called_once()

"""Once the session is locked, text must go to the unlock flow, never to a stale pending input."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from password_bot.handlers import auth, dispatcher, inline_cmd
from password_bot.state.keys import ChatDataKey


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["_search_query", "_copy_query", "password", "_cat_new_name"])
async def test_locked_session_routes_text_to_unlock(monkeypatch, field):
    unlock = AsyncMock()
    search = AsyncMock()
    monkeypatch.setattr(auth, "handle_passphrase_message", unlock)
    monkeypatch.setattr(inline_cmd, "cmd_get", search)

    update = MagicMock()
    update.message.text = "my secret passphrase"
    chat_data = {ChatDataKey.PENDING_INPUT.value: {"field": field, "id": "a1"}}
    context = MagicMock()
    context.chat_data = chat_data

    await dispatcher.on_text(update, context)

    unlock.assert_awaited_once()
    search.assert_not_awaited()
    assert ChatDataKey.PENDING_INPUT.value not in chat_data

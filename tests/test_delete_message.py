from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

from telegram.error import Forbidden

from password_bot.telegram_utils.delete_message import _delete_job


async def test_delete_job_swallows_forbidden_without_raising():
    """A Forbidden (bot kicked/blocked) during the 30s secret-deletion job must never
    propagate to the error handler — only BadRequest was caught before this fix."""
    bot = SimpleNamespace(delete_message=AsyncMock(side_effect=Forbidden("bot was blocked")))
    job = SimpleNamespace(data=(1, 2))
    context = SimpleNamespace(job=job, bot=bot)

    await _delete_job(context)  # must not raise

    bot.delete_message.assert_awaited_once_with(chat_id=1, message_id=2)


async def test_delete_job_noop_without_job():
    context = SimpleNamespace(job=None, bot=SimpleNamespace(delete_message=AsyncMock()))
    await _delete_job(context)
    context.bot.delete_message.assert_not_awaited()


async def test_delete_job_deletes_the_message():
    bot = SimpleNamespace(delete_message=AsyncMock())
    context = SimpleNamespace(job=SimpleNamespace(data=(5, 9)), bot=bot)
    await _delete_job(context)
    bot.delete_message.assert_awaited_once_with(chat_id=5, message_id=9)

"""Schedule auto-deletion of messages that carry sensitive content."""

from __future__ import annotations

import logging

from telegram.error import TelegramError
from telegram.ext import Application, ContextTypes

log = logging.getLogger(__name__)


async def _delete_job(context: ContextTypes.DEFAULT_TYPE) -> None:
    job = context.job
    if job is None:
        return
    chat_id, message_id = job.data  # type: ignore[misc]
    try:
        await context.bot.delete_message(chat_id=chat_id, message_id=message_id)
    except TelegramError as e:
        log.warning("delete_message failed for %s/%s: %s", chat_id, message_id, e)


def schedule_delete(
    application: Application,
    *,
    chat_id: int,
    message_id: int,
    delay_seconds: int = 30,
) -> None:
    if application.job_queue is None:
        return
    application.job_queue.run_once(
        _delete_job,
        when=delay_seconds,
        data=(chat_id, message_id),
        name=f"delete:{chat_id}:{message_id}",
    )

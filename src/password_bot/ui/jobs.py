"""Session autolock job."""

from __future__ import annotations

import logging
import time
from typing import Any

from telegram.error import TelegramError

from password_bot.ui.navigator import Navigator, autolock_job_name

log = logging.getLogger(__name__)


def schedule_autolock(application: Any, chat_id: int, expires_at: int) -> None:
    jq = application.job_queue
    if jq is None:
        return
    name = autolock_job_name(chat_id)
    for job in jq.get_jobs_by_name(name):
        job.schedule_removal()
    jq.run_once(
        autolock_job,
        when=max(1, expires_at - int(time.time())),
        chat_id=chat_id,
        data=expires_at,
        name=name,
    )


async def autolock_job(context: Any) -> None:
    job = context.job
    if job is None or job.chat_id is None:
        return
    try:
        await Navigator.from_context(context, job.chat_id).lock(expected_deadline=job.data)
    except TelegramError as e:
        log.warning("Autolock notice not delivered to chat_id=%s: %s", job.chat_id, e)

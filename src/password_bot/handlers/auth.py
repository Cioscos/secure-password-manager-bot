"""Passphrase setup, unlock, change. The 'unlock' flow also triggers lazy migration."""

from __future__ import annotations

import contextlib
import logging

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from password_bot.container import Container
from password_bot.i18n.it import MESSAGES
from password_bot.state.fsm import FsmContext
from password_bot.telegram_utils.md import escape_md

log = logging.getLogger(__name__)


def _fsm(context: ContextTypes.DEFAULT_TYPE) -> FsmContext:
    return FsmContext(context.chat_data)  # type: ignore[arg-type]


async def handle_passphrase_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Catch the passphrase the user sent and route to setup or unlock."""
    container: Container = context.application.bot_data["container"]
    chat_id = update.effective_chat.id
    passphrase = update.message.text or ""
    log.info("handle_passphrase_message chat_id=%s passphrase_len=%s", chat_id, len(passphrase))

    # Always delete the inbound message first.
    with contextlib.suppress(Exception):
        await update.message.delete()

    user = await container.users.get(chat_id)
    log.info(
        "handle_passphrase_message user_exists=%s crypto_version=%s",
        user is not None,
        user.crypto_version if user else None,
    )
    if user is None:
        # First-time setup.
        r = await container.auth.register(
            chat_id=chat_id,
            name=update.effective_user.full_name,
            passphrase=passphrase,
            autolock_minutes=container.config.autolock_minutes_default,
            alert_days=container.config.alert_days_default,
        )
        if not r.ok or r.value is None:
            await context.bot.send_message(chat_id, MESSAGES["passphrase_wrong"])
            return
        _fsm(context).set_session(r.value)
        _schedule_autolock(context, chat_id, r.value.expires_at)
        await context.bot.send_message(
            chat_id,
            escape_md("Vault creato. /menu per iniziare."),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return

    if user.crypto_version == 1:
        log.info("unlock_legacy starting for chat_id=%s", chat_id)
        legacy_r = await container.migration.unlock_legacy(chat_id=chat_id, passphrase=passphrase)
        log.info(
            "unlock_legacy ok=%s err=%s",
            legacy_r.ok,
            type(legacy_r.error).__name__ if legacy_r.error else None,
        )
        if not legacy_r.ok or legacy_r.value is None:
            await context.bot.send_message(chat_id, MESSAGES["passphrase_wrong"])
            return
        await context.bot.send_message(
            chat_id,
            escape_md("Sto migrando il vault…"),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        log.info("migrate_user starting for chat_id=%s", chat_id)
        await container.migration.migrate_user(
            chat_id=chat_id, passphrase=passphrase, session=legacy_r.value
        )
        log.info("migrate_user done for chat_id=%s", chat_id)
        _fsm(context).set_session(legacy_r.value)
        _schedule_autolock(context, chat_id, legacy_r.value.expires_at)
        await context.bot.send_message(
            chat_id,
            escape_md("Migrazione completata. /menu per iniziare."),
            parse_mode=ParseMode.MARKDOWN_V2,
        )
        return

    r = await container.auth.unlock(chat_id=chat_id, passphrase=passphrase)
    if not r.ok or r.value is None:
        await context.bot.send_message(chat_id, MESSAGES["passphrase_wrong"])
        return
    _fsm(context).set_session(r.value)
    _schedule_autolock(context, chat_id, r.value.expires_at)
    await context.bot.send_message(
        chat_id,
        escape_md("Sbloccato. /menu per il menu."),
        parse_mode=ParseMode.MARKDOWN_V2,
    )


def _schedule_autolock(context: ContextTypes.DEFAULT_TYPE, chat_id: int, expires_at: int) -> None:
    import time

    if context.application.job_queue is None:
        return
    delay = max(1, expires_at - int(time.time()))
    name = f"autolock:{chat_id}"
    for job in context.application.job_queue.get_jobs_by_name(name):
        job.schedule_removal()
    context.application.job_queue.run_once(
        _autolock_callback,
        when=delay,
        chat_id=chat_id,
        name=name,
    )


async def _autolock_callback(context: ContextTypes.DEFAULT_TYPE) -> None:
    job = context.job
    if job is None or job.chat_id is None:
        return
    chat_data = context.application.chat_data.get(job.chat_id, {})  # type: ignore[union-attr]
    FsmContext(chat_data).clear_session()
    await context.bot.send_message(
        job.chat_id,
        escape_md(MESSAGES["session_locked"]),
        parse_mode=ParseMode.MARKDOWN_V2,
    )
